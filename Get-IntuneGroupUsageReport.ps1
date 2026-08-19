<#
.VERSION
    1.0.0

.VERSIONHISTORY
    2026-08-19 | 1.0.0 - Initial version with group-centric reporting, Graph
            pagination handling, direct Graph requests replaced with
            Invoke-MgGraphRequest, and README updates.

.SYNOPSIS
    Identifies Entra ID groups that are used for Intune assignments.

.DESCRIPTION
    Captures:
      - Settings Catalog / Configuration Policies
      - Classic Device Configurations
      - Compliance Policies
      - Mobile Apps including Required / Available / Uninstall
      - iOS Managed App Protection Policies
      - Android Managed App Protection Policies
      - Proactive Remediations / Device Management Scripts
      - Device Health Scripts

    For each object, include and exclude assignments are captured separately.

    Additionally, the following are detected:
      - All Users
      - All Devices

    Groups are resolved via Invoke-MgGraphRequest and cached.

    The actual Intune data is read via Invoke-MgGraphRequest from the
    Microsoft Graph PowerShell SDK. This allows mixing v1.0 and Beta
    endpoints.

.NOTES
    PowerShell 7+
    Microsoft.Graph.Applications
    Microsoft.Graph.Authentication


    Required Delegated Permissions:

      DeviceManagementConfiguration.Read.All
      DeviceManagementApps.Read.All
      DeviceManagementScripts.Read.All
      Group.Read.All

    No Tenant ID, Client ID or Credentials required.

    API Versions:

      v1.0:
        /deviceManagement/deviceConfigurations
        /deviceManagement/deviceCompliancePolicies
        /deviceAppManagement/mobileApps
        /deviceAppManagement/iosManagedAppProtections
        /deviceAppManagement/androidManagedAppProtections

      beta:
        /deviceManagement/configurationPolicies
        /deviceManagement/deviceManagementScripts
        /deviceManagement/deviceHealthScripts

    Note:
      configurationPolicies are currently still in Beta.
      Device Health Scripts / Proactive Remediations are also Beta.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [string]$CsvPath = ".\Intune-GroupAssignments.csv",

    [switch]$CreateReverseLookup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Version = "1.0.0"

# ---------------------------------------------------------------------------
# 1. Authentication
# ---------------------------------------------------------------------------

$Scopes = @(
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementScripts.Read.All",
    "Group.Read.All"
)

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan

try {
    Connect-MgGraph `
        -Scopes $Scopes `
        -NoWelcome `
        -ErrorAction Stop
}
catch {
    Write-Error "Microsoft Graph authentication failed: $($_.Exception.Message)"
    return
}

# ---------------------------------------------------------------------------
# 2. Global Variables
# ---------------------------------------------------------------------------

$script:Results = [System.Collections.Generic.List[object]]::new()

# Group Cache:
#   Key   = Entra Object ID
#   Value = Hashtable with Id / DisplayName
$script:GroupCache = @{}

# ---------------------------------------------------------------------------
# 3. Helper Function: Graph GET with full pagination
# ---------------------------------------------------------------------------

function Invoke-GraphGetAll {
    <#
    .SYNOPSIS
        Retrieves all pages for a Microsoft Graph GET request.

    .DESCRIPTION
        Uses Invoke-MgGraphRequest repeatedly until @odata.nextLink is exhausted.
        This handles paginated responses from Microsoft Graph and normalizes
        dictionary-based payloads returned by newer Graph endpoints.

    .PARAMETER Uri
        The Graph resource URL to query.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $Items = [System.Collections.Generic.List[object]]::new()

    $NextUri = $Uri

    while ($NextUri) {

        try {
            $Response = Invoke-MgGraphRequest `
                -Method GET `
                -Uri $NextUri `
                -ErrorAction Stop
        }
        catch {
            throw
        }

        $PageItems = @()

        if ($Response -and $Response -is [System.Collections.IDictionary]) {
            if ($Response.Contains('value')) {
                $PageItems = @($Response['value'])
            }
            elseif ($Response.Contains('@odata.nextLink')) {
                $PageItems = @($Response)
            }
        }
        elseif ($Response -and $Response.PSObject.Properties.Name -contains 'value') {
            $PageItems = @($Response.value)
        }
        elseif ($Response -and $Response -is [System.Collections.IEnumerable] -and -not ($Response -is [string])) {
            $PageItems = @($Response)
        }

        foreach ($Item in $PageItems) {
            if ($null -ne $Item) {
                $Items.Add($Item)
            }
        }

        # Graph returns @odata.nextLink only when additional pages exist.
        # Some endpoints return a single page without this property.
        $NextUri = $null
        if ($Response -and $Response -is [System.Collections.IDictionary]) {
            if ($Response.Contains('@odata.nextLink')) {
                $NextUri = [string]$Response['@odata.nextLink']
            }
        }
        elseif ($Response -and $Response.PSObject.Properties.Name -contains '@odata.nextLink') {
            $NextUri = [string]$Response.'@odata.nextLink'
        }

        if ([string]::IsNullOrWhiteSpace($NextUri)) {
            $NextUri = $null
        }
    }

    return $Items
}

function Get-ObjectPropertyValue {
    <#
    .SYNOPSIS
        Safely reads a property from either a dictionary or an object.

    .DESCRIPTION
        Graph responses in this script are sometimes returned as hashtables or
        dictionaries instead of PSCustomObjects. This helper abstracts the lookup
        so property access is safe across both response shapes.

    .PARAMETER InputObject
        The object or dictionary to inspect.

    .PARAMETER PropertyName
        The property name to read.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        $InputObject,

        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($PropertyName)) {
            return $InputObject[$PropertyName]
        }
        return $null
    }

    if ($InputObject -is [System.Collections.Hashtable]) {
        if ($InputObject.ContainsKey($PropertyName)) {
            return $InputObject[$PropertyName]
        }
        return $null
    }

    if ($InputObject.PSObject.Properties.Name -contains $PropertyName) {
        return $InputObject.$PropertyName
    }

    return $null
}

# ---------------------------------------------------------------------------
# 4. Group Resolution with Cache
# ---------------------------------------------------------------------------

function Resolve-EntraGroup {
    <#
    .SYNOPSIS
        Resolves an Entra group by object ID.

    .DESCRIPTION
        Looks up a single Microsoft Entra group via Graph and caches the result so
        later assignments do not trigger repeated queries. Missing or invalid
        groups are stored as a fallback entry to avoid repeated lookups.

    .PARAMETER GroupId
        The Entra object ID of the group to resolve.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupId
    )

    if ([string]::IsNullOrWhiteSpace($GroupId)) {
        return $null
    }

    # Already in cache?
    if ($script:GroupCache.ContainsKey($GroupId)) {
        return $script:GroupCache[$GroupId]
    }

    try {
        $GroupUri = "https://graph.microsoft.com/v1.0/groups/" + [System.Uri]::EscapeDataString($GroupId) + "?%24select=id,displayName,mail,securityEnabled,groupTypes"

        $Group = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $GroupUri `
            -ErrorAction Stop

        $Resolved = [PSCustomObject]@{
            Id              = [string](Get-ObjectPropertyValue -InputObject $Group -PropertyName 'id')
            DisplayName     = [string](Get-ObjectPropertyValue -InputObject $Group -PropertyName 'displayName')
            Mail            = [string](Get-ObjectPropertyValue -InputObject $Group -PropertyName 'mail')
            SecurityEnabled = Get-ObjectPropertyValue -InputObject $Group -PropertyName 'securityEnabled'
            GroupTypes      = $null
        }

        if ($Resolved.SecurityEnabled -is [System.Collections.IEnumerable] -and -not ($Resolved.SecurityEnabled -is [string])) {
            $Resolved.GroupTypes = ($Resolved.SecurityEnabled -join ";")
        }

        $RawGroupTypes = Get-ObjectPropertyValue -InputObject $Group -PropertyName 'groupTypes'
        if ($null -ne $RawGroupTypes) {
            if ($RawGroupTypes -is [System.Collections.IEnumerable] -and -not ($RawGroupTypes -is [string])) {
                $Resolved.GroupTypes = ($RawGroupTypes -join ";")
            }
            else {
                $Resolved.GroupTypes = [string]$RawGroupTypes
            }
        }

        if ([string]::IsNullOrWhiteSpace($Resolved.GroupTypes)) {
            $Resolved.GroupTypes = ""
        }

        $script:GroupCache[$GroupId] = $Resolved

        return $Resolved
    }
    catch {
        Write-Warning "Group $GroupId could not be resolved: $($_.Exception.Message)"

        $Resolved = [PSCustomObject]@{
            Id              = $GroupId
            DisplayName     = "<unresolvable>"
            Mail            = ""
            SecurityEnabled = $null
            GroupTypes      = ""
        }

        # Cache errors as well, so the same broken ID
        # is not queried again for each assignment.
        $script:GroupCache[$GroupId] = $Resolved

        return $Resolved
    }
}

# ---------------------------------------------------------------------------
# 5. Analyze Assignment Target
# ---------------------------------------------------------------------------

function Resolve-AssignmentTarget {
    <#
    .SYNOPSIS
        Normalizes a single Intune assignment target.

    .DESCRIPTION
        Converts a Graph assignment target into a common shape for downstream
        evaluation. It recognizes all-users, all-devices, and Entra group
        assignments, including include/exclude targets.

    .PARAMETER Target
        The raw target object from a Graph assignment payload.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Target
    )

    if (-not $Target) {
        return [PSCustomObject]@{
            Type        = "Unknown"
            GroupId     = $null
            GroupName   = $null
            Assignment  = "Include"
        }
    }

    $OdataType = [string]$Target.'@odata.type'

    # -----------------------------------------------------------------------
    # All Users
    # -----------------------------------------------------------------------

    if ($OdataType -match "allLicensedUsersAssignmentTarget") {

        return [PSCustomObject]@{
            Type        = "All Users"
            GroupId     = $null
            GroupName   = "All Users"
            Assignment  = "Include"
        }
    }

    # -----------------------------------------------------------------------
    # All Devices
    # -----------------------------------------------------------------------

    if ($OdataType -match "allDevicesAssignmentTarget") {

        return [PSCustomObject]@{
            Type        = "All Devices"
            GroupId     = $null
            GroupName   = "All Devices"
            Assignment  = "Include"
        }
    }

    # -----------------------------------------------------------------------
    # Groups
    #
    # Depending on API version / resource type, the ID may have different
    # names. Older Intune APIs sometimes use groupId, newer targets
    # sometimes use entraObjectId.
    # -----------------------------------------------------------------------

    $GroupId = $null

    if ($Target.groupId) {
        $GroupId = [string]$Target.groupId
    }
    elseif ($Target.entraObjectId) {
        $GroupId = [string]$Target.entraObjectId
    }

    if ($GroupId) {

        $Group = Resolve-EntraGroup -GroupId $GroupId

        # Exclusion is detected via the OData type.
        $AssignmentType = "Include"

        if (
            $OdataType -match "exclusionGroupAssignmentTarget" -or
            $OdataType -match "exclusion"
        ) {
            $AssignmentType = "Exclude"
        }

        return [PSCustomObject]@{
            Type        = "Group"
            GroupId     = $Group.Id
            GroupName   = $Group.DisplayName
            Assignment  = $AssignmentType
        }
    }

    # -----------------------------------------------------------------------
    # Unknown Target
    # -----------------------------------------------------------------------

    return [PSCustomObject]@{
        Type        = if ($OdataType) { $OdataType } else { "Unknown" }
        GroupId     = $null
        GroupName   = $null
        Assignment  = "Unknown"
    }
}

# ---------------------------------------------------------------------------
# 6. Write Assignment Information to Result Object
# ---------------------------------------------------------------------------

function Add-IntuneObject {
    <#
    .SYNOPSIS
        Stores one Intune object and its group assignment summary.

    .DESCRIPTION
        Evaluates all assignment targets for a single Intune object and records the
        included and excluded Entra groups, as well as all-users/all-devices usage.

    .PARAMETER Name
        The display name of the Intune object.

    .PARAMETER ObjectType
        The Intune object category such as Mobile App or Compliance Policy.

    .PARAMETER ObjectId
        The unique object ID returned by Graph.

    .PARAMETER ApiVersion
        The Graph API version used for this object type.

    .PARAMETER Assignments
        The raw assignment objects returned by the Graph assignments endpoint.

    .PARAMETER Intent
        Optional mobile app intent such as required, available, or uninstall.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$ObjectType,

        [Parameter(Mandatory)]
        [string]$ObjectId,

        [Parameter(Mandatory)]
        [string]$ApiVersion,

        [Parameter(Mandatory)]
        [array]$Assignments,

        [string]$Intent = ""
    )

    $IncludeGroups = [System.Collections.Generic.List[string]]::new()
    $IncludeGroupIds = [System.Collections.Generic.List[string]]::new()

    $ExcludeGroups = [System.Collections.Generic.List[string]]::new()
    $ExcludeGroupIds = [System.Collections.Generic.List[string]]::new()

    $AllUsers = $false
    $AllDevices = $false

    foreach ($Assignment in $Assignments) {

        $Resolved = Resolve-AssignmentTarget -Target $Assignment.target

        if ($Resolved.Type -eq "All Users") {
            $AllUsers = $true
            continue
        }

        if ($Resolved.Type -eq "All Devices") {
            $AllDevices = $true
            continue
        }

        if ($Resolved.Type -ne "Group") {
            continue
        }

        if ($Resolved.Assignment -eq "Exclude") {

            if ($Resolved.GroupName) {
                $ExcludeGroups.Add($Resolved.GroupName)
            }

            if ($Resolved.GroupId) {
                $ExcludeGroupIds.Add($Resolved.GroupId)
            }
        }
        else {

            if ($Resolved.GroupName) {
                $IncludeGroups.Add($Resolved.GroupName)
            }

            if ($Resolved.GroupId) {
                $IncludeGroupIds.Add($Resolved.GroupId)
            }
        }
    }

    $script:Results.Add(
        [PSCustomObject]@{
            Name                  = $Name
            ObjectType            = $ObjectType
            ObjectId              = $ObjectId
            ApiVersion            = $ApiVersion
            Intent                = $Intent

            IncludeGroups         = ($IncludeGroups -join " | ")
            IncludeGroupIds       = ($IncludeGroupIds -join " | ")

            ExcludeGroups         = ($ExcludeGroups -join " | ")
            ExcludeGroupIds       = ($ExcludeGroupIds -join " | ")

            AllUsers              = $AllUsers
            AllDevices            = $AllDevices

            AssignmentCount       = @($Assignments).Count
        }
    )
}

# ---------------------------------------------------------------------------
# 7. Read Category from Graph
# ---------------------------------------------------------------------------

function Get-IntuneCategory {
    <#
    .SYNOPSIS
        Reads one Intune object category from Microsoft Graph.

    .DESCRIPTION
        Queries a category such as configuration policies or mobile apps, resolves
        each item's assignments, and adds the resulting group usage information to
        the script-wide results list.

    .PARAMETER Name
        Human-readable name used for logging.

    .PARAMETER ObjectEndpoint
        The Graph endpoint that returns the objects in this category.

    .PARAMETER AssignmentEndpointTemplate
        The Graph URL template for the assignments of each object, replacing {id}.

    .PARAMETER ObjectType
        The output category name used in the result set.

    .PARAMETER ApiVersion
        The Graph API version to query for this category, either v1.0 or beta.

    .PARAMETER UseNameProperty
        Indicates that the object uses name instead of displayName.

    .PARAMETER UseIntent
        Indicates that assignment intents should be aggregated in the output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$ObjectEndpoint,

        [Parameter(Mandatory)]
        [string]$AssignmentEndpointTemplate,

        [Parameter(Mandatory)]
        [string]$ObjectType,

        [Parameter(Mandatory)]
        [ValidateSet("v1.0","beta")]
        [string]$ApiVersion,

        [switch]$UseNameProperty,

        [switch]$UseIntent
    )

    Write-Host ""
    Write-Host "=== $Name ===" -ForegroundColor Yellow

    try {

        $Objects = Invoke-GraphGetAll `
            -Uri "https://graph.microsoft.com/$ApiVersion$ObjectEndpoint"

        Write-Host "Objects found: $($Objects.Count)" -ForegroundColor Gray
    }
    catch {

        Write-Warning "$Name could not be read: $($_.Exception.Message)"
        return
    }

    foreach ($Object in $Objects) {

        try {

            if ($null -eq $Object) {
                continue
            }

            $ObjectNameValue = $null
            if ($UseNameProperty) {
                $ObjectNameValue = Get-ObjectPropertyValue -InputObject $Object -PropertyName 'name'
                if ($null -eq $ObjectNameValue) {
                    $ObjectNameValue = Get-ObjectPropertyValue -InputObject $Object -PropertyName 'displayName'
                }
            }
            else {
                $ObjectNameValue = Get-ObjectPropertyValue -InputObject $Object -PropertyName 'displayName'
                if ($null -eq $ObjectNameValue) {
                    $ObjectNameValue = Get-ObjectPropertyValue -InputObject $Object -PropertyName 'name'
                }
            }

            $DisplayName = [string]$ObjectNameValue
            if ([string]::IsNullOrWhiteSpace($DisplayName)) {
                $DisplayName = "<unnamed>"
            }

            $ObjectId = [string](Get-ObjectPropertyValue -InputObject $Object -PropertyName 'id')

            if ([string]::IsNullOrWhiteSpace($ObjectId)) {
                Write-Warning "$Name contains an object without an ID."
                continue
            }

            $AssignmentUri = $AssignmentEndpointTemplate `
                -replace "\{id\}", $ObjectId

            $Assignments = Invoke-GraphGetAll `
                -Uri "https://graph.microsoft.com/$ApiVersion$AssignmentUri"

            $Intent = ""

            # Apps additionally have Required / Available / Uninstall.
            if ($UseIntent -and $Assignments.Count -gt 0) {

                # With multiple assignments, the intent per assignment
                # is combined in the result.
                $Intents = @(
                    $Assignments |
                    ForEach-Object {
                        if ($_.intent) {
                            [string]$_.intent
                        }
                    } |
                    Sort-Object -Unique
                )

                $Intent = $Intents -join " | "
            }

            Add-IntuneObject `
                -Name $DisplayName `
                -ObjectType $ObjectType `
                -ObjectId $ObjectId `
                -ApiVersion $ApiVersion `
                -Assignments $Assignments `
                -Intent $Intent
        }
        catch {

            $ObjectNameForWarning = Get-ObjectPropertyValue -InputObject $Object -PropertyName 'displayName'
            if ($null -eq $ObjectNameForWarning) {
                $ObjectNameForWarning = Get-ObjectPropertyValue -InputObject $Object -PropertyName 'name'
            }

            $ObjectLabel = if ([string]::IsNullOrWhiteSpace([string]$ObjectNameForWarning)) { "<unnamed>" } else { [string]$ObjectNameForWarning }

            Write-Warning `
                "$Name '$ObjectLabel' could not be processed completely: $($_.Exception.Message)"
        }
    }
}

# ===========================================================================
# 8. Configuration Profiles / Settings Catalog
# ===========================================================================
#
# API:
#   GET /deviceManagement/configurationPolicies
#
# Currently Beta.
# Microsoft continues to document configurationPolicies as Beta.
#
# Permission:
#   DeviceManagementConfiguration.Read.All
#
# ===========================================================================

Get-IntuneCategory `
    -Name "Configuration Profiles / Settings Catalog" `
    -ObjectEndpoint "/deviceManagement/configurationPolicies" `
    -AssignmentEndpointTemplate "/deviceManagement/configurationPolicies/{id}/assignments" `
    -ObjectType "Configuration Profile / Settings Catalog" `
    -ApiVersion "beta" `
    -UseNameProperty

# ===========================================================================
# 9. Classic Device Configurations
# ===========================================================================
#
# API:
#   GET /deviceManagement/deviceConfigurations
#   GET /deviceManagement/deviceConfigurations/{id}/assignments
#
# Available in v1.0.
# ===========================================================================

Get-IntuneCategory `
    -Name "Classic Device Configurations" `
    -ObjectEndpoint "/deviceManagement/deviceConfigurations" `
    -AssignmentEndpointTemplate "/deviceManagement/deviceConfigurations/{id}/assignments" `
    -ObjectType "Classic Device Configuration" `
    -ApiVersion "v1.0"

# ===========================================================================
# 10. Compliance Policies
# ===========================================================================
#
# API:
#   GET /deviceManagement/deviceCompliancePolicies
#   GET /deviceManagement/deviceCompliancePolicies/{id}/assignments
#
# Available in v1.0.
# ===========================================================================

Get-IntuneCategory `
    -Name "Compliance Policies" `
    -ObjectEndpoint "/deviceManagement/deviceCompliancePolicies" `
    -AssignmentEndpointTemplate "/deviceManagement/deviceCompliancePolicies/{id}/assignments" `
    -ObjectType "Compliance Policy" `
    -ApiVersion "v1.0"

# ===========================================================================
# 11. Mobile Apps
# ===========================================================================
#
# API:
#   GET /deviceAppManagement/mobileApps
#   GET /deviceAppManagement/mobileApps/{id}/assignments
#
# Available in v1.0.
#
# Important:
# Microsoft now explicitly recommends loading apps first without
# $expand=assignments and then reading assignments per app.
# ===========================================================================

Get-IntuneCategory `
    -Name "Mobile Apps" `
    -ObjectEndpoint "/deviceAppManagement/mobileApps" `
    -AssignmentEndpointTemplate "/deviceAppManagement/mobileApps/{id}/assignments" `
    -ObjectType "Mobile App" `
    -ApiVersion "v1.0" `
    -UseIntent

# ===========================================================================
# 12. iOS App Protection Policies
# ===========================================================================
#
# API:
#   GET /deviceAppManagement/iosManagedAppProtections
#   GET /deviceAppManagement/iosManagedAppProtections/{id}/assignments
#
# v1.0.
# ===========================================================================

Get-IntuneCategory `
    -Name "iOS App Protection Policies" `
    -ObjectEndpoint "/deviceAppManagement/iosManagedAppProtections" `
    -AssignmentEndpointTemplate "/deviceAppManagement/iosManagedAppProtections/{id}/assignments" `
    -ObjectType "iOS Managed App Protection" `
    -ApiVersion "v1.0"

# ===========================================================================
# 13. Android App Protection Policies
# ===========================================================================
#
# API:
#   GET /deviceAppManagement/androidManagedAppProtections
#   GET /deviceAppManagement/androidManagedAppProtections/{id}/assignments
#
# v1.0.
# ===========================================================================

Get-IntuneCategory `
    -Name "Android App Protection Policies" `
    -ObjectEndpoint "/deviceAppManagement/androidManagedAppProtections" `
    -AssignmentEndpointTemplate "/deviceAppManagement/androidManagedAppProtections/{id}/assignments" `
    -ObjectType "Android Managed App Protection" `
    -ApiVersion "v1.0"

# ===========================================================================
# 14. Proactive Remediations / Device Management Scripts
# ===========================================================================
#
# Current Graph Endpoint:
#
#   GET /deviceManagement/deviceManagementScripts
#   GET /deviceManagement/deviceManagementScripts/{id}/assignments
#
# Beta.
#
# Permission:
#   DeviceManagementScripts.Read.All
#
# Depending on tenant/API status, this endpoint may be limited or
# available differently.
# ===========================================================================

Get-IntuneCategory `
    -Name "Proactive Remediations / Device Management Scripts" `
    -ObjectEndpoint "/deviceManagement/deviceManagementScripts" `
    -AssignmentEndpointTemplate "/deviceManagement/deviceManagementScripts/{id}/assignments" `
    -ObjectType "Proactive Remediation / Device Management Script" `
    -ApiVersion "beta"

# ===========================================================================
# 15. Device Health Scripts
# ===========================================================================
#
# Current Graph Endpoint:
#
#   GET /deviceManagement/deviceHealthScripts
#   GET /deviceManagement/deviceHealthScripts/{id}/assignments
#
# Beta.
#
# Device Health Scripts use DeviceManagementScripts.Read.All.
# ===========================================================================

Get-IntuneCategory `
    -Name "Device Health Scripts" `
    -ObjectEndpoint "/deviceManagement/deviceHealthScripts" `
    -AssignmentEndpointTemplate "/deviceManagement/deviceHealthScripts/{id}/assignments" `
    -ObjectType "Device Health Script" `
    -ApiVersion "beta"

# ===========================================================================
# 16. Output Results
# ===========================================================================

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Results" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

Write-Host "Intune Objects: $($script:Results.Count)"
Write-Host "Groups in Cache: $($script:GroupCache.Count)"

# Group-centric View (primary report)
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Group-centric View" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

$GroupUsageSummary = foreach ($GroupId in $script:GroupCache.Keys) {

    $Group = $script:GroupCache[$GroupId]

    $Usages = foreach ($Result in $script:Results) {

        $Include = $false
        $Exclude = $false

        if ($Result.IncludeGroupIds) {
            $Include = $Result.IncludeGroupIds `
                -split "\s*\|\s*" |
                Where-Object { $_ -eq $GroupId }
        }

        if ($Result.ExcludeGroupIds) {
            $Exclude = $Result.ExcludeGroupIds `
                -split "\s*\|\s*" |
                Where-Object { $_ -eq $GroupId }
        }

        if ($Include -or $Exclude) {
            $Assignment = if ($Exclude) { "Exclude" } else { "Include" }

            [PSCustomObject]@{
                ObjectType = $Result.ObjectType
                Name       = $Result.Name
                ObjectId   = $Result.ObjectId
                Intent     = $Result.Intent
                Assignment = $Assignment
            }
        }
    }

    if ($Usages) {
        [PSCustomObject]@{
            GroupName = $Group.DisplayName
            GroupId   = $Group.Id
            UsedIn    = (
                $Usages |
                ForEach-Object {
                    "$($_.ObjectType): $($_.Name) [$($_.Assignment)]" +
                    $(if ($_.Intent) { " <$($_.Intent)>" } else { "" })
                }
            ) -join " | "
        }
    }
}

$GroupUsageSummary |
    Sort-Object GroupName |
    Format-Table -AutoSize

# ===========================================================================
# 17. CSV Export (group-centric)
# ===========================================================================

try {

    $GroupUsageSummary |
        Export-Csv `
            -Path $CsvPath `
            -NoTypeInformation `
            -Encoding UTF8

    Write-Host ""
    Write-Host "CSV written: $CsvPath" -ForegroundColor Green
}
catch {

    Write-Warning "CSV could not be written: $($_.Exception.Message)"
}

# ===========================================================================
# 18. Optional Group-centric View
# ===========================================================================

if ($CreateReverseLookup) {

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "Group-centric View" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan

    $GroupUsageSummary |
        Sort-Object GroupName |
        Format-Table -AutoSize

    $ReverseCsvPath = [System.IO.Path]::Combine(
        [System.IO.Path]::GetDirectoryName(
            [System.IO.Path]::GetFullPath($CsvPath)
        ),
        "Intune-GroupAssignments-Reverse.csv"
    )

    try {

        $GroupUsageSummary |
            Export-Csv `
                -Path $ReverseCsvPath `
                -NoTypeInformation `
                -Encoding UTF8

        Write-Host ""
        Write-Host "Reverse CSV written: $ReverseCsvPath" `
            -ForegroundColor Green
    }
    catch {

        Write-Warning `
            "Reverse CSV could not be written: $($_.Exception.Message)"
    }
}

# ===========================================================================
# 19. Also return group-centric results as PowerShell object
# ===========================================================================

$GroupUsageSummary
