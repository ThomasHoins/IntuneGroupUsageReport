<#
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

    Groups are resolved via Get-MgGroup and cached.

    The actual Intune data is read via Invoke-MgGraphRequest from the
    Microsoft Graph PowerShell SDK. This allows mixing v1.0 and Beta
    endpoints.

.NOTES
    PowerShell 7+
    Microsoft.Graph

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
#Requires -Modules Microsoft.Graph

[CmdletBinding()]
param(
    [string]$CsvPath = ".\Intune-GroupAssignments.csv",

    [switch]$CreateReverseLookup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

        if ($Response.value) {
            foreach ($Item in $Response.value) {
                $Items.Add($Item)
            }
        }

        # Graph returns @odata.nextLink for pagination.
        $NextUri = $Response.'@odata.nextLink'
    }

    return $Items
}

# ---------------------------------------------------------------------------
# 4. Group Resolution with Cache
# ---------------------------------------------------------------------------

function Resolve-EntraGroup {
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
        $Group = Get-MgGroup `
            -GroupId $GroupId `
            -Property "id,displayName,mail,securityEnabled,groupTypes" `
            -ErrorAction Stop

        $Resolved = [PSCustomObject]@{
            Id              = $Group.Id
            DisplayName     = $Group.DisplayName
            Mail            = $Group.Mail
            SecurityEnabled = $Group.SecurityEnabled
            GroupTypes      = if ($Group.GroupTypes) {
                ($Group.GroupTypes -join ";")
            }
            else {
                ""
            }
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

            if ($UseNameProperty) {
                $DisplayName = [string]$Object.name
            }
            else {
                $DisplayName = [string]$Object.displayName
            }

            if ([string]::IsNullOrWhiteSpace($DisplayName)) {
                $DisplayName = "<unnamed>"
            }

            $ObjectId = [string]$Object.id

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

            Write-Warning `
                "$Name '$($Object.displayName)' could not be processed completely: $($_.Exception.Message)"
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

# Object/Assignment View
$script:Results |
    Sort-Object ObjectType, Name |
    Format-Table `
        Name,
        ObjectType,
        Intent,
        IncludeGroups,
        ExcludeGroups,
        AllUsers,
        AllDevices `
        -AutoSize

# ===========================================================================
# 17. CSV Export
# ===========================================================================

try {

    $script:Results |
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

    $ReverseLookup = foreach ($GroupId in $script:GroupCache.Keys) {

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

                $Assignment = if ($Exclude) {
                    "Exclude"
                }
                else {
                    "Include"
                }

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

    $ReverseLookup |
        Sort-Object GroupName |
        Format-Table -AutoSize

    $ReverseCsvPath = [System.IO.Path]::Combine(
        [System.IO.Path]::GetDirectoryName(
            [System.IO.Path]::GetFullPath($CsvPath)
        ),
        "Intune-GroupAssignments-Reverse.csv"
    )

    try {

        $ReverseLookup |
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
# 19. Also return results as PowerShell object
# ===========================================================================

$script:Results
