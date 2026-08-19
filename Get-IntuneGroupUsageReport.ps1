<#
.SYNOPSIS
    Ermittelt Entra-ID-Gruppen, die für Intune-Zuweisungen verwendet werden.

.DESCRIPTION
    Erfasst:
      - Settings Catalog / Configuration Policies
      - klassische Device Configurations
      - Compliance Policies
      - Mobile Apps inkl. Required / Available / Uninstall
      - iOS Managed App Protection Policies
      - Android Managed App Protection Policies
      - Proactive Remediations / Device Management Scripts
      - Device Health Scripts

    Für jedes Objekt werden Include- und Exclude-Zuweisungen getrennt
    erfasst.

    Zusätzlich werden:
      - All Users
      - All Devices

    erkannt.

    Gruppen werden über Get-MgGroup aufgelöst und gecacht.

    Die eigentlichen Intune-Daten werden über Invoke-MgGraphRequest
    aus dem Microsoft Graph PowerShell SDK gelesen. Dadurch können
    v1.0- und Beta-Endpunkte gemischt verwendet werden.

.NOTES
    PowerShell 7+
    Microsoft.Graph

    Benötigte Delegated Permissions:

      DeviceManagementConfiguration.Read.All
      DeviceManagementApps.Read.All
      DeviceManagementScripts.Read.All
      Group.Read.All

    Keine Tenant-ID, Client-ID oder Credentials notwendig.

    API-Versionen:

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

    Hinweis:
      configurationPolicies sind aktuell weiterhin Beta.
      Device Health Scripts / Proactive Remediations ebenfalls Beta.
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

Write-Host "Verbinde mit Microsoft Graph..." -ForegroundColor Cyan

try {
    Connect-MgGraph `
        -Scopes $Scopes `
        -NoWelcome `
        -ErrorAction Stop
}
catch {
    Write-Error "Microsoft Graph Anmeldung fehlgeschlagen: $($_.Exception.Message)"
    return
}

# ---------------------------------------------------------------------------
# 2. Globale Variablen
# ---------------------------------------------------------------------------

$script:Results = [System.Collections.Generic.List[object]]::new()

# Gruppen-Cache:
#   Key   = Entra Object ID
#   Value = Hashtable mit Id / DisplayName
$script:GroupCache = @{}

# ---------------------------------------------------------------------------
# 3. Hilfsfunktion: Graph GET mit kompletter Pagination
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

        # Graph liefert bei Pagination @odata.nextLink.
        $NextUri = $Response.'@odata.nextLink'
    }

    return $Items
}

# ---------------------------------------------------------------------------
# 4. Gruppenauflösung mit Cache
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

    # Bereits im Cache?
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
        Write-Warning "Gruppe $GroupId konnte nicht aufgelöst werden: $($_.Exception.Message)"

        $Resolved = [PSCustomObject]@{
            Id              = $GroupId
            DisplayName     = "<nicht auflösbar>"
            Mail            = ""
            SecurityEnabled = $null
            GroupTypes      = ""
        }

        # Auch Fehler werden gecacht, damit dieselbe kaputte ID
        # nicht bei jedem Assignment erneut abgefragt wird.
        $script:GroupCache[$GroupId] = $Resolved

        return $Resolved
    }
}

# ---------------------------------------------------------------------------
# 5. Assignment Target analysieren
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
    # Gruppen
    #
    # Je nach API-Version / Ressourcentyp kann die ID unterschiedlich
    # heißen. Ältere Intune APIs verwenden teilweise groupId, neuere
    # Targets teilweise entraObjectId.
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

        # Exclusion wird über den OData-Typ erkannt.
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
    # Unbekanntes Target
    # -----------------------------------------------------------------------

    return [PSCustomObject]@{
        Type        = if ($OdataType) { $OdataType } else { "Unknown" }
        GroupId     = $null
        GroupName   = $null
        Assignment  = "Unknown"
    }
}

# ---------------------------------------------------------------------------
# 6. Assignment-Information in Ergebnisobjekt schreiben
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
# 7. Kategorie aus Graph lesen
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

        Write-Host "Objekte gefunden: $($Objects.Count)" -ForegroundColor Gray
    }
    catch {

        Write-Warning "$Name konnte nicht gelesen werden: $($_.Exception.Message)"
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
                $DisplayName = "<ohne Namen>"
            }

            $ObjectId = [string]$Object.id

            if ([string]::IsNullOrWhiteSpace($ObjectId)) {
                Write-Warning "$Name enthält ein Objekt ohne ID."
                continue
            }

            $AssignmentUri = $AssignmentEndpointTemplate `
                -replace "\{id\}", $ObjectId

            $Assignments = Invoke-GraphGetAll `
                -Uri "https://graph.microsoft.com/$ApiVersion$AssignmentUri"

            $Intent = ""

            # Apps haben zusätzlich Required / Available / Uninstall.
            if ($UseIntent -and $Assignments.Count -gt 0) {

                # Bei mehreren Assignments wird der Intent pro Assignment
                # im Ergebnis zusammengeführt.
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
                "$Name '$($Object.displayName)' konnte nicht vollständig verarbeitet werden: $($_.Exception.Message)"
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
# Aktuell Beta.
# Microsoft dokumentiert configurationPolicies weiterhin als Beta.
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
# 9. Klassische Device Configurations
# ===========================================================================
#
# API:
#   GET /deviceManagement/deviceConfigurations
#   GET /deviceManagement/deviceConfigurations/{id}/assignments
#
# v1.0 verfügbar.
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
# v1.0 verfügbar.
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
# v1.0 verfügbar.
#
# Wichtig:
# Microsoft empfiehlt inzwischen ausdrücklich, die Apps zunächst ohne
# $expand=assignments zu laden und danach die Assignments pro App zu lesen.
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
# Aktueller Graph-Endpoint:
#
#   GET /deviceManagement/deviceManagementScripts
#   GET /deviceManagement/deviceManagementScripts/{id}/assignments
#
# Beta.
#
# Permission:
#   DeviceManagementScripts.Read.All
#
# Je nach Tenant/API-Stand kann dieser Endpoint eingeschränkt bzw.
# unterschiedlich verfügbar sein.
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
# Aktueller Graph-Endpoint:
#
#   GET /deviceManagement/deviceHealthScripts
#   GET /deviceManagement/deviceHealthScripts/{id}/assignments
#
# Beta.
#
# Device Health Scripts verwenden DeviceManagementScripts.Read.All.
# ===========================================================================

Get-IntuneCategory `
    -Name "Device Health Scripts" `
    -ObjectEndpoint "/deviceManagement/deviceHealthScripts" `
    -AssignmentEndpointTemplate "/deviceManagement/deviceHealthScripts/{id}/assignments" `
    -ObjectType "Device Health Script" `
    -ApiVersion "beta"

# ===========================================================================
# 16. Ergebnis ausgeben
# ===========================================================================

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Ergebnis" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

Write-Host "Intune-Objekte : $($script:Results.Count)"
Write-Host "Gruppen im Cache: $($script:GroupCache.Count)"

# Objekt-/Assignment-Sicht
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
    Write-Host "CSV geschrieben: $CsvPath" -ForegroundColor Green
}
catch {

    Write-Warning "CSV konnte nicht geschrieben werden: $($_.Exception.Message)"
}

# ===========================================================================
# 18. Optionale gruppenzentrierte Sicht
# ===========================================================================

if ($CreateReverseLookup) {

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "Gruppenzentrierte Sicht" -ForegroundColor Cyan
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
        Write-Host "Reverse CSV geschrieben: $ReverseCsvPath" `
            -ForegroundColor Green
    }
    catch {

        Write-Warning `
            "Reverse CSV konnte nicht geschrieben werden: $($_.Exception.Message)"
    }
}

# ===========================================================================
# 19. Ergebnis auch als PowerShell-Objekt zurückgeben
# ===========================================================================

$script:Results
