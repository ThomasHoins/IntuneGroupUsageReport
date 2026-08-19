# Intune Group Usage Report

This script inspects Microsoft Intune resources and identifies which Entra ID groups are used in their assignment targets.

It scans the main Intune categories and builds a group-centric summary, showing which groups are used by which policies, apps, scripts, and other resources.

## What it covers

The script currently reviews:

- Configuration profiles / Settings Catalog
- Classic device configurations
- Compliance policies
- Mobile apps (required / available / uninstall intent captured)
- iOS managed app protection policies
- Android managed app protection policies
- Proactive remediations / device management scripts
- Device health scripts

It also detects:

- All Users
- All Devices
- Include vs exclude assignment targets

## Authentication and permissions

The script relies on Microsoft Graph delegated permissions and uses interactive sign-in through Connect-MgGraph.

Required scopes:

- DeviceManagementConfiguration.Read.All
- DeviceManagementApps.Read.All
- DeviceManagementScripts.Read.All
- Group.Read.All

## How it works

1. Connects to Microsoft Graph.
2. Reads each Intune category via Invoke-MgGraphRequest.
3. Reads assignment targets for each object.
4. Resolves group IDs via Graph and caches them.
5. Builds a group-centric summary of usage.
6. Exports the result to CSV.

The output is primarily group-centered, so the default report is organized by group instead of by Intune policy.

## Usage

Run the script from PowerShell 7+:

```powershell
.\Get-IntuneGroupUsageReport.ps1
```

Optional:

```powershell
.\Get-IntuneGroupUsageReport.ps1 -CsvPath .\MyReport.csv
.\Get-IntuneGroupUsageReport.ps1 -CreateReverseLookup
```

## Output

The script writes:

- a CSV report in the current directory by default
- a group-centric console summary
- an optional reverse lookup report when -CreateReverseLookup is used

The default CSV is grouped by Entra group, which makes it easier to answer questions such as: “Which policies and apps are assigned to this group?”

The actual CSV contains three columns:

- GroupName
- GroupId
- UsedIn

Example CSV output:

```csv
GroupName,GroupId,UsedIn
"IT Admins","9b0d2b12-1d5b-4b13-a6cf-f274fa10f219","Configuration Profile / Settings Catalog: Corporate WiFi [Include] | Compliance Policy: Windows 10 [Include] | Mobile App: Teams [Include] <Required>"
"Engineering","20b5fd71-0ee7-4b4c-a5d1-0c3d7231bb7a","Device Configuration: Laptops [Include] | Proactive Remediation: Disk Cleanup [Exclude]"
"All Users","","Compliance Policy: Baseline [Include] | App Protection: Finance iOS [Include]"
```

Example console summary:

```text
GroupName                     GroupId                              UsedIn
---------                     -------                              ------
IT Admins                     9b0d2b12-1d5b-4b13-a6cf-f274fa10f219  Configuration Profile / Settings Catalog: Corporate WiFi [Include] | Compliance Policy: Windows 10 [Include] | Mobile App: Teams [Include] <Required>
Engineering                   20b5fd71-0ee7-4b4c-a5d1-0c3d7231bb7a  Device Configuration: Laptops [Include] | Proactive Remediation: Disk Cleanup [Exclude]
All Users                     ""                                 Compliance Policy: Baseline [Include] | App Protection: Finance iOS [Include]
```

## Notes

- Some Graph endpoints are still beta.
- The script handles paginated Graph responses and normalizes dictionary-based objects returned by Graph in some tenants.
- It is designed for delegated Microsoft Graph access and interactive sign-in.
