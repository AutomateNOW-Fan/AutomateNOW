# AutomateNOW! PowerShell module

> Requires an account on an AutomateNOW! instance

![image](usage-example.png)

```
Created by AutomateNOW-Fan
```
```
⚠ Not affiliated with InfiniteDATA
```
## Installation 🏗

Install from the PowerShell Gallery 👉 `Install-Module -Name AutomateNOW -Scope CurrentUser`
<br/><br/>
## Usage 🤔
Use `Connect-AutomateNOW` to establish your session (access token)
<br/><br/>
## Features 🤓

- Completely browserless operation
- Compatible with both Windows PowerShell & PowerShell Core
- Class objects and enums defined (see Classes.ps1)
- Supports both http & https protocols
- Session token refreshing is handled automatically
- Pipeline capability
- All function sets include an Export function
- All functions include help by way of the -? parameter
- Alternate encryption key bytes can be supplied (let's hope it is never needed 🤞)
<br/><br/>
## Efficacy 🧪

This module has been tested against the below versions of AutomateNOW!

- 3.3.1.73 & 3.3.1.74HF1
<br/><br/>
## Change Log 📝

### 1.0.9
- Added new functions: `Export-AutomateNOWDomain`, `Export-AutomateNOWIcon`, `Export-AutomateNOWNode`, `Export-AutomateNOWTag`, `Export-AutomateNOWTimeZone`, `Export-AutomateNOWUser`, `Get-AutomateNOWTimeZone`, `Import-AutomateNOWLocalIcon`, `Import-AutomateNOWTimeZone`, `New-AutomateNOWNode`, `Read-AutomateNOWIcon`, `Remove-AutomateNOWNode`, `Write-AutomateNOWIconData`
- Removed all instances of the -All parameter from the Get-* functions. Instead, the Get-* functions will now return all items by default when no parameters are supplied.
- Consolidated the two session variables into one
- Added pipeline capability to (virtually) all functions 🥳
- Replaced validation arrays with Enums
- Added a welcome 'MOTD' to the default output of `Connect-AutomateNOW`
- Added _-SkipMOTD_ parameter for skipping the 'MOTD' to `Connect-AutomateNOW`
- Added base classes _[ANOWDomain]_, _[ANOWFolder]_, _[ANOWNode]_, _[ANOWTag]_, _[ANOWTask]_, _[ANOWUser]_, _[ANOWWorkflow]_
- Added enums for Icons, Tasks, Users and Workflows
- Removed functions (most of these will be added back after fine-tuning): `Get-AutomateNOWAdhocReport`, `Get-AutomateNOWAuditLog`, `Get-AutomateNOWCalendar`, `Get-AutomateNOWOverview`, `Get-AutomateNOWTriggerLog`, `Read-AutomateNOWTimeZone`, `Show-AutomateNOWDomain`, `Show-AutomateNOWTaskType`, `Start-AutomateNOWTask`
- Removed base class (this will be back after fine-tuning): [_ANOWAuditLogEntry_]

### 1.0.8
- Added new functions: `Get-AutomateNOWAdhocReport`, `Get-AutomateNOWAuditLog`, `Get-AutomateNOWCalendar`, `Get-AutomateNOWOverview`, `Read-AutomateNOWTimeZone`
- Replaced hard-coded query strings with properly defined URL parameter hashtables with the help of `ConvertTo-QueryString`
- Fixed an issue with `Import-AutomateNOWIcon` exporting the .csv to the wrong location
- Added support for entering your own session token directly into `Connect-AutomateNOW` (optionally include refresh token + expiration date for best results)
- Added support for reading the authentication JSON payload from the clipboard
- Incorporated `Compare-ObjectProperty` (see PoshFunctions on the PowerShell Gallery)
- Initiated the beginnings of class objects for AutomateNOW objects
- Added base class _[ANOWAuditLogEntry]_ with sub classes (UPDATE, DELETE and INSERT)
- Added base class _[ANOWTimeZone]_
- Added method **CompareOldNewValues()** to derived class _ANOWAuditLogEntry_Update_ (note: only applies to UPDATE audit log entries)
- Added myriad tiny fixes

### 1.0.7
- Added new functions: `Get-AutomateNOWTask`, `Show-AutomateNOWTaskType`, `Start-AutomateNOWTask`
- Added support for transparent colors in `New-AutomateNOWTag`
- Added a requirement to use `Disconnect-AutomateNOW` before connecting to a different instance
- Added the _-Headers_ parameter to `Invoke-AutomateNOWAPI` for including additional headers (experimental)
- Incorporated `ConvertTo-QueryString` (see MSIdentityTools on the PowerShell Gallery)
- Fixed an issue with the token expiration date sometimes showing +1 hour ahead
- Fixed an issue with HTTP error hints not being shown
- Fixed an issue with the domain not being set in the header variable whenever the domain was specified with the _-Domain_ parameter of `Confirm-AutomateNOWSession`

### 1.0.6
- Added new functions: `Get-AutomateNOWWorkflow`, `Get-AutomateNOWFolder`, `New-AutomateNOWFolder`
- Added masked input to (and fixed some minor bugs with) `Connect-AutomateNOW`
- Improved guidance when http codes 401, 403 and 404 are encountered
- Fixed an issue with the usage of `Add-Type` (applies to Windows PowerShell only)
- Changed `Invoke-AutomateNOWAPI` will no longer recognize a GET request that accidentally included a body

### 1.0.5
- Fixed an issue with token updating

### 1.0.4
- Finished adding the help content with examples to each function

### 1.0.3
- Added new functions: `Import-AutomateNOWIcon`, `New-AutomateNOWTag`, `Remove-AutomateNOWTag` & `Update-AutomateNOWToken`
- Added the ability to refresh the token (See `Update-AutomateNOWToken`)
- Fixed an issue where the _-SkipCertificateCheck_ parameter was included in PowerShell 7 even when it was not needed

### 1.0.2
- Cosmetic fixes for PowerShell Gallery (again!)

### 1.0.1
- Cosmetic fixes for PowerShell Gallery

### 1.0.0
- Initial release (feedback requested)
<br/><br/>
## Caution 🚸

Use the _-NotSecure_ parameter when connecting to an instance that doesn't use https 😒
<br/><br/>
## Wish List 🌠

- add export capability for workflow diagram data to PNG

## Functions 🛠

`Confirm-AutomateNOWSession`

`Connect-AutomateNOW`

`Disconnect-AutomateNOW`

`Export-AutomateNOWDomain`

`Export-AutomateNOWFolder`

`Export-AutomateNOWIcon`

`Export-AutomateNOWNode`

`Export-AutomateNOWTag`

`Export-AutomateNOWTask`

`Export-AutomateNOWTimeZone`

`Export-AutomateNOWUser`

`Export-AutomateNOWWorkflow`

`Get-AutomateNOWDomain`

`Get-AutomateNOWNode`

`Get-AutomateNOWTag`

`Get-AutomateNOWTask`

`Get-AutomateNOWTimeZone`

`Get-AutomateNOWUser`

`Get-AutomateNOWWorkflow`

`Get-AutomateNOWfolder`

`Import-AutomateNOWIcon`

`Import-AutomateNOWLocalIcon`

`Import-AutomateNOWTimeZone`

`Invoke-AutomateNOWAPI`

`New-AutomateNOWFolder`

`New-AutomateNOWNode`

`New-AutomateNOWTag`

`New-AutomateNOWTask`

`New-AutomateNOWWorkflow`

`Read-AutomateNOWIcon`

`Remove-AutomateNOWFolder`

`Remove-AutomateNOWNode`

`Remove-AutomateNOWTag`

`Remove-AutomateNOWTask`

`Remove-AutomateNOWWorkflow`

`Set-AutomateNOWPassword`

`Switch-AutomateNOWDomain`

`Update-AutomateNOWToken`

`Write-AutomateNOWIconData`


