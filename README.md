# AutomateNOW! PowerShell module

> Requires an account on an AutomateNOW! instance

<img width="1115" height="366" alt="usage-example" src="https://github.com/user-attachments/assets/e20134de-0336-4421-b9d8-9fa88006d2c4" />

```
Created by AutomateNOW-Fan
```
```
⚠ Not affiliated with Beta Systems
```
## Efficacy 🧪

Compatible with AutomateNOW! version _3.3.1.95 HF2<sup>[1]</sup>_
<br/><br/>
## Installation 🏗

Install from the PowerShell Gallery 👉 `Install-Module -Name AutomateNOW -Scope CurrentUser`
<br/><br/>
## Usage 🤔
Use `Connect-AutomateNOW` to establish your session
<br/><br/>
## Features 🤓

- Completely browserless operation
- Both http & https protocols supported
- PowerShell Core (incl. Linux 🐧) & Windows PowerShell compatible
- Classes and enums are defined (see Classes.psm1)
- Pipeline capability to streamline your workloads
- Session tokens will be automatically refreshed during usage
- All functions can return help with Get-Help or the -? parameter
- PSScriptAnalyzer compliant / Approved verbs only
- Alternate encryption key bytes can be supplied (let's hope it is never needed 🤞)
- Integration with the git app for showing out of sync item that require manual merging
- Edit source code objects with NotePad (Windows only for now)
<br/><br/>
## Change Log 📝

## 1.0.42
### Major updates
- Rated A+ for code quality by Copilot 🤖 (requires `copilot-instructions.md`)
- A `copilot-instructions.md` file is now included with this project (defensive documentation 🛡️)
- Importing and Exporting Domain JSON is added and fully supported
- All 5 types of Secret Vaults 🔒 are added and partially supported
- You can now easily write to disk 💾 each of the sysout logs from restarted Tasks (including from round-robin load balancer)
- Bump compatibility to ANOW version _3.3.1.95 HF2_

### Minor updates
- A code repository object is no longer required for `Compare-AutomateNOWCodeRepositoryConflictItem` (improves pipeline capability)
- When auditing a users security roles, you can now specify a limited array of permissions to check
- Added filtering options to `Show-AutomateNOWTaskTemplateType`
- `Read-AutomateNOWWorkflowTemplateItem` no longer returns an empty object when the Workflow Template is empty
- Strengthened the filtering within `Get-AutomateNOWTask` & `Get-AutomateNOWServiceManager` to ensure correct results
- Non-domain-admins can now change the properties of an existing View

### Detailed Change Log
- Added new functions: 'Add-AutomateNOWSecretVaultSecret', 'Clear-AutomateNOWSecretVaultCache', 'Copy-AutomateNOWSecretVault', 'Export-AutomateNOWDomainJSON', 'Export-AutomateNOWSecretVault', 'Get-AutomateNOWSecretVault', 'Import-AutomateNOWDomainJSON', 'New-AutomateNOWSecretVault', 'New-AutomateNOWViewSetup', 'Read-AutomateNOWIconSet', 'Read-AutomateNOWNotificationGroupMember', 'Remove-AutomateNOWSecretVault', 'Rename-AutomateNOWSecretVault', 'Set-AutomateNOWSecretVault', 'Set-AutomateNOWSecretVaultDefault', 'Set-AutomateNOWViewSetup', 'Test-AutomateNOWSecretVault', 'Write-AutomateNOWObjectVersion'
- Added the `-PermissionList` parameter to `Measure-AutomateNOWSecUserPermission`
- Added the `-NoDomain` parameter to `Invoke-AutomateNOWAPI`
- Added a token expiration check to `Invoke-AutomateNOWAPI`
- Renamed `Restore-AutomateNOWObjectVersion` to `Write-AutomateNOWObjectVersion`
- Renamed `Get-AutomateNOWNotificationGroupMember` to `Read-AutomateNOWNotificationGroupMember`
- Renamed `Read-AutomateNOWIcon` to `Read-AutomateNOWIconSet`
- Removed the `-Synchronous` parameter from `Start-AutomatenowScheduleTemplate`
- Removed the `-CodeRepository` parameter from `Compare-AutomateNOWCodeRepositoryConflictItem`
- `Get-AutomateNOWSchedule` now only accepts id's from and will only return Schedule (Trigger) objects
- `Get-AutomateNOWServiceManager` now only accepts id's from and will only return Service Manager objects
- `Get-AutomateNOWTask` now only accepts id's from and will only return Task objects
- `Get-AutomateNOWWorkflow` now only accepts id's from and will only return Workflow objects
- Cleaned up and aligned all parameters within the in-line help (including the parameter ordering)
- Fixed pipeline issues with `Confirm-AutomateNOWCodeRepository` and `Confirm-AutomateNOWScheduleTemplate`
- Fixed an issue with `Get-AutomateNOWDeletedObject` and Self-Service Templates
- Fixed the KByte/sec display in `Write-AutomateNOWIconData`


## 1.0.41
### Major updates
- Retrieving sysout logs is now possible 🥳
- Non-admin users can now audit their own security permissions (domain role privileges) 📜
- Admins can now compare the security permissions (domain role privileges) between 2 users 🔎
- The content (items) within Code Repositories can now be transformed for batch export (see FAQ)
- _Force Complete_ and _Force Fail_ are now added and fully supported
- Searching all domain roles for instances of a Tag 🏷️ is now possible
- Bump compatibility to ANOW version _3.3.1.93<sup>[1]</sup>_

<sup>[1] Should work with _3.3.1.94_ but not tested yet</sup>

### Minor updates
- The individual settings of items with Schedule Templates can now be configured
- Tracing Tasks, Workflows & Service Managers will now always return the specific class object instead of the generic [ANOWProcessing] base class
- Restarting Workflows, Tasks, Schedules & Service Managers now returns back the restarted [ANOWProcessing] object along with other small improvements
- Security Role objects will now always have the associated Domain Role objects (if any) embedded within
- User objects will now always have their associated Security Role objects (if any) embedded within
- The pipeline can now be used to add items to a Data Source
- Cleaned up a couple of minor discrepancies within the Classes.psm1 🧹
- Tags within domain role permissions are now always properly forgotten (cleared) whenever the permission is set to false
- `Read-AutomateNOWSecurityRoleDomain` now always requires an [ANOWSecRole] object

### Detailed Change Log
- Added new functions: `Compare-AutomateNOWSecUserPermission`, `Complete-AutomateNOWSchedule`, `Complete-AutomateNOWServiceManager`, `Complete-AutomateNOWTask`, `Complete-AutomateNOWWorkflow`, `ConvertFrom-AutomateNOWCodeRepositoryItem`, `Export-AutomateNOWSecUserPermission`, `Export-AutomateNOWServiceManagerTemplateItem`, `Get-AutomateNOWAgentSysOutLog`, `Measure-AutomateNOWSecUserPermission`, `New-AutomateNOWSecUserPrivilegeList`, `New-AutomateNOWSecUserPrivilegeLookupTable`, `New-AutomateNOWSecUserPrivilegeReport`, `Resolve-AutomateNOWSecUserPermission`, `Save-AutomateNOWAgentSysOutLog`, `Search-AutomateNOWSecurityRole`, `Set-AutomateNOWScheduleTemplateItem`
- Added a new constructor to the 4 sub-classes of [ANOWProcessing] that allows the conversion of [ANOWProcessing] objects to their sub class<sup>[2]</sup>
- Added a new constructor to the 4 sub-classes of [ANOWProcessingTemplate] that allows the conversion of [ANOWProcessingTemplate] objects to their sub class<sup>[3]</sup>
- Added the `-restartType` parameter to `Restart-AutomateNOWWorkflow` and `Restart-AutomateNOWServiceManager`
- Added new parameters `-AdminsOnly`, `-NonAdminsOnly` and `-NoWarning` to `Get-AutomateNOWSecUser`
- Added the `-AllowTimeout` parameter to `Connect-AutomateNOW` (this is intended to accomodate for certain edge case git scenarios)
- Removed the `-SecurityRole` parameter from `Set-AutomateNOWSecurityRoleDomain` (improves pipeline support)
- Removed the `-OverrideProcessingType` parameter from `Get-AutomateNOWWorkflowTemplate`. Use `Get-AutomateNOWProcessingTemplate` instead.
- Downgraded the 'SecRole' property inside of the [ANOWDomainRole] class from an [ANOWSecRole] object to a string
- Upgraded the 'resource' property inside of the [ANOWResourceTimestampState] class from a string to an [ANOWSemaphore] object
- Upgraded the 'actionTimestamp' property inside of the [ANOWAuditLog] class from a string to a [datetime] object
- Replaced all instances of the `-Type` parameter with something more specific (e.g. `-DataSourceType`)
- Fixed an issue where `Get-AutomateNOWSecurityRole` failed to accept certain types of internal security roles when using the `-Id` parameter
- Fixed an issue with `Get-AutomateNOWSecUser` where the secRoles property was not populated
- Fixed an issue with `Merge-AutomateNOWCodeRepositoryConflictItem` during post-processing of the result
- Fixed an issue with `Get-AutomateNOWProcessingState` that occurred when the associated processing template no longer exists
- Fixed an issue with the [ANOWProcessing] class where the 'internalProcessingStatus' property was defined as an enum instead of a string
- Fixed an issue with the [ANOWSecRoleDomain] class where the members related to Tags 🏷️ were joined into a single string instead of a string array

<sup>[2] This was required for accurate tracing with `Trace-AutomateNOWProcess` because PowerShell class inheritance is one-directional</sup>

<sup>[3] This was required for exporting the JSON content of all possible items within a Code Repository (see FAQ)</sup>

## 1.0.40
### Major updates
- Fixed an issue with `Set-AutomateNOWAgent` when changing the configuration of an Agent that could result in a corrupted Agent definition

### Detailed Change Log
- The default sort order for `Get-AutomateNOWWorkflow`, `Get-AutomateNOWTask`, `Get-AutomateNOWSchedule` and `Get-AutomateNOWServiceManager` is now descending.
- Fixed an issue when trying to use the `-Name` parameter of `Get-AutomateNOWContextVariable`

## 1.0.39
### Major updates
- Communication Notes 📝 are added and fully supported
- Creating API users 🤖 is added and fully supported
- Reading the Agent Log (not sysout) is added and fully supported
- Bump compatibility to ANOW version _3.3.1.92_

### Minor updates
- You can now create and delete Context Variables
- You can now reload Workflows/Tasks that are on hold ⏸️
- You can now 'load items' on lazy mode workflows that are on hold ⏸️
- You can now 'restate' workflows that were Force Completed or Force Failed
- You can now Activate (enable) and Deactive (disable) user accounts
- You can now set and unset the Processing Template within Processing Deadline Monitors
- Launching Processing Templates with multiple tags 🏷️ assigned works correctly now
- When creating a new user, you can now copy roles from another user
- The `-Name` parameter of `Get-AutomateNOWContextVariable` now accepts a string array
- `ConvertFrom-AutomateNOWContextVariable` now defaults to JSON output
- `Trace-AutomateNOWProcessing` (and its aliases) now returns [ANOWProcessingContextVariable] class objects instead of generic [PSCustomObject] objects when using the `-ReturnContextVariables` parameter
- The `-DesignTemplate` parameter in the New Processing Template functions now requires an actual [ANOWDesignTemplate] object

### Detailed Change Log
- Added new functions: `Disable-AutomateNOWSecUser`, `Enable-AutomateNOWSecUser`, `Export-AutomateNOWBusinessViewItem`, `Export-AutomateNOWCommunicationNote`, `Export-AutomateNOWScheduleTemplateItem`, `Export-AutomateNOWServiceManagerTemplateDependency`, `Export-AutomateNOWWorkflowTemplateDependency`, `Export-AutomateNOWWorkflowTemplateItem`, `Get-AutomateNOWAgentLog`, `Get-AutomateNOWCommunicationNote`, `New-AutomateNOWCommunicationNote`, `New-AutomateNOWContextVariable`, `Remove-AutomateNOWCommunicationNote`, `Remove-AutomateNOWContextVariable`, `Reset-AutomateNOWWorkflow`, `Show-AutomateNOWCollaborationWall`, `Update-AutomateNOWCommunicationNote`, `Update-AutomateNOWWorkflowLazyItem`
- Fixed a handful of classes that had a typo in their Create() method
- Fixed a number of issues with `New-AutomateNOWServiceManagerTemplate`
- Fixed an issue with the `Start-AutomateNOW*` functions (for processing templates) when assigning multiple tags
- Fixed an issue with `Save-AutomateNOWDataSourceItem` when saving text files
- Fixed an issue when specifying a Phone Number 📞 in `New-AutomateNOWSecUser`
- Fixed an issue (PowerShell Core only) when specifying a password in `New-AutomateNOWSecUser`
- Added the parameters `-APIUser` & `-Description` to `New-AutomateNOWSecUser`
- Fixed pipeline support for all of the Skip, Suspend, Resume & Confirm functions
- Added the parameter `-ProcessingTemplate` to `Set-AutomateNOWServiceManagerTemplate`
- Added a warning to `Connect-AutomateNOW` if the licence status is less than 30 days (suppress with -Quiet)
- Fixed a few functions that were missing an example within the in-line help
- Moved older Change Log entries to [README-OLD.md](README-OLD.md)
- Many tiny clean-ups & optimizations 🧹

<br/><br/>
## Caution 🚸

Use the _-NotSecure_ parameter when connecting to an instance that doesn't use https 😒

## Wish List 🌠

- Expand and enrish the sorting options for all Get functions
- Export diagrams to PNG
- Automatic binary file MIME type detection for `Add-AutomateNOWDataSourceItem`
- Refactor any redundant code
- The individual Export functions need to be enhanced (Use `Export-AutomateNOWMigration` for now)
- Ability to action individual items in a code repository instead of applying the action to all items
- Support for establishing multiple concurrent sessions to different ANOW instances or domains

## Bonuses* 🎰

- List & apply tags, folders etc. on an instance that you may not have permission to in the UI *sometimes*
- Deep search for root Workflows that were spawned by other Tasks/Workflows
- Modify the source code of certain objects (e.g. Stocks)
- Modify the template definition within a Design Template object
- Detect MIME type automatically when uploading text files to text file stores
- Utilize temporal duration timestamps unrestricted within Processing Dependencies (See `Add-AutomateNOWWorkflowTemplateDependency`)
- Non-admins can modify the settings of their Views

<sub>* things the console does not allow or provide for</sub>

## Questions ❓

### Is this module supported by or affiliated with Beta Systems (formerly InfiniteDATA)
>No. This should be considered a community-supported tool.

### What exactly can I do with this module? How complete is this?
>See the feature chart below

<img width="1338" height="1401" alt="feature-chart" src="https://github.com/user-attachments/assets/b47bc7dd-e98d-4419-908d-b2a821899c9a" />

### Where are the connection details stored in my PowerShell session after successfully authenticating?
>Check the global variable `$anow_session`

### Once connected, what's the fastest way to get my current access token into my clipboard so I can use it elsewhere?
>`$anow_session.AccessToken | Set-Clipboard`

### Which version of PowerShell do I need?
>This module is compatible with both `Windows PowerShell 5.1` and `PowerShell Core 7.x`

### Do the functions in this module utilize the PowerShell pipeline?
>Yes, except where it doesn't make sense. Otherwise, this module is designed to take advantage of the pipeline.

### I imported the AutomateNOW module into my PowerShell session. What's next?
>Try `Connect-AutomateNOW -?`. Also try `Get-Command -Module AutomateNOW` to see the full list of commands.

### How can I specify the domain with the `-Domain` parameter of `Connect-AutomateNOW` if I don't know what domains are available to my account?
>Use `Connect-AutomateNOW` without the `-Domain` parameter to discover available domains to your account.

### How do I use a particular command? Where's the help?
>Type the name of the command followed by -? for quick syntax. For the full help with examples, try `Get-Help NameOfCommand -Full`.

### Help! I keep receiving the error message "Parameter set cannot be resolved using the specified named parameters."
>Type the name of the command followed by -?. You need to review the "parameter sets". Not all parameters can be mixed with others. Please consult the built-in help for that individual function.

### How do I see 👀 the actual payloads, headers, parameters that are sent to ANOW?
>Include the `-Verbose` parameter (use with caution)

### Why don't these functions share the identical verbs as the ANOW UI? (e.g. "Suspend" instead of "Hold")
>This module uses only approved verbs. See https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands for more.

### Why do I only receive 100 results when using the Get commands? I should be getting more results...
>The default values of `-startRow` and `-endRow` are 0 and 100 respectively. You can use those parameters to paginate the results.

### How do I paginate the results?
>You will have to develop your own routine for interating through the pages. Pay careful attention to which property you are sorting by! (I'm looking at you `Design Audit Log`)

### Why doesn't this module work correctly with my older version of AutomateNOW?
>This module uses classes and enums to manage the schema. Beta Systems (formerly InfiniteDATA) makes frequent updates to this schema (with most new non-hotfix patch updates). Thus, the incompatilities cannot be helped. You will need to downgrade to a previous version of this module that matches your ANOW version.

### How does the password encryption in this module work?
>It's the same as the console. See the `Protect-AutomateNOWEncryptedString` and `Unprotect-AutomateNOWEncryptedString` functions for technical details.

### Why are some of the columns in the export .csv containing `[System.Object]`?
>All of the individual Export functions should be considered work-in-progress. For now, use the `Export-AutomateNOWMigration` function to create proper json exports.

### How do I add a Task Template to a Workflow Template?
>Use `Add-AutomateNOWWorkflowTemplateItem`

### How do I change my domain?
>Use `Switch-AutomateNOWDomain -Domain 'MyDomain'`

### How to retrieve a Task or Workflow (a.k.a. a "job") by its RunId?
>Use `Get-AutomateNOWTask -Id 12345` for Tasks or `Get-AutomateNOWWorkflow -Id 12345` for Workflows. There is also `Get-AutomateNOWProcessingList -Id 12345` which can provide both Task and Workflow outputs.

### How to push my changes to my properly configured code repository that my admin provided?
> Step 1 - Select the branch of the repository
> `Select-AutomateNOWCodeRepositoryBranch` -CodeRepository $repository -Branch 'development' -Force

> Step 2 - Make a change to one of the items in the repository
> `Set-AutomateNOWTaskTemplate` -TaskTemplate $task_template -processingCommand $script -Force

> Step 3 - Commit all of the changes in the repository
> `Publish-AutomateNOWCodeRepository` -CodeRepository $repository -Force

> Step 4 - Push all of the commited changes in the local repository to the remote repository
> `Send-AutomateNOWCodeRepository` -CodeRepository $repository -Force

> Step 5 - Synchronize the local and remote repositories - Do not forget this step! 😅
> `Sync-AutomateNOWCodeRepository` -CodeRepository $repository -Force

### I made a change to the code on my properly configured remote repository. How do I pull it down to the local repository?
> Step 1 - Select the branch of the repository
> `Select-AutomateNOWCodeRepositoryBranch` -CodeRepository $repository -branch 'development' -Force -Quiet

> Step 2 - Pull all of the commited changes in the remote repository to the local repository
> `Receive-AutomateNOWCodeRepository` -CodeRepository $repository -Force

> Step 3 - Synchronize the local and remote repositories - Do not forget this step! 😅
> `Sync-AutomateNOWCodeRepository` -CodeRepository $repository -Force

### Where are the 5 types of Processing Event Logs in the ANOW UI?
>Use `Get-Help Read-AutomateNOWProcessingEventLog -Full` for some hints on where they all are.

### I want to set all values in my Metric to null (i.e. to reset them). How can I do this?
>It's a two-step process. In any order:
>1) Run `Set-AutomateNOWMetric` with the `-UnsetValue` parameter
>2) Run `Set-AutomateNOWMetric` with these parameters: `-UnsetValueUnit` `-UnsetMinValue` `-UnsetVeryLowThreshold` `-UnsetLowThreshold` `-UnsetHighThreshold` `-UnsetVeryHighThreshold` `-UnsetMaxValue`

### Why is there a `-Detailed` parameter for the 9 Resource related Get-* functions? What benefit does it provide?
>- Calendars will include: calculatedDates
>- Events will include: (unknown)
>- Locks will include: lockState
>- Metrics will include: historicalValues
>- Physical Resources will include: historicalValues
>- Semaphores will include: (nothing)
>- Stocks will include: (nothing)
>- Time Windows will include: (nothing)
>- Variables will include: historicalValues

### How do I rearrange the sort orders of the child nodes in my load balancer node?
> Refer to `Push-AutomateNOWLoadBalancerNode` and `Pop-AutomateNOWLoadBalancerNode`

### I'm confused about why some functions are prefixed with New- and others with Add-?
> `New` is for when we are creating something new from scratch. `Add` is for when we are adding an existing object to another existing object.

### I'm confused about why some functions are prefixed with Get- and others with Read-?
> `Get` is for when we are fetching something that can be created with a `New` command. `Read` is for when we are fetching something that can be created with an `Add` command.

### Why is there no Copy and Rename functions for Time Triggers?
> The ANOW application does not actually offer this functionality. You must 'add' a Time Trigger to a Schedule Template.

### How can I use `Edit-AutomateNOWDataSourceItem` if I don't already know the Id (36 character GUID) of the item?
> Use the built-in help `Get-Help Edit-AutomateNOWDataSourceItem -Examples` to see examples

### Why doesn't `Get-AutomateNOWContextVariable` include the level of the variable (i.e. Self, Parent or Root)?
> The scope of the variable is not actually included within the [ANOWProcessingContextVariable] object (refer to the ANOW schema and/or Classes.psm1). Scope is a -derived- property which is calculated by comparing the ProcessingId of the variable with the one specific task/workflow Id that you are comparing with. In other words, you will have to calculate this yourself. However, the functionality to include a scope with a context variable may be added as an enhancement in the future (e.g. `Show-AutomateNOWContextVariable`).

### I'm tired of seeing the Trigger Items in the results of `Trace-AutomateNOWProcessing`
> Use the `-DoNotIncludeTriggers` parameter with `Trace-AutomateNOWProcessing`. Even better, you can also use the `-Synchronous` parameter when starting the Task/Workflow Template.

### I need more from `Trace-AutomateNOWProcessing`. It only returns Workflows which were parented by my Workflow. I need to see *everything* which could have been launched by my Workflow.
> Use the `-PerformDeepSearch` parameter. Note that this parameter will significantly increase the time required. Also, the UI does not offer this functionality.

### How do I start a Workflow, wait for it to finish executing and then return all of the related Context Variables in a single command?
> `Get-AutomateNOWWorkflowTemplate -Id 'WorkflowTemplate1' | Start-AutomateNOWWorkflowTemplate | Trace-AutomateNOWProcessing -WaitForExecution -ReturnContextVariables`

### `Trace-AutomateNOWProcessing` doesn't seem to work. It doesn't return all of the processing items that it should be.
> Try adding the `-IncludeArchived` switch parameter to include searching the archived processing items.

### How can I see the items that exist in the UI under the Monitoring -> Trigger tab?
> Use `Get-AutomateNOWSchedule` to retrieve these

### What is the difference between an [ANOWResource] object, an [ANOWAnomaly] object and the [ANOWResourceAnomaly] object? This is confusing
> An [ANOWResource] is a base class that is the foundation for the 9 Resource objects (e.g. Locks, Stocks, Metrics).
> An [ANOWAnomaly] is a class representing the ANOW Anomaly object. These are intended for interpreting Metrics.
> An [ANOWResourceAnomaly] is a class representing what you get when you add an Anomaly to a Metric.
> Think of [ANOWResourceAnomaly] as synonymous with adding a Task Template to a Workflow Template (which creates a Workflow Template Item) or a Dashboard to a Business View (which creates a Business View Item)

### Why doesn't `Read-AutomateNOWSecurityAccessToken` include the actual security token?
> `Read-AutomateNOWSecurityAccessToken` will tell you everything else about the security token objects except the actual token. This is by design. You only get to see the token once when it was created with `Add-AutomateNOWSecurityAccessToken`.

### Why do some functions sort descending by default and others ascending?
> That is the behavior of the ANOW console.

### Wait! There is `Read-AutomateNOWAgentServerNode` function but also a `Read-AutomateNOWServerNodeAgent`. Is this some kind of mistake?
> No, but this does get confusing. `Read-AutomateNOWAgentServerNode` fetches the [ANOWAgentServerNode] objects that have been attached to an Agent (see classes.psm1 for more details on the ANOW classes). Whereas `Read-AutomateNOWServerNodeAgent` exists to take advantage of a similarly named ANOW endpoint that will fetch the Agents ([ANOWAgent] class object) to which the provided Server Node is attached to (mounted on). The former is a function that retrieves full-fledged class objects whereas the latter is more of a shortcut to lookup Agents associated with a particular Server Node thus these two functions are actually quite different.

### How can I see a list of all verbs that are represented in this module?
> ((Get-Command -Module AutomateNOW | Select-Object -ExpandProperty Name) -split '-[a-z0-9]{1,}' -match '[a-z]{1,}' | Sort-Object -Unique ) -join ', '

### Why do I not receive the expected results when using the `-Title` parameter with `Read-AutomateNOWWorkflowTemplateItem` or `Read-AutomateNOWServiceManagerTemplateItem`?
> The "title" and "name" property of Processing Template Items can be misleading. Upon creation (i.e. adding) the item, the "name" property of the Item is automatically created and will be immutable (typically with a ".1" suffix). The ANOW UI will then use this "name" as the "title" as well since the "title" is NULL by default. To populate the "title" property for each Item you would need to specifically set the "title".

### How can I resolve (merge) Out Of Sync conflicts in my git repository?
> The first below code will show the left/right comparison (yours/theirs) using your installed git executable. This will help you to decide whether to "Accept Yours" or "Accept Theirs".
> `$repository = Get-AutomateNOWCodeRepository -Id 'MyRepository'`
> `$conflict_item = $repository | Get-AutomateNOWCodeRepositoryOutOfSyncItem | Select-Object -First 1`
> `$comparison = $conflict_item | Compare-AutomateNOWCodeRepositoryConflictItem -CodeRepository $repository`
> `$comparison | Show-AutomateNOWCodeRepositoryConflictItemComparison`
>
> The second below code will apply the "Accept Yours" decision (i.e. "Accept Left")
> $repository = Get-AutomateNOWCodeRepository -Id 'MyRepository'
> $out_of_sync_items = $repository | Get-AutomateNOWCodeRepositoryOutOfSyncItem -startRow 0 -endRow 10000
> $out_of_sync_items | Merge-AutomateNOWCodeRepositoryConflictItem -CodeRepository $repo -AcceptYours

### How can I fetch only the Server Nodes that are also Load Balancers?
> Use the `Get-AutomateNOWServerNode` with the `-AllLoadBalancers` switch parameter (depending on your scenario).

### Why is there no `Push-AutomateNOWCodeRepository` command?
> Look for the commands using the `Send` verb instead. The `Push` and `Pop` verbs are reserved for moving objects up or down (e.g. nodes within a Load Balancer).

### How do I 'close' a Communication Note?
> Use the -Close switch parameter with `Update-AutomateNOWCommunicationNote`

### How do I create a copy of a user? I was expecting `Copy-AutomateNOWSecUser` to exist.
> ANOW does not offer a copy function for users but you can copy the roles from another user by using `-CopyRolesFromUser` with `New-AutomateNOWSecUser`

### Why isn't there a `Lock-AutomateNOWSecUser` to accompany `Unlock-AutomateNOWSecUser`?
> An account can only be locked through too many failed password attempts. To enable/disable an account you can use `Enable-AutomateNOWSecUser` & `Disable-AutomateNOWSecUser`

### Where is the function for exporting items from within a Code Repository?
> Use `Export-AutomateNOWCodeRepositoryObjectSource`

### Why can't I combine the `-Id` parameter with the `-IncludeArchived` parameter when using the `Get-AutomateNOWTask` (et al) functions?
> The processing archive is already included when using the `-Id` parameter

### Why is the 'secRole' property sometimes empty on users?
> Not all users have 'internal' security roles. The 'secRole' property is a string representing the Id of the internal security role for that user

### How is it possible to send all objects within a Code Repository to the Migration Export functionality?
> `Get-AutomateNOWCodeRepository -Id 'CodeRepository1' | Read-AutomateNOWCodeRepositoryItem -startRow 0 -endRow 10000 | ConvertFrom-AutomateNOWCodeRepositoryItem | Export-AutomateNOWMigration -IndividualExportFile`

> See the full in-line help for both `Read-AutomateNOWCodeRepositoryItem` and `ConvertFrom-AutomateNOWCodeRepositoryItem`

> Note: It is not recommended to send multiple repositories across the pipeline. As a best practice, keep this process limited to one repository at a time.

### As a non-admin on the instance, how can I generate a full report of all of my permissions (granted or not) (including undocumented) for all domains?
> `Measure-AutomateNOWSecUserPermission -Me -IncludeUndocumented -FullReport | Resolve-AutomateNOWSecUserPermission`

> Note that the `-FullReport` parameter will include all privileges whether granted or not

### How can I export the permission report from the previous question to a .csv?
> `Measure-AutomateNOWSecUserPermission -Me | Export-AutomateNOWSecUserPermission`

### What if I am an admin and I wish to do the same for a different non-admin user?
> `Get-AutomateNOWSecUser -Id 'User1' | Measure-AutomateNOWSecUserPermission | Export-AutomateNOWSecUserPermission`

### 

## Functions 🛠

`Add-AutomateNOWApprovalRule`

`Add-AutomateNOWBusinessViewItem`

`Add-AutomateNOWCodeRepositoryItem`

`Add-AutomateNOWDashboardPortlet`

`Add-AutomateNOWDataSourceItem`

`Add-AutomateNOWLoadBalancerNode`

`Add-AutomateNOWNotificationGroupMember`

`Add-AutomateNOWResourceAnomaly`

`Add-AutomateNOWResultMappingRule`

`Add-AutomateNOWScheduleTemplateItem`

`Add-AutomateNOWSecretVaultSecret`

`Add-AutomateNOWSecurityAccessToken`

`Add-AutomateNOWSecurityRoleDomain`

`Add-AutomateNOWSecurityRoleUser`

`Add-AutomateNOWServerNodeEndpoint`

`Add-AutomateNOWServerNodeGroupItem`

`Add-AutomateNOWServiceManagerTemplateDependency`

`Add-AutomateNOWServiceManagerTemplateItem`

`Add-AutomateNOWTimeTrigger`

`Add-AutomateNOWWorkflowTemplateDependency`

`Add-AutomateNOWWorkflowTemplateItem`

`Approve-AutomateNOWCodeRepositoryMergeRequest`

`Clear-AutomateNOWDomain`

`Clear-AutomateNOWProcessingStateRegistry`

`Clear-AutomateNOWSecretVaultCache`

`Compare-AutomateNOWCodeRepositoryConflictItem`

`Compare-AutomateNOWSecUserPermission`

`Complete-AutomateNOWSchedule`

`Complete-AutomateNOWServiceManager`

`Complete-AutomateNOWTask`

`Complete-AutomateNOWWorkflow`

`Confirm-AutomateNOWCodeRepository`

`Confirm-AutomateNOWMigrationImport`

`Confirm-AutomateNOWScheduleTemplate`

`Confirm-AutomateNOWServiceManagerTemplate`

`Confirm-AutomateNOWSession`

`Confirm-AutomateNOWTaskTemplate`

`Confirm-AutomateNOWWorkflowTemplate`

`Connect-AutomateNOW`

`ConvertFrom-AutomateNOWCodeRepositoryItem`

`ConvertFrom-AutomateNOWContextVariable`

`Copy-AutomateNOWAdhocReport`

`Copy-AutomateNOWAgent`

`Copy-AutomateNOWAnomaly`

`Copy-AutomateNOWApproval`

`Copy-AutomateNOWBusinessView`

`Copy-AutomateNOWCalendar`

`Copy-AutomateNOWDashboard`

`Copy-AutomateNOWDataSource`

`Copy-AutomateNOWDesignTemplate`

`Copy-AutomateNOWDomain`

`Copy-AutomateNOWEndpoint`

`Copy-AutomateNOWEvent`

`Copy-AutomateNOWLock`

`Copy-AutomateNOWMetric`

`Copy-AutomateNOWNotificationChannel`

`Copy-AutomateNOWNotificationGroup`

`Copy-AutomateNOWNotificationMessageTemplate`

`Copy-AutomateNOWPhysicalResource`

`Copy-AutomateNOWProcessingFunction`

`Copy-AutomateNOWResultMapping`

`Copy-AutomateNOWRuntimeAction`

`Copy-AutomateNOWScheduleTemplate`

`Copy-AutomateNOWSecretVault`

`Copy-AutomateNOWSecurityRole`

`Copy-AutomateNOWSecurityRoleDomain`

`Copy-AutomateNOWSemaphore`

`Copy-AutomateNOWServerNode`

`Copy-AutomateNOWServerNodeGroup`

`Copy-AutomateNOWServiceManagerTemplate`

`Copy-AutomateNOWStock`

`Copy-AutomateNOWTag`

`Copy-AutomateNOWTaskTemplate`

`Copy-AutomateNOWTimeWindow`

`Copy-AutomateNOWUserReport`

`Copy-AutomateNOWVariable`

`Copy-AutomateNOWViewSetup`

`Copy-AutomateNOWWorkflowTemplate`

`Copy-AutomateNOWWorkspace`

`Deny-AutomateNOWCodeRepositoryMergeRequest`

`Disable-AutomateNOWAgentCentralManagement`

`Disable-AutomateNOWSecUser`

`Disconnect-AutomateNOW`

`Dismount-AutomateNOWAgentServerNode`

`Edit-AutomateNOWCodeRepositoryObjectSource`

`Edit-AutomateNOWDataSourceItem`

`Enable-AutomateNOWAgentCentralManagement`

`Enable-AutomateNOWSecUser`

`Export-AutomateNOWAdhocReport`

`Export-AutomateNOWAgent`

`Export-AutomateNOWAgentServerNode`

`Export-AutomateNOWAnomaly`

`Export-AutomateNOWApproval`

`Export-AutomateNOWAuditLog`

`Export-AutomateNOWBusinessView`

`Export-AutomateNOWBusinessViewItem`

`Export-AutomateNOWCalendar`

`Export-AutomateNOWCodeRepository`

`Export-AutomateNOWCodeRepositoryObjectSource`

`Export-AutomateNOWCommunicationNote`

`Export-AutomateNOWContextVariable`

`Export-AutomateNOWDashboard`

`Export-AutomateNOWDataSource`

`Export-AutomateNOWDataSourceItem`

`Export-AutomateNOWDeletedDomain`

`Export-AutomateNOWDeletedObject`

`Export-AutomateNOWDesignTemplate`

`Export-AutomateNOWDomain`

`Export-AutomateNOWDomainJSON`

`Export-AutomateNOWEndpoint`

`Export-AutomateNOWEvent`

`Export-AutomateNOWFolder`

`Export-AutomateNOWIcon`

`Export-AutomateNOWLock`

`Export-AutomateNOWMenuCustomization`

`Export-AutomateNOWMetric`

`Export-AutomateNOWMigration`

`Export-AutomateNOWMigrationImport`

`Export-AutomateNOWNotification`

`Export-AutomateNOWNotificationChannel`

`Export-AutomateNOWNotificationGroup`

`Export-AutomateNOWNotificationGroupMember`

`Export-AutomateNOWNotificationMessageTemplate`

`Export-AutomateNOWPhysicalResource`

`Export-AutomateNOWProcessingEventLog`

`Export-AutomateNOWProcessingFunction`

`Export-AutomateNOWProcessingState`

`Export-AutomateNOWProcessingTriggerLog`

`Export-AutomateNOWResourceAnomaly`

`Export-AutomateNOWResultMapping`

`Export-AutomateNOWRuntimeAction`

`Export-AutomateNOWSchedule`

`Export-AutomateNOWScheduleTemplate`

`Export-AutomateNOWScheduleTemplateItem`

`Export-AutomateNOWSecretVault`

`Export-AutomateNOWSecurityAccessToken`

`Export-AutomateNOWSecurityEventLog`

`Export-AutomateNOWSecurityRole`

`Export-AutomateNOWSecurityRoleDomain`

`Export-AutomateNOWSecurityRoleUser`

`Export-AutomateNOWSecUser`

`Export-AutomateNOWSecUserPermission`

`Export-AutomateNOWSemaphore`

`Export-AutomateNOWSemaphoreTimestamp`

`Export-AutomateNOWServerNode`

`Export-AutomateNOWServerNodeEndpoint`

`Export-AutomateNOWServerNodeGroup`

`Export-AutomateNOWServiceManager`

`Export-AutomateNOWServiceManagerTemplate`

`Export-AutomateNOWServiceManagerTemplateDependency`

`Export-AutomateNOWServiceManagerTemplateItem`

`Export-AutomateNOWStock`

`Export-AutomateNOWTag`

`Export-AutomateNOWTask`

`Export-AutomateNOWTaskTemplate`

`Export-AutomateNOWTimeTrigger`

`Export-AutomateNOWTimeWindow`

`Export-AutomateNOWTimeZone`

`Export-AutomateNOWUserReport`

`Export-AutomateNOWVariable`

`Export-AutomateNOWVariableTimestamp`

`Export-AutomateNOWViewSetup`

`Export-AutomateNOWWorkflow`

`Export-AutomateNOWWorkflowTemplate`

`Export-AutomateNOWWorkflowTemplateDependency`

`Export-AutomateNOWWorkflowTemplateItem`

`Export-AutomateNOWWorkspace`

`Find-AutomateNOWObjectReferral`

`Get-AutomateNOWAdhocReport`

`Get-AutomateNOWAgent`

`Get-AutomateNOWAgentLog`

`Get-AutomateNOWAgentSysOutLog`

`Get-AutomateNOWAnomaly`

`Get-AutomateNOWApproval`

`Get-AutomateNOWAuditLog`

`Get-AutomateNOWBusinessView`

`Get-AutomateNOWCalendar`

`Get-AutomateNOWCodeRepository`

`Get-AutomateNOWCodeRepositoryBranch`

`Get-AutomateNOWCodeRepositoryConflictItem`

`Get-AutomateNOWCodeRepositoryMergeRequest`

`Get-AutomateNOWCodeRepositoryObjectSource`

`Get-AutomateNOWCodeRepositoryOutOfSyncItem`

`Get-AutomateNOWCodeRepositoryTag`

`Get-AutomateNOWCommunicationNote`

`Get-AutomateNOWContextVariable`

`Get-AutomateNOWDashboard`

`Get-AutomateNOWDataSource`

`Get-AutomateNOWDeletedDomain`

`Get-AutomateNOWDeletedObject`

`Get-AutomateNOWDesignTemplate`

`Get-AutomateNOWDomain`

`Get-AutomateNOWEndpoint`

`Get-AutomateNOWEvent`

`Get-AutomateNOWFolder`

`Get-AutomateNOWInterface`

`Get-AutomateNOWLock`

`Get-AutomateNOWMenuCustomization`

`Get-AutomateNOWMetric`

`Get-AutomateNOWMigrationImport`

`Get-AutomateNOWNotification`

`Get-AutomateNOWNotificationChannel`

`Get-AutomateNOWNotificationGroup`

`Get-AutomateNOWNotificationMessageTemplate`

`Get-AutomateNOWPhysicalResource`

`Get-AutomateNOWProcessingFunction`

`Get-AutomateNOWProcessingList`

`Get-AutomateNOWProcessingState`

`Get-AutomateNOWProcessingTemplate`

`Get-AutomateNOWProcessingTriggerLog`

`Get-AutomateNOWResourceList`

`Get-AutomateNOWResultMapping`

`Get-AutomateNOWRuntimeAction`

`Get-AutomateNOWSchedule`

`Get-AutomateNOWScheduleTemplate`

`Get-AutomateNOWSecretVault`

`Get-AutomateNOWSecurityEventLog`

`Get-AutomateNOWSecurityRole`

`Get-AutomateNOWSecUser`

`Get-AutomateNOWSemaphore`

`Get-AutomateNOWSemaphoreTimestamp`

`Get-AutomateNOWServerNode`

`Get-AutomateNOWServerNodeGroup`

`Get-AutomateNOWServiceManager`

`Get-AutomateNOWServiceManagerTemplate`

`Get-AutomateNOWStock`

`Get-AutomateNOWTag`

`Get-AutomateNOWTask`

`Get-AutomateNOWTaskTemplate`

`Get-AutomateNOWTimeWindow`

`Get-AutomateNOWTimeZone`

`Get-AutomateNOWUserReport`

`Get-AutomateNOWVariable`

`Get-AutomateNOWVariableTimestamp`

`Get-AutomateNOWViewSetup`

`Get-AutomateNOWWorkflow`

`Get-AutomateNOWWorkflowTemplate`

`Get-AutomateNOWWorkspace`

`Import-AutomateNOWDomainJSON`

`Import-AutomateNOWIcon`

`Import-AutomateNOWLocalIcon`

`Import-AutomateNOWLocalTimeZone`

`Import-AutomateNOWTimeZone`

`Invoke-AutomateNOWAdhocReport`

`Invoke-AutomateNOWAPI`

`Measure-AutomateNOWSecUserPermission`

`Merge-AutomateNOWCodeRepositoryBranch`

`Merge-AutomateNOWCodeRepositoryConflictItem`

`Mount-AutomateNOWAgentServerNode`

`New-AutomateNOWAdhocReport`

`New-AutomateNOWAgent`

`New-AutomateNOWAnomaly`

`New-AutomateNOWApproval`

`New-AutomateNOWApprovalRule`

`New-AutomateNOWBusinessView`

`New-AutomateNOWCalendar`

`New-AutomateNOWCodeRepository`

`New-AutomateNOWCodeRepositoryBranch`

`New-AutomateNOWCodeRepositoryTag`

`New-AutomateNOWCommunicationNote`

`New-AutomateNOWContextVariable`

`New-AutomateNOWDashboard`

`New-AutomateNOWDataSource`

`New-AutomateNOWDefaultProcessingTitle`

`New-AutomateNOWDesignTemplate`

`New-AutomateNOWDomain`

`New-AutomateNOWEndpoint`

`New-AutomateNOWEvent`

`New-AutomateNOWFolder`

`New-AutomateNOWLock`

`New-AutomateNOWMetric`

`New-AutomateNOWMigrationImport`

`New-AutomateNOWNotificationChannel`

`New-AutomateNOWNotificationGroup`

`New-AutomateNOWNotificationMessageTemplate`

`New-AutomateNOWPhysicalResource`

`New-AutomateNOWProcessingFunction`

`New-AutomateNOWProcessingState`

`New-AutomateNOWResultMapping`

`New-AutomateNOWResultMappingRule`

`New-AutomateNOWResultMappingRuleCondition`

`New-AutomateNOWResultMappingRuleConditionCriteria`

`New-AutomateNOWRuntimeAction`

`New-AutomateNOWScheduleTemplate`

`New-AutomateNOWSecretVault`

`New-AutomateNOWSecurityRole`

`New-AutomateNOWSecUser`

`New-AutomateNOWSecUserPrivilegeList`

`New-AutomateNOWSecUserPrivilegeLookupTable`

`New-AutomateNOWSecUserPrivilegeReport`

`New-AutomateNOWSemaphore`

`New-AutomateNOWServerDayTimestamp`

`New-AutomateNOWServerNode`

`New-AutomateNOWServerNodeGroup`

`New-AutomateNOWServiceManagerTemplate`

`New-AutomateNOWStock`

`New-AutomateNOWTag`

`New-AutomateNOWTaskTemplate`

`New-AutomateNOWTimeWindow`

`New-AutomateNOWVariable`

`New-AutomateNOWViewSetup`

`New-AutomateNOWWorkflowTemplate`

`New-AutomateNOWWorkspace`

`Pop-AutomateNOWApprovalRule`

`Pop-AutomateNOWDashboard`

`Pop-AutomateNOWLoadBalancerNode`

`Pop-AutomateNOWResultMappingRule`

`Pop-AutomateNOWServerNodeEndpoint`

`Pop-AutomateNOWServerNodeGroupItem`

`Protect-AutomateNOWEncryptedString`

`Publish-AutomateNOWCodeRepository`

`Push-AutomateNOWApprovalRule`

`Push-AutomateNOWDashboard`

`Push-AutomateNOWLoadBalancerNode`

`Push-AutomateNOWResultMappingRule`

`Push-AutomateNOWServerNodeEndpoint`

`Push-AutomateNOWServerNodeGroupItem`

`Read-AutomateNOWAgentServerNode`

`Read-AutomateNOWBusinessViewItem`

`Read-AutomateNOWCodeRepositoryItem`

`Read-AutomateNOWDashboardPortlet`

`Read-AutomateNOWDataSourceItem`

`Read-AutomateNOWIconSet`

`Read-AutomateNOWNotificationGroupMember`

`Read-AutomateNOWProcessingEventLog`

`Read-AutomateNOWProcessingStateItem`

`Read-AutomateNOWResourceAnomaly`

`Read-AutomateNOWScheduleTemplateItem`

`Read-AutomateNOWSecurityAccessToken`

`Read-AutomateNOWSecurityRoleDomain`

`Read-AutomateNOWSecurityRoleUser`

`Read-AutomateNOWServerNodeAgent`

`Read-AutomateNOWServerNodeEndpoint`

`Read-AutomateNOWServerNodeGroupItem`

`Read-AutomateNOWServiceManagerTemplateDependency`

`Read-AutomateNOWServiceManagerTemplateItem`

`Read-AutomateNOWTimeTrigger`

`Read-AutomateNOWWorkflowTemplateDependency`

`Read-AutomateNOWWorkflowTemplateItem`

`Receive-AutomateNOWCodeRepository`

`Register-AutomateNOWProcessingState`

`Remove-AutomateNOWAdhocReport`

`Remove-AutomateNOWAgent`

`Remove-AutomateNOWAnomaly`

`Remove-AutomateNOWApproval`

`Remove-AutomateNOWApprovalRule`

`Remove-AutomateNOWBusinessView`

`Remove-AutomateNOWBusinessViewItem`

`Remove-AutomateNOWCalendar`

`Remove-AutomateNOWCodeRepository`

`Remove-AutomateNOWCodeRepositoryBranch`

`Remove-AutomateNOWCodeRepositoryItem`

`Remove-AutomateNOWCodeRepositoryTag`

`Remove-AutomateNOWCommunicationNote`

`Remove-AutomateNOWContextVariable`

`Remove-AutomateNOWDashboard`

`Remove-AutomateNOWDashboardPortlet`

`Remove-AutomateNOWDataSource`

`Remove-AutomateNOWDataSourceItem`

`Remove-AutomateNOWDeletedObject`

`Remove-AutomateNOWDesignTemplate`

`Remove-AutomateNOWDomain`

`Remove-AutomateNOWEndpoint`

`Remove-AutomateNOWEvent`

`Remove-AutomateNOWFolder`

`Remove-AutomateNOWLoadBalancerNode`

`Remove-AutomateNOWLock`

`Remove-AutomateNOWMenuCustomization`

`Remove-AutomateNOWMetric`

`Remove-AutomateNOWMigrationImport`

`Remove-AutomateNOWNotification`

`Remove-AutomateNOWNotificationChannel`

`Remove-AutomateNOWNotificationGroup`

`Remove-AutomateNOWNotificationGroupMember`

`Remove-AutomateNOWNotificationMessageTemplate`

`Remove-AutomateNOWPhysicalResource`

`Remove-AutomateNOWProcessingFunction`

`Remove-AutomateNOWProcessingState`

`Remove-AutomateNOWResourceAnomaly`

`Remove-AutomateNOWResultMapping`

`Remove-AutomateNOWResultMappingRule`

`Remove-AutomateNOWRuntimeAction`

`Remove-AutomateNOWSchedule`

`Remove-AutomateNOWScheduleTemplate`

`Remove-AutomateNOWScheduleTemplateItem`

`Remove-AutomateNOWSecretVault`

`Remove-AutomateNOWSecurityAccessToken`

`Remove-AutomateNOWSecurityRole`

`Remove-AutomateNOWSecurityRoleDomain`

`Remove-AutomateNOWSecurityRoleUser`

`Remove-AutomateNOWSecUser`

`Remove-AutomateNOWSemaphore`

`Remove-AutomateNOWServerNode`

`Remove-AutomateNOWServerNodeEndpoint`

`Remove-AutomateNOWServerNodeGroup`

`Remove-AutomateNOWServerNodeGroupItem`

`Remove-AutomateNOWServiceManager`

`Remove-AutomateNOWServiceManagerTemplate`

`Remove-AutomateNOWServiceManagerTemplateDependency`

`Remove-AutomateNOWServiceManagerTemplateItem`

`Remove-AutomateNOWStock`

`Remove-AutomateNOWTag`

`Remove-AutomateNOWTask`

`Remove-AutomateNOWTaskTemplate`

`Remove-AutomateNOWTimeTrigger`

`Remove-AutomateNOWTimeWindow`

`Remove-AutomateNOWUserReport`

`Remove-AutomateNOWVariable`

`Remove-AutomateNOWViewSetup`

`Remove-AutomateNOWWorkflow`

`Remove-AutomateNOWWorkflowTemplate`

`Remove-AutomateNOWWorkflowTemplateDependency`

`Remove-AutomateNOWWorkflowTemplateItem`

`Remove-AutomateNOWWorkspace`

`Rename-AutomateNOWAdhocReport`

`Rename-AutomateNOWAgent`

`Rename-AutomateNOWAnomaly`

`Rename-AutomateNOWApproval`

`Rename-AutomateNOWBusinessView`

`Rename-AutomateNOWCalendar`

`Rename-AutomateNOWDashboard`

`Rename-AutomateNOWDataSource`

`Rename-AutomateNOWDesignTemplate`

`Rename-AutomateNOWDomain`

`Rename-AutomateNOWEndpoint`

`Rename-AutomateNOWEvent`

`Rename-AutomateNOWLock`

`Rename-AutomateNOWMetric`

`Rename-AutomateNOWNotificationChannel`

`Rename-AutomateNOWNotificationGroup`

`Rename-AutomateNOWNotificationMessageTemplate`

`Rename-AutomateNOWPhysicalResource`

`Rename-AutomateNOWProcessingFunction`

`Rename-AutomateNOWResultMapping`

`Rename-AutomateNOWScheduleTemplate`

`Rename-AutomateNOWSecretVault`

`Rename-AutomateNOWSecurityRole`

`Rename-AutomateNOWSemaphore`

`Rename-AutomateNOWServerNode`

`Rename-AutomateNOWServerNodeGroup`

`Rename-AutomateNOWServiceManagerTemplate`

`Rename-AutomateNOWStock`

`Rename-AutomateNOWTaskTemplate`

`Rename-AutomateNOWTimeWindow`

`Rename-AutomateNOWUserReport`

`Rename-AutomateNOWVariable`

`Rename-AutomateNOWViewSetup`

`Rename-AutomateNOWWorkflowTemplate`

`Rename-AutomateNOWWorkspace`

`Reset-AutomateNOWJWTIssuerToken`

`Reset-AutomateNOWWorkflow`

`Resolve-AutomateNOWCodeRepository`

`Resolve-AutomateNOWMonitorType2ServerNodeType`

`Resolve-AutomateNOWObject2TableName`

`Resolve-AutomateNOWSecUserPermission`

`Resolve-AutomateNOWSensorType2ServerNodeType`

`Resolve-AutomateNOWTaskType2ServerNodeType`

`Restart-AutomateNOWSchedule`

`Restart-AutomateNOWServiceManager`

`Restart-AutomateNOWTask`

`Restart-AutomateNOWWorkflow`

`Restore-AutomateNOWDeletedObject`

`Resume-AutomateNOWDomain`

`Resume-AutomateNOWSchedule`

`Resume-AutomateNOWScheduleTemplate`

`Resume-AutomateNOWServerNode`

`Resume-AutomateNOWServiceManager`

`Resume-AutomateNOWServiceManagerTemplate`

`Resume-AutomateNOWTask`

`Resume-AutomateNOWTaskTemplate`

`Resume-AutomateNOWTimeTrigger`

`Resume-AutomateNOWWorkflow`

`Resume-AutomateNOWWorkflowTemplate`

`Save-AutomateNOWAgentSysOutLog`

`Save-AutomateNOWDataSourceItem`

`Save-AutomateNOWDeletedDomain`

`Save-AutomateNOWMigrationImport`

`Search-AutomateNOWSecurityRole`

`Select-AutomateNOWCodeRepositoryBranch`

`Select-AutomateNOWCodeRepositoryTag`

`Send-AutomateNOWAgentConfiguration`

`Send-AutomateNOWCodeRepository`

`Set-AutomateNOWAdhocReport`

`Set-AutomateNOWAgent`

`Set-AutomateNOWAnomaly`

`Set-AutomateNOWApproval`

`Set-AutomateNOWBusinessView`

`Set-AutomateNOWCodeRepository`

`Set-AutomateNOWContextVariable`

`Set-AutomateNOWDashboard`

`Set-AutomateNOWDataSource`

`Set-AutomateNOWDesignTemplate`

`Set-AutomateNOWDomain`

`Set-AutomateNOWEndpoint`

`Set-AutomateNOWEvent`

`Set-AutomateNOWFolder`

`Set-AutomateNOWLock`

`Set-AutomateNOWMetric`

`Set-AutomateNOWNotificationChannel`

`Set-AutomateNOWNotificationGroup`

`Set-AutomateNOWNotificationGroupMember`

`Set-AutomateNOWNotificationMessageTemplate`

`Set-AutomateNOWPhysicalResource`

`Set-AutomateNOWProcessingFunction`

`Set-AutomateNOWRuntimeAction`

`Set-AutomateNOWScheduleTemplate`

`Set-AutomateNOWScheduleTemplateItem`

`Set-AutomateNOWSecretVault`

`Set-AutomateNOWSecretVaultDefault`

`Set-AutomateNOWSecurityRole`

`Set-AutomateNOWSecurityRoleDomain`

`Set-AutomateNOWSecUser`

`Set-AutomateNOWSecUserPassword`

`Set-AutomateNOWSemaphore`

`Set-AutomateNOWSemaphoreTimestamp`

`Set-AutomateNOWServerNode`

`Set-AutomateNOWServerNodeEndpoint`

`Set-AutomateNOWServerNodeGroup`

`Set-AutomateNOWServiceManagerTemplate`

`Set-AutomateNOWServiceManagerTemplateItem`

`Set-AutomateNOWStock`

`Set-AutomateNOWTag`

`Set-AutomateNOWTaskTemplate`

`Set-AutomateNOWTimeTrigger`

`Set-AutomateNOWTimeWindow`

`Set-AutomateNOWUserReport`

`Set-AutomateNOWVariable`

`Set-AutomateNOWVariableTimestamp`

`Set-AutomateNOWViewSetup`

`Set-AutomateNOWWorkflowTemplate`

`Set-AutomateNOWWorkflowTemplateItem`

`Set-AutomateNOWWorkspace`

`Show-AutomateNOWCodeRepositoryConflictItemComparison`

`Show-AutomateNOWCollaborationWall`

`Show-AutomateNOWEndpointType`

`Show-AutomateNOWTaskTemplateType`

`Skip-AutomateNOWSchedule`

`Skip-AutomateNOWScheduleTemplate`

`Skip-AutomateNOWServerNode`

`Skip-AutomateNOWServiceManager`

`Skip-AutomateNOWServiceManagerTemplate`

`Skip-AutomateNOWTask`

`Skip-AutomateNOWTaskTemplate`

`Skip-AutomateNOWTimeTrigger`

`Skip-AutomateNOWWorkflow`

`Skip-AutomateNOWWorkflowTemplate`

`Start-AutomateNOWEvent`

`Start-AutomateNOWScheduleTemplate`

`Start-AutomateNOWServerNode`

`Start-AutomateNOWServiceManagerTemplate`

`Start-AutomateNOWTaskTemplate`

`Start-AutomateNOWWorkflowTemplate`

`Stop-AutomateNOWSchedule`

`Stop-AutomateNOWServerNode`

`Stop-AutomateNOWServiceManager`

`Stop-AutomateNOWTask`

`Stop-AutomateNOWWorkflow`

`Suspend-AutomateNOWDomain`

`Suspend-AutomateNOWSchedule`

`Suspend-AutomateNOWScheduleTemplate`

`Suspend-AutomateNOWServerNode`

`Suspend-AutomateNOWServiceManager`

`Suspend-AutomateNOWServiceManagerTemplate`

`Suspend-AutomateNOWTask`

`Suspend-AutomateNOWTaskTemplate`

`Suspend-AutomateNOWTimeTrigger`

`Suspend-AutomateNOWWorkflow`

`Suspend-AutomateNOWWorkflowTemplate`

`Switch-AutomateNOWDomain`

`Sync-AutomateNOWCodeRepository`

`Sync-AutomateNOWDomainResource`

`Sync-AutomateNOWDomainServerNode`

`Test-AutomateNOWSecretVault`

`Test-AutomateNOWSecUserPassword`

`Trace-AutomateNOWProcessing`

`Unlock-AutomateNOWSecUser`

`Unprotect-AutomateNOWEncryptedString`

`Unpublish-AutomateNOWCodeRepository`

`Unregister-AutomateNOWProcessingState`

`Update-AutomateNOWCodeRepositoryObjectSource`

`Update-AutomateNOWCommunicationNote`

`Update-AutomateNOWSchedule`

`Update-AutomateNOWServiceManager`

`Update-AutomateNOWTask`

`Update-AutomateNOWToken`

`Update-AutomateNOWWorkflow`

`Update-AutomateNOWWorkflowLazyItem`

`Wait-AutomateNOWProcessing`

`Write-AutomateNOWIconData`

`Write-AutomateNOWObjectVersion`
