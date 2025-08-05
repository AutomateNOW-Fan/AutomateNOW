## 1.0.30
- Bump compatibility to _ANOW version 3.3.1.84_
- Added new functions: `Add-AutomateNOWBusinessViewItem`, `Copy-AutomateNOWBusinessView`, `Export-AutomateNOWBusinessView`, `Export-AutomateNOWSecurityEventLog`, `Get-AutomateNOWBusinessView`, `Get-AutomateNOWSecurityEventLog`, `New-AutomateNOWBusinessView`, `Read-AutomateNOWBusinessViewItem`, `Remove-AutomateNOWBusinessView`, `Remove-AutomateNOWBusinessViewItem`, `Rename-AutomateNOWBusinessView`, `Resolve-AutomateNOWEndpoinType2JavaScriptDefinition`, `Set-AutomateNOWBusinessView`
- Added preliminary functionality for securely setting endpoint credentials via `Set-AutomateNOWEndpoint` 🥳
- Renamed the `AutomateNOWNode` functions to `AutomateNOWServerNode`
- Renamed the `-Pass` parameter to `-String` in `Protect-AutomateNOWString`
- Added the `-SecureString` parameter to `Protect-AutomateNOWString`
- Added the `-ForceCommit` parameter to `Publish-AutomateNOWCodeRepository`
- Added the domain class 'DataSource' to `Get-AutomateNOWCodeRepositoryObjectSource` (this means it is now possible to edit the source code of a DataSource 👍)
- Fixed an issue with `Connect-AutomateNOW` where the default domain (if configured for that user) was still used in the connection even if a different domain had been specified via the `-Domain` parameter (workaround: use `Switch-AutomateNOWDomain` after logging in)
- Fixed an issue with `Connect-AutomateNOW` and non-API users whose 'accountValidUntil' date is not configured
- Fixed an issue with `Connect-AutomateNOW` when using `-access_token` without including the `-refresh_token`
- Fixed the error message on all `New-*` functions when receiving a non-zero response from the API
- Fixed an issue with the response object from `Add-AutomateNOWDataSourceItem`
- Fixed an issue with `Add-AutomateNOWCodeRepositoryItem` where the datasource property was wrong for some of the object classes

## 1.0.29
- Bump compatibility to _ANOW version 3.3.1.83 HF0_
- Added new function: `Set-AutomateNOWTimeTrigger`
- Added support for default domain to `Connect-AutomateNOWUser`
- Improved the parameters for `Get-AutomateNOWTimeTrigger`
- Fixed the empty name in the `-Force` confirmation prompt for many functions during pipeline processing
- Fixed an issue with `Get-AutomateNOWWorkflow` when receiving Id's from the pipeline
- Fixed the `-WorkflowType` parameter on `New-AutomateNOWWorkflowTemplate`
- Fixed an issue where `Get-AutomateNOWContextVariable` would accept an empty collection of RunId's
- Fixed an issue with `Get-AutomateNOWTimeTrigger` whenever receiving multiple Schedule Templates during pipeline processing
- Fixed the parameters for `Get-AutomateNOWTask` to allow `-startRow` and `-endRow` parameters when filtering by Task Template
- Fixed the parameters for `Get-AutomateNOWSchedule` to allow `-startRow` and `-endRow` parameters when filtering by Schedule Template

## 1.0.28
- Fixed for PowerShell Gallery

## 1.0.27
- Added new functions: `Copy-AutomateNOWNotificationMessageTemplate`, `Export-AutomateNOWNotificationMessageTemplate`, `Export-AutomateNOWSemaphoreTimestamp`, `Export-AutomateNOWVariableTimestamp`, `Get-AutomateNOWNotificationMessageTemplate`, `New-AutomateNOWNotificationMessageTemplate`, `Remove-AutomateNOWNotificationMessageTemplate`, `Rename-AutomateNOWNotificationMessageTemplate`, `Resume-AutomateNOWTimeTrigger`, `Set-AutomateNOWNotificationMessageTemplate`, `Skip-AutomateNOWTimeTrigger`, `Suspend-AutomateNOWTimeTrigger`
- Fixed a major compatibly issue with Windows PowerShell and authentication functions (PowerShell Core was not affected)
- Fixed some issues with `Add-AutomateNOWNotificationGroupMember`
- Fixed an issue with `New-AutomateNOWTaskTemplate`
- Fixed `New-AutomateNOWTag` to no longer require an icon code & library
- Enforced `Set-AutomateNOWPassword` to accept only secure strings for passwords
- Enforced `Test-AutomateNOWPassword` to accept only secure strings for passwords
- Enforced the Skip functions to always confirm that the object doesn't already have skip set
- Updated and fixed some aspects of the Remove functions
- Updated and fixed some issues with `Add-AutomateNOWScheduleTemplateItem`, `Add-AutomateNOWWorkflowTemplateItem`, `Read-AutomateNOWScheduleTemplateItem`, `Read-AutomateNOWWorkflowTemplateItem`
- Renamed the `-template` parameter on `Get-AutomateNOWWorkflow` to `-WorkflowTemplate` to allow filtering by template
- Added the `-TaskTemplate` parameter to `Get-AutomateNOWTask` to allow filtering by template
- Added the `-ScheduleTemplate` parameter to `Get-AutomateNOWSchedule` to allow filtering by template
- Renamed `Set-AutomateNOWPassword` to `Set-AutomateNOWUserPassword`
- Updated `Show-AutomateNOWEndpointType`
- Updated the built-in help for `Connect-AutomateNOW`
- Downgraded `New-AutomateNOWUser` to experimental status

## 1.0.26
- Bump compatibility to _ANOW version 3.3.1.81 HF0_
- Added new functions: `Add-AutomateNOWNotificationGroupMember`, `Copy-AutomateNOWNotificationChannel`, `Copy-AutomateNOWNotificationGroup`, `Export-AutomateNOWNotificationChannel`, `Export-AutomateNOWNotificationGroupMember`, `Export-AutomateNOWNotificationGroup`, `Export-AutomateNOWNotification`, `Get-AutomateNOWNotificationChannel`, `Get-AutomateNOWNotificationGroupMember`, `Get-AutomateNOWNotificationGroup`, `Get-AutomateNOWNotification`, `New-AutomateNOWNotificationChannel`, `New-AutomateNOWNotificationGroup`, `Remove-AutomateNOWNotificationChannel`, `Remove-AutomateNOWNotificationGroupMember`, `Remove-AutomateNOWNotificationGroup`, `Remove-AutomateNOWNotification`, `Remove-AutomateNOWWorkflowTemplateItem`, `Rename-AutomateNOWNotificationChannel`, `Rename-AutomateNOWNotificationGroup`, `Set-AutomateNOWNotificationChannel`, `Set-AutomateNOWNotificationGroupMember`, `Set-AutomateNOWNotificationGroup`
- Removed function: `Set-AutomateNOWTask`
- Restored missing class property _delayedStartTime_ which impacted `Read-AutomateNOWScheduleTemplateItem` and `Read-AutomateNOWWorkflowTemplateItem`
- Fixed pipeline capability with `Read-AutomateNOWScheduleTemplateItem` and `Read-AutomateNOWWorkflowTemplateItem`
- Fixed an issue with `Get-AutomateNOWContextVariable`
- Repaired the `-Folder` and `-Tags` parameters on `Start-AutomateNOWScheduleTemplate`
- Fixed an issue with `Connect-AutomateNOW` that only manifested if `-User` was used without `-Pass`
- Enforced `Connect-AutomateNOW` to accept only secure strings for passwords
- Ensured that all functions stop 🛑 whenever a non-zero status from the ANOW API is received
- Added the `-Force` parameter to `Edit-AutomateNOWCodeRepositoryObjectSource`
- Added the `-VerboseMode` parameter to `Set-AutomateNOWTaskTemplate` and `Set-AutomateNOWWorkflowTemplate`
- Added the `-InactiveUsers` parameter to `Get-AutomateNOWUser` (Experimental 🧪)
- Added the `-TaskTemplateId` parameter to `Start-AutomateNOWTaskTemplate` (allows specifying the Task Template by name instead of object)
- Added the `-ScheduleTemplateId` parameter to `Start-AutomateNOWScheduleTemplate` (allows specifying the Schedule Template by name instead of object)
- Added the `-WorkflowTemplateId` parameter to `Start-AutomateNOWWorkflowTemplate` (allows specifying the Workflow Template by name instead of object)
- Updated Icons.ps1

## 1.0.25
- Added new functions: `Copy-AutomateNOWEvent`, `Copy-AutomateNOWMetric`, `Copy-AutomateNOWPhysicalResource`, `Export-AutomateNOWCodeRepositoryObjectSource`, `Export-AutomateNOWEvent`, `Export-AutomateNOWMetric`, `Export-AutomateNOWPhysicalResource`, `Get-AutomateNOWEvent`, `Get-AutomateNOWMetric`, `Get-AutomateNOWPhysicalResource`, `New-AutomateNOWEvent`, `New-AutomateNOWMetric`, `New-AutomateNOWPhysicalResource`, `Pop-AutomateNOWLoadBalancerNode`, `Push-AutomateNOWLoadBalancerNode`, `Remove-AutomateNOWEvent`, `Remove-AutomateNOWMetric`, `Remove-AutomateNOWPhysicalResource`, `Rename-AutomateNOWEvent`, `Rename-AutomateNOWMetric`, `Rename-AutomateNOWPhysicalResource`, `Set-AutomateNOWEvent`, `Set-AutomateNOWMetric`, `Set-AutomateNOWPhysicalResource`
- Optimized the classes and enums reducing the Classes.psm1 file by 33% 😲
- Fixed a typo in `Set-AutomateNOWTaskTemplate` (occurred when setting the Node)

## 1.0.24
- Added new functions: `Get-AutomateNOWCodeRepositoryObjectSource`, `Edit-AutomateNOWCodeRepositoryObjectSource`, `Update-AutomateNOWCodeRepositoryObjectSource`
- Added the `-template` parameter to `Get-AutomateNOWWorkflow`
- Added the `-folder` parameter to `Get-AutomateNOWTaskTemplate`

## 1.0.23
- Bump compatibility to _ANOW version 3.3.1.80 HF0_
- Added new functions: `Dismount-AutomateNOWNode`, `Export-AutomateNOWContextVariable`, `Export-AutomateNOWProcessingEventLog`, `Get-AutomateNOWContextVariable`, `Get-AutomateNOWProcessingEventLog`, `Rename-AutomateNOWAdhocReport`, `Rename-AutomateNOWAgent`, `Rename-AutomateNOWApproval`, `Rename-AutomateNOWDataSource`, `Rename-AutomateNOWNode`, `Resume-AutomateNOWNode`, `Skip-AutomateNOWNode`, `Suspend-AutomateNOWNode`
- Added the `-defaultDomain` parameter to `Set-AutomateNOWUser`
- Added support for "Sensor", "Monitor" and "Service Manager" Task types in `New-AutomateNOWTaskTemplate`
- Fixed an issue with `Stop-AutomateNOWNode` and promoted it to high impact and added the `-Force` parameter
- Fixed a fatal typo within `New-AutomateNOWNode`
- Fixed multiple issues in `Get-AutomateNOWWorkflow`
- Improved the warning from `Connect-AutomateNOW` when the existing session has expired
- Removed experimental status from `Write-AutomateNOWIconData`
- Removed references to WorkSpaces in all functions except for `New-AutomateNOWTaskTemplate` and `New-AutomateNOWWorkflowTemplate`

## 1.0.22
- Bump compatibility to _ANOW version 3.3.1.79 HF2_
- Added new functions: `Clear-AutomateNOWDomain`, `Copy-AutomateNOWDomain`, `Copy-AutomateNOWWorkspace`, `New-AutomateNOWDomain`, `Remove-AutomateNOWDomain`, `Rename-AutomateNOWCalendar`, `Rename-AutomateNOWDomain`, `Rename-AutomateNOWEndpoint`, `Rename-AutomateNOWResultMapping`, `Rename-AutomateNOWSemaphore`, `Rename-AutomateNOWWorkspace`, `Resolve-AutomateNOWMonitorType2ServerNodeType`, `Resolve-AutomateNOWSensorType2ServerNodeType`, `Resume-AutomateNOWDomain`, `Set-AutomateNOWDomain`, `Suspend-AutomateNOWDomain`, `Sync-AutomateNOWDomainResource`, `Sync-AutomateNOWDomainServerNode`
- Removed functions: `Add-AutomateNOWProcessingTimeTrigger`, `Copy-AutomateNOWUser`
- Fixed a parameter issue with `Start-AutomateNOWWorkflowTemplate` around the naming of the executed Workflow
- Added automatic recognition for API users (see APIUser in the $anow_session variable)
- Added support for 10 digit expiration dates to `Connect-AutomateNOW`
- Added High Impact status and the `-Force` parameter to all Copy-* and Add-* functions.
- Added the `-Quiet` parameter to all Copy-AutomateNOW* functions.
- Improved how `Invoke-AutomateNOWAPI` handles binary payloads.
- Renamed the ProcessingTimeTrigger functions to TimeTrigger
- Added small improvements to `Get-AutomateNOWTimeTrigger`

## 1.0.21
- Added new functions: `Add-AutomateNOWCodeRepositoryItem`,  `Approve-AutomateNOWCodeRepositoryMergeRequest`,  `Compare-AutomateNOWCodeRepositoryOutOfSyncItem`,  `Confirm-AutomateNOWCodeRepository`,  `Deny-AutomateNOWCodeRepositoryMergeRequest`,  `Get-AutomateNOWCodeRepositoryBranch`,  `Get-AutomateNOWCodeRepositoryItem`,  `Get-AutomateNOWCodeRepositoryMergeRequest`,  `Get-AutomateNOWCodeRepositoryOutOfSyncItem`,  `Get-AutomateNOWCodeRepositoryTag`,  `Merge-AutomateNOWCodeRepositoryBranch`,  `Merge-AutomateNOWCodeRepositoryOutOfSyncItem`,  `New-AutomateNOWCodeRepository`,  `New-AutomateNOWCodeRepositoryBranch`,  `New-AutomateNOWCodeRepositoryTag`,  `Publish-AutomateNOWCodeRepository`,  `Receive-AutomateNOWCodeRepository`,  `Remove-AutomateNOWCodeRepository`,  `Remove-AutomateNOWCodeRepositoryBranch`,  `Remove-AutomateNOWCodeRepositoryItem`,  `Remove-AutomateNOWCodeRepositoryTag`,  `Remove-AutomateNOWScheduleTemplateItem`,  `Select-AutomateNOWCodeRepositoryBranch`,  `Select-AutomateNOWCodeRepositoryTag`,  `Send-AutomateNOWCodeRepository`,  `Set-AutomateNOWCodeRepository`,  `Set-AutomateNOWTask`,  `Show-AutomateNOWCodeRepositoryOutOfSyncItemComparison`,  `Sync-AutomateNOWCodeRepository`,  `UnPublish-AutomateNOWCodeRepository`
- Added complete functionality with Git Repositories. `Show-AutomateNOWCodeRepositoryOutOfSyncItemComparison` requires the git executable to be available.
- Added `-processingCommand` parameter to `Set-AutomateNOWTaskTemplate` allowing changes to the script within the Task Template (experimental)
- Fixed an issue with case-sensitivity when adding Tags to an object
- Improved `Set-AutomateNOWTaskTemplate` by making the boolean parameters nullable

## 1.0.20
- Added new functions: `Add-AutomateNOWScheduleTemplateItem`, `Confirm-AutomateNOWScheduleTemplate`, `Copy-AutomateNOWTimeWindow`, `Export-AutomateNOWTimeWindow`, `Get-AutomateNOWTimeWindow`, `New-AutomateNOWTimeWindow`, `Read-AutomateNOWScheduleTemplateItem`, `Remove-AutomateNOWTimeWindow`, `Rename-AutomateNOWTimeWindow`, `Set-AutomateNOWTimeWindow`
- Fixed a (rare) issue with `Invoke-AutomateNOWAPI` and JSON deserialization (note that MaxJsonLength is set to 2,147,483,647 instead of the default 2,097,152)
- Added parameter `-serverNodeType` along with other minor improvements to `Get-AutomateNOWNode`
- Added parameter `-Quiet` to `Set-AutomateNOWTaskTemplate` and `Set-AutomateNOWWorkflowTemplate`
- Added parameter `-Parameters` to `Start-AutomateNOWTaskTemplate`, `Start-AutomateNOWWorkflowTemplate`, `Start-AutomateNOWScheduleTemplate`. This makes it finally possible to execute Processing Templates with parameters!
- Extended support for adding Processing Template Items to Workflow Templates & Schedule Templates
- Added the ability to modify the tags, folder and code repository to `Set-AutomateNOWDataSource`

## 1.0.19
- Added new functions: `Add-AutomateNOWWorkflowTemplateItem` `Copy-AutomateNOWLock` `Copy-AutomateNOWStock` `Copy-AutomateNOWVariable` `Export-AutomateNOWLock` `Export-AutomateNOWStock` `Export-AutomateNOWVariable` `Get-AutomateNOWLock` `Get-AutomateNOWStock` `Get-AutomateNOWVariable` `Get-AutomateNOWVariableTimestamp` `New-AutomateNOWLock` `New-AutomateNOWStock` `New-AutomateNOWVariable` `Read-AutomateNOWWorkflowTemplateItem` `Remove-AutomateNOWLock` `Remove-AutomateNOWStock` `Remove-AutomateNOWVariable` `Rename-AutomateNOWLock` `Rename-AutomateNOWStock`, `Rename-AutomateNOWVariable`, `Set-AutomateNOWLock`, `Set-AutomateNOWStock`, `Set-AutomateNOWVariable`, `Set-AutomateNOWVariableTimestamp`
- Fixed an issue with `Get-AutomateNOWTask` when using the `-Id` parameter
- Added a new parameter `-ChildNodes` to `Get-AutomateNOWNode`, some other parameters were renamed as well
- Added preliminary support for adding Task Templates to Workflow Templates by way of `Add-AutomateNOWWorkflowTemplateItem`
- Enhanced the password validity checking of `Set-AutomateNOWPassword` by way of `Test-AutomateNOWPassword`
- Enhanced the output of `Invoke-AutomateNOWAPI` when JSON conversion errors occur (workaround: use `-JustGiveMeJSON`)

## 1.0.18
- Added new functions: `Copy-AutomateNOWNode`, `Copy-AutomateNOWResultMapping`, `Copy-AutomateNOWUser`, `Get-AutomateNOWSemaphoreTimestamp`, `New-AutomateNOWServerDayTimestamp`, `New-AutomateNOWUser`, `Remove-AutomateNOWUser`, `Set-AutomateNOWSemaphoreTimestamp`, `Test-AutomateNOWUserPassword`

## 1.0.17
- Bump compatibility to _ANOW version 3.3.1.78 HF2_
- Added new functions: `Add-AutomateNOWProcessingTimeTrigger`, `Copy-AutomateNOWAdhocReport`, `Copy-AutomateNOWAgent`, `Copy-AutomateNOWCalendar`, `Copy-AutomateNOWScheduleTemplate`, `Copy-AutomateNOWSemaphore`, `Export-AutomateNOWAdhocReport`, `Export-AutomateNOWAgent`, `Export-AutomateNOWProcessingTimeTrigger`, `Export-AutomateNOWSchedule`, `Export-AutomateNOWScheduleTemplate`, `Export-AutomateNOWSemaphore`, `Get-AutomateNOWAdhocReport`, `Get-AutomateNOWAgent`, `Get-AutomateNOWProcessingTimeTrigger`, `Get-AutomateNOWSchedule`, `Get-AutomateNOWScheduleTemplate`, `Get-AutomateNOWSemaphore`, `Import-AutomateNOWLocalTimeZone`, `Invoke-AutomateNOWAdhocReport`, `New-AutomateNOWAdhocReport`, `New-AutomateNOWAgent`, `New-AutomateNOWScheduleTemplate`, `New-AutomateNOWSemaphore`, `Remove-AutomateNOWAdhocReport`, `Remove-AutomateNOWAgent`, `Remove-AutomateNOWProcessingTimeTrigger`, `Remove-AutomateNOWSchedule`, `Remove-AutomateNOWScheduleTemplate`, `Remove-AutomateNOWSemaphore`, `Rename-AutomateNOWScheduleTemplate`, `Restart-AutomateNOWSchedule`, `Resume-AutomateNOWSchedule`, `Resume-AutomateNOWScheduleTemplate`, `Set-AutomateNOWAdhocReport`, `Set-AutomateNOWAgent`, `Set-AutomateNOWScheduleTemplate`, `Set-AutomateNOWSemaphore`, `Skip-AutomateNOWSchedule`, `Skip-AutomateNOWScheduleTemplate`, `Start-AutomateNOWScheduleTemplate`, `Stop-AutomateNOWSchedule`, `Suspend-AutomateNOWSchedule`, `Suspend-AutomateNOWScheduleTemplate`
- Added new filtering parameter -processingStatus to `Get-AutomateNOWTask` and `Get-AutomateNOWWorkflow`
- Added new filtering parameter -Tags to `Get-AutomateNOWTaskTemplate`
- Fixed an issue with `Get-AutomateNOWDomain` and domains that have a logo png applied
- Renamed `Protect-AutomateNOWAuthenticationString` to `Protect-AutomateNOWEncryptedString`

## 1.0.16
- Bump compatibility to _ANOW version 3.3.1.76 HF2_
- Added new functions: `Copy-AutomateNOWDataSource`
- Added preliminary support for the new Notes feature
- Added experimental parameter `-All` to `Get-AutomateNOWDataSourceItem`
- Fixed an issue with `Get-AutomateNOWUser` and parsing the domain roles of the root admin account
- Minor improvements to `Disconnect-AutomateNOW`
- Minor improvements to `Connect-AutomateNOW`

## 1.0.15
- Added new functions: `Add-AutomateNOWApprovalRule`, `Copy-AutomateNOWApproval`, `Copy-AutomateNOWEndpoint`, `Export-AutomateNOWApproval`, `Export-AutomateNOWCalendar`, `Export-AutomateNOWEndpoint`, `Get-AutomateNOWApproval`, `Get-AutomateNOWCalendar`, `Get-AutomateNOWEndpoint`, `New-AutomateNOWApproval`, `New-AutomateNOWApprovalRule`, `New-AutomateNOWCalendar`, `New-AutomateNOWEndpoint`, `Remove-AutomateNOWApproval`, `Remove-AutomateNOWCalendar`, `Remove-AutomateNOWEndpoint`, `Set-AutomateNOWApproval`, `Set-AutomateNOWEndpoint`, `Set-AutomateNOWWorkflowTemplate`, `Show-AutomateNOWEndpointType`, `Unprotect-AutomateNOWEncryptedString`
- Fixed an issue for PowerShell 7 that could prevent the classes.psm1 from loading
- Fixed an issue with Daylight Saving Time that impacted `Connect-AutomateNOW`
- Fixed an issue with the `-ReadJSONFromClipboard` parameter of `Connect-AutomateNOW`
- Aligned some parameter names throughout the Set-* functions
- Added -Quiet parameter to all of the New-* functions
- Added 2 new parameters `-LoadBalancersOnly`, `-ChildNodesOnly` to `Get-AutomateNOWNode`
- `Connect-AutomateNOW` now enforces that the domain supplied on the -Domain parameter must actually exist
- `Connect-AutomateNOW` now halts when the -Domain parameter is not supplied but it will display the available domains
- `Get-AutomateNOWTaskTemplate` no longer retrieves a named processing item that is actually a workflow
- `Get-AutomateNOWWorkflowTemplate` no longer retrieves a named processing item that is actually a task
- `Set-AutomateNOWWorkflowTemplate` has support for most of the settings in the Attributes tab. It can also move Workflow Templates into and out of Workspaces.
- `New-AutomateNOWAuthenticationEncryptedString` was renamed to `Protect-AutomateNOWAuthenticationString`

## 1.0.14
- Bump compatibility to _ANOW version 3.3.1.75 HF3_
- Added new functions: `Add-AutomateNOWResultMappingRule` `Export-AutomateNOWResultMapping` `Get-AutomateNOWResultMapping` `New-AutomateNOWResultMapping` `New-AutomateNOWResultMappingRule` `New-AutomateNOWResultMappingRuleCondition` `New-AutomateNOWResultMappingRuleConditionCriteria` `Remove-AutomateNOWResultMapping` `Remove-AutomateNOWTask` `Remove-AutomateNOWWorkflow` `Restart-AutomateNOWTask` `Restart-AutomateNOWWorkflow` `Resume-AutomateNOWTask` `Resume-AutomateNOWWorkflow` `Set-AutomateNOWDataSource` `Set-AutomateNOWTaskTemplate` `Skip-AutomateNOWTask` `Skip-AutomateNOWWorkflow` `Stop-AutomateNOWTask` `Stop-AutomateNOWWorkflow` `Suspend-AutomateNOWTask` `Suspend-AutomateNOWWorkflow`
- Fixed an issue with JSON depth and `Get-AutomateNOWAuditlog`
- `New-AutomateNOWTaskTemplate` will now differentiate between Internal Tasks, Service Manager Tasks and Standard Tasks
- `Set-AutomateNOWWorkspace` has support for all of the settings in the Attributes tab
- `Set-AutomateNOWTaskTemplate` has support for most of the settings in the Attributes tab. It can also move Task Templates into and out of Workspaces.

## 1.0.13
- Fixed an issue with `Connect-AutomateNOW`
- Fixed an issue with `Get-AutomateNOWUser`

## 1.0.12
- Added new functions: `Export-AutomateNOWAuditLog`, `Get-AutomateNOWAuditLog`, `Set-AutomateNOWUser`
- Aligned `Get-AutomateNOWWorkspace` with the other Get-* functions
- Updated and fixed the help examples for many functions
- `Get-AutomateNOWDomain` is now capable of retrieving a single domain
- `Get-AutomateNOWUser` is now capable of retrieving all users (if permissions exist)

## 1.0.11
- Bump compatibility to _ANOW version 3.3.1.75 HF1_
- Added new functions: `Confirm-AutomateNOWTaskTemplate`, `Confirm-AutomateNOWWorkflowTemplate`, `Copy-AutomateNOWTaskTemplate`, `Export-AutomateNOWCodeRepository`, `Get-AutomateNOWCodeRepository`, `Rename-AutomateNOWTaskTemplate`, `Resolve-AutomateNOWTaskType2ServerNodeType`,`Resume-AutomateNOWTaskTemplate`, `Resume-AutomateNOWWorkflowTemplate`, `Skip-AutomateNOWTaskTemplate`, `Skip-AutomateNOWWorkflowTemplate`, `Start-AutomateNOWNode`, `Start-AutomateNOWTaskTemplate`, `Start-AutomateNOWWorkflowTemplate`, `Stop-AutomateNOWNode`, `Suspend-AutomateNOWTaskTemplate`, `Suspend-AutomateNOWWorkflowTemplate`
- Improved the global session variable to use class objects (e.g. [ANOWTimeZone], [ANOWUser])
- Enhanced the `Get-AutomatenowUser` function to fetch the full user details. If you don't know the username (e.g. using an access token) then use the -LoggedOnUser parameter.
- Decorated the [ANOWUser] object with [ANOWDomainRole] and [ANOWSecurityRole] class objects
- Fixed an issue where error messages returned from the API were not always reflected back
- Enforced on most functions that tags, folders, code repositories and workspaces must actually exist before trying to add them to an object
- Lowered the default endRow from 2000 to 100
- Enforced that the endRow must be greater than the startRow
- Fixed an issue with `Get-AutomateNOWTag` when the same tag name occurs across multiple domains
- Enforced that the server node type supplied to `New-AutomateNOWTaskTemplate` must match the task type
- Completed renaming the *Task* functions to *TaskTemplate*. All Task/Workflow functions have been aligned and optimized.

## 1.0.10
- Added new functions: `Add-AutomateNOWDataSourceItem`, `Copy-AutomateNOWWorkflowTemplate`, `Export-AutomateNOWDataSource`, `Export-AutomateNOWDataSourceItem`, `Export-AutomateNOWWorkspace`, `Find-AutomateNOWObjectReferral`, `Get-AutomateNOWDataSource`, `Get-AutomateNOWDataSourceItem`, `Get-AutomateNOWWorkspace`, `New-AutomateNOWDataSource`, `New-AutomateNOWWorkspace`, `Remove-AutomateNOWDataSource`, `Remove-AutomateNOWDataSourceItem`, `Remove-AutomateNOWWorkspace`, `Resume-AutomateNOWTask`, `Set-AutomateNOWFolder`, `Set-AutomateNOWTag`, `Set-AutomateNOWWorkspace`, `Show-AutomateNOWTaskType`
- Organized the classes into "base" and "sub" classes in line with best practices (changes to classes and enums will no longer be listed in this change log)
- Added method CreateOldValues() to ANOW base class. It is imperative that this method will always precisely match what the console expects. This method is intended for use with the Set-* functions.
- Removed a check that is no longer needed from the Remove-* functions
- Fixed an issue with the default constructor on some classes
- Renamed the *Task* and *Workflow* functions to *TaskTemplate* and *WorkflowTemplate* since that's what they actually were
- Added automation mime type detection (ASCII vs. UTF-8) when uploading text files to a Data Source (the console does not do this)

### 1.0.9
- Added new functions: `Export-AutomateNOWDomain`, `Export-AutomateNOWIcon`, `Export-AutomateNOWNode`, `Export-AutomateNOWTag`, `Export-AutomateNOWTask`, `Export-AutomateNOWTimeZone`, `Export-AutomateNOWUser`, `Export-AutomateNOWWorkflow`, `Get-AutomateNOWTimeZone`, `Import-AutomateNOWLocalIcon`, `Import-AutomateNOWTimeZone`, `New-AutomateNOWNode`, `Read-AutomateNOWIcon`, `Remove-AutomateNOWNode`, `Write-AutomateNOWIconData`
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
- Bump compatibility to _ANOW version 3.3.1.75 HF0_
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
- Compatibile with _ANOW version 3.2.1.69_
