<#	

Developed and tested against AutomateNOW! version 3.3.1.84

#>
@{	
	# Author of this module
	Author                 = 'AutomateNOW-Fan'

	# Script module or binary module file associated with this manifest
	RootModule             = 'AutomateNOW.psm1'
	
	# Version number of this module.
	ModuleVersion          = '1.0.31'
	
	# ID used to uniquely identify this module
	GUID                   = 'dbb2b435-ba69-4fae-9bb0-8494816c382b'
	
	# Copyright statement for this module
	Copyright              = 'not affiliated with Beta Systems'
	
	# Description of the functionality provided by this module
	Description            = 'Interact with the API of an AutomateNOW! instance'
	
	# Minimum version of the Windows PowerShell engine required by this module
	PowerShellVersion      = '5.1'
	
	# Name of the Windows PowerShell host required by this module
	PowerShellHostName     = ''
	
	# Minimum version of the Windows PowerShell host required by this module
	PowerShellHostVersion  = ''
	
	# Minimum version of the .NET Framework required by this module
	DotNetFrameworkVersion = ''
	
	# Minimum version of the common language runtime (CLR) required by this module
	CLRVersion             = ''
	
	# Processor architecture (None, X86, Amd64, IA64) required by this module
	ProcessorArchitecture  = 'None'
	
	# Modules that must be imported into the global environment prior to importing
	# this module
	RequiredModules        = @()
	
	# Assemblies that must be loaded prior to importing this module
	RequiredAssemblies     = @()
	
	# Script files (.ps1) that are run in the caller's environment prior to
	# importing this module
	ScriptsToProcess       = @()
	
	# Type files (.ps1xml) to be loaded when importing this module
	TypesToProcess         = @()
	
	# Format files (.ps1xml) to be loaded when importing this module
	FormatsToProcess       = @()
	
	# Modules to import as nested modules of the module specified in
	# ModuleToProcess
	NestedModules          = @()
	
	# Functions to export from this module
	FunctionsToExport      = @('Add-AutomateNOWApprovalRule', 'Add-AutomateNOWBusinessViewItem', 'Add-AutomateNOWCodeRepositoryItem', 'Add-AutomateNOWDataSourceItem', 'Add-AutomateNOWNotificationGroupMember', 'Add-AutomateNOWResultMappingRule', 'Add-AutomateNOWScheduleTemplateItem', 'Add-AutomateNOWServerNodeEndpoint', 'Add-AutomateNOWServiceManagerTemplateItem', 'Add-AutomateNOWTimeTrigger', 'Add-AutomateNOWWorkflowTemplateItem', 'Approve-AutomateNOWCodeRepositoryMergeRequest', 'Clear-AutomateNOWDomain', 'Compare-AutomateNOWCodeRepositoryConflictItem', 'Confirm-AutomateNOWCodeRepository', 'Confirm-AutomateNOWScheduleTemplate', 'Confirm-AutomateNOWServiceManagerTemplate', 'Confirm-AutomateNOWSession', 'Confirm-AutomateNOWTaskTemplate', 'Confirm-AutomateNOWWorkflowTemplate', 'Connect-AutomateNOW', 'Copy-AutomateNOWAdhocReport', 'Copy-AutomateNOWAgent', 'Copy-AutomateNOWApproval', 'Copy-AutomateNOWBusinessView', 'Copy-AutomateNOWCalendar', 'Copy-AutomateNOWDataSource', 'Copy-AutomateNOWDomain', 'Copy-AutomateNOWEndpoint', 'Copy-AutomateNOWEvent', 'Copy-AutomateNOWLock', 'Copy-AutomateNOWMetric', 'Copy-AutomateNOWNotificationChannel', 'Copy-AutomateNOWNotificationGroup', 'Copy-AutomateNOWNotificationMessageTemplate', 'Copy-AutomateNOWPhysicalResource', 'Copy-AutomateNOWResultMapping', 'Copy-AutomateNOWScheduleTemplate', 'Copy-AutomateNOWSemaphore', 'Copy-AutomateNOWServerNode', 'Copy-AutomateNOWServiceManagerTemplate', 'Copy-AutomateNOWStock', 'Copy-AutomateNOWTaskTemplate', 'Copy-AutomateNOWTimeWindow', 'Copy-AutomateNOWUserReport', 'Copy-AutomateNOWVariable', 'Copy-AutomateNOWWorkflowTemplate', 'Copy-AutomateNOWWorkspace', 'Deny-AutomateNOWCodeRepositoryMergeRequest', 'Disconnect-AutomateNOW', 'Dismount-AutomateNOWServerNode', 'Edit-AutomateNOWCodeRepositoryObjectSource', 'Edit-AutomateNOWDataSourceItem', 'Export-AutomateNOWAdhocReport', 'Export-AutomateNOWAgent', 'Export-AutomateNOWApproval', 'Export-AutomateNOWAuditLog', 'Export-AutomateNOWBusinessView', 'Export-AutomateNOWCalendar', 'Export-AutomateNOWCodeRepository', 'Export-AutomateNOWCodeRepositoryObjectSource', 'Export-AutomateNOWContextVariable', 'Export-AutomateNOWDataSource', 'Export-AutomateNOWDataSourceItem', 'Export-AutomateNOWDomain', 'Export-AutomateNOWEndpoint', 'Export-AutomateNOWEvent', 'Export-AutomateNOWFolder', 'Export-AutomateNOWIcon', 'Export-AutomateNOWLock', 'Export-AutomateNOWMetric', 'Export-AutomateNOWNotification', 'Export-AutomateNOWNotificationChannel', 'Export-AutomateNOWNotificationGroup', 'Export-AutomateNOWNotificationGroupMember', 'Export-AutomateNOWNotificationMessageTemplate', 'Export-AutomateNOWPhysicalResource', 'Export-AutomateNOWProcessingEventLog', 'Export-AutomateNOWResultMapping', 'Export-AutomateNOWSchedule', 'Export-AutomateNOWScheduleTemplate', 'Export-AutomateNOWSecurityEventLog', 'Export-AutomateNOWSemaphore', 'Export-AutomateNOWSemaphoreTimestamp', 'Export-AutomateNOWServerNode', 'Export-AutomateNOWServiceManager', 'Export-AutomateNOWServiceManagerTemplate', 'Export-AutomateNOWStock', 'Export-AutomateNOWTag', 'Export-AutomateNOWTask', 'Export-AutomateNOWTaskTemplate', 'Export-AutomateNOWTimeTrigger', 'Export-AutomateNOWTimeWindow', 'Export-AutomateNOWTimeZone', 'Export-AutomateNOWUser', 'Export-AutomateNOWUserReport', 'Export-AutomateNOWVariable', 'Export-AutomateNOWVariableTimestamp', 'Export-AutomateNOWWorkflow', 'Export-AutomateNOWWorkflowTemplate', 'Export-AutomateNOWWorkspace', 'Find-AutomateNOWObjectReferral', 'Get-AutomateNOWAdhocReport', 'Get-AutomateNOWAgent', 'Get-AutomateNOWApproval', 'Get-AutomateNOWAuditLog', 'Get-AutomateNOWBusinessView', 'Get-AutomateNOWCalendar', 'Get-AutomateNOWCodeRepository', 'Get-AutomateNOWCodeRepositoryBranch', 'Get-AutomateNOWCodeRepositoryConflictItem', 'Get-AutomateNOWCodeRepositoryItem', 'Get-AutomateNOWCodeRepositoryMergeRequest', 'Get-AutomateNOWCodeRepositoryObjectSource', 'Get-AutomateNOWCodeRepositoryTag', 'Get-AutomateNOWContextVariable', 'Get-AutomateNOWDataSource', 'Get-AutomateNOWDomain', 'Get-AutomateNOWEndpoint', 'Get-AutomateNOWEvent', 'Get-AutomateNOWFolder', 'Get-AutomateNOWLock', 'Get-AutomateNOWMetric', 'Get-AutomateNOWNotification', 'Get-AutomateNOWNotificationChannel', 'Get-AutomateNOWNotificationGroup', 'Get-AutomateNOWNotificationGroupMember', 'Get-AutomateNOWNotificationMessageTemplate', 'Get-AutomateNOWPhysicalResource', 'Get-AutomateNOWProcessingEventLog', 'Get-AutomateNOWResultMapping', 'Get-AutomateNOWSchedule', 'Get-AutomateNOWScheduleTemplate', 'Get-AutomateNOWSecurityEventLog', 'Get-AutomateNOWSemaphore', 'Get-AutomateNOWSemaphoreTimestamp', 'Get-AutomateNOWServerNode', 'Get-AutomateNOWServiceManager', 'Get-AutomateNOWServiceManagerTemplate', 'Get-AutomateNOWStock', 'Get-AutomateNOWTag', 'Get-AutomateNOWTask', 'Get-AutomateNOWTaskTemplate', 'Get-AutomateNOWTimeTrigger', 'Get-AutomateNOWTimeWindow', 'Get-AutomateNOWTimeZone', 'Get-AutomateNOWUser', 'Get-AutomateNOWUserReport', 'Get-AutomateNOWVariable', 'Get-AutomateNOWVariableTimestamp', 'Get-AutomateNOWWorkflow', 'Get-AutomateNOWWorkflowTemplate', 'Get-AutomateNOWWorkspace', 'Import-AutomateNOWIcon', 'Import-AutomateNOWLocalIcon', 'Import-AutomateNOWLocalTimeZone', 'Import-AutomateNOWTimeZone', 'Invoke-AutomateNOWAdhocReport', 'Invoke-AutomateNOWAPI', 'Merge-AutomateNOWCodeRepositoryBranch', 'Merge-AutomateNOWCodeRepositoryConflictItem', 'New-AutomateNOWAdhocReport', 'New-AutomateNOWAgent', 'New-AutomateNOWApproval', 'New-AutomateNOWApprovalRule', 'New-AutomateNOWBusinessView', 'New-AutomateNOWCalendar', 'New-AutomateNOWCodeRepository', 'New-AutomateNOWCodeRepositoryBranch', 'New-AutomateNOWCodeRepositoryTag', 'New-AutomateNOWDataSource', 'New-AutomateNOWDefaultProcessingTitle', 'New-AutomateNOWDomain', 'New-AutomateNOWEndpoint', 'New-AutomateNOWEvent', 'New-AutomateNOWFolder', 'New-AutomateNOWLock', 'New-AutomateNOWMetric', 'New-AutomateNOWNotificationChannel', 'New-AutomateNOWNotificationGroup', 'New-AutomateNOWNotificationMessageTemplate', 'New-AutomateNOWPhysicalResource', 'New-AutomateNOWResultMapping', 'New-AutomateNOWResultMappingRule', 'New-AutomateNOWResultMappingRuleCondition', 'New-AutomateNOWResultMappingRuleConditionCriteria', 'New-AutomateNOWScheduleTemplate', 'New-AutomateNOWSemaphore', 'New-AutomateNOWServerDayTimestamp', 'New-AutomateNOWServerNode', 'New-AutomateNOWServiceManagerTemplate', 'New-AutomateNOWStock', 'New-AutomateNOWTag', 'New-AutomateNOWTaskTemplate', 'New-AutomateNOWTimeWindow', 'New-AutomateNOWUser', 'New-AutomateNOWVariable', 'New-AutomateNOWWorkflowTemplate', 'New-AutomateNOWWorkspace', 'Pop-AutomateNOWLoadBalancerNode', 'Protect-AutomateNOWEncryptedString', 'Publish-AutomateNOWCodeRepository', 'Push-AutomateNOWLoadBalancerNode', 'Read-AutomateNOWBusinessViewItem', 'Read-AutomateNOWDataSourceItem', 'Read-AutomateNOWIcon', 'Read-AutomateNOWScheduleTemplateItem', 'Read-AutomateNOWServerNodeEndpoint', 'Read-AutomateNOWServiceManagerTemplateItem', 'Read-AutomateNOWWorkflowTemplateItem', 'Receive-AutomateNOWCodeRepository', 'Remove-AutomateNOWAdhocReport', 'Remove-AutomateNOWAgent', 'Remove-AutomateNOWApproval', 'Remove-AutomateNOWBusinessView', 'Remove-AutomateNOWBusinessViewItem', 'Remove-AutomateNOWCalendar', 'Remove-AutomateNOWCodeRepository', 'Remove-AutomateNOWCodeRepositoryBranch', 'Remove-AutomateNOWCodeRepositoryItem', 'Remove-AutomateNOWCodeRepositoryTag', 'Remove-AutomateNOWDataSource', 'Remove-AutomateNOWDataSourceItem', 'Remove-AutomateNOWDomain', 'Remove-AutomateNOWEndpoint', 'Remove-AutomateNOWEvent', 'Remove-AutomateNOWFolder', 'Remove-AutomateNOWLock', 'Remove-AutomateNOWMetric', 'Remove-AutomateNOWNotification', 'Remove-AutomateNOWNotificationChannel', 'Remove-AutomateNOWNotificationGroup', 'Remove-AutomateNOWNotificationGroupMember', 'Remove-AutomateNOWNotificationMessageTemplate', 'Remove-AutomateNOWPhysicalResource', 'Remove-AutomateNOWResultMapping', 'Remove-AutomateNOWSchedule', 'Remove-AutomateNOWScheduleTemplate', 'Remove-AutomateNOWScheduleTemplateItem', 'Remove-AutomateNOWSemaphore', 'Remove-AutomateNOWServerNode', 'Remove-AutomateNOWServerNodeEndpoint', 'Remove-AutomateNOWServiceManager', 'Remove-AutomateNOWServiceManagerTemplate', 'Remove-AutomateNOWServiceManagerTemplateItem', 'Remove-AutomateNOWStock', 'Remove-AutomateNOWTag', 'Remove-AutomateNOWTask', 'Remove-AutomateNOWTaskTemplate', 'Remove-AutomateNOWTimeTrigger', 'Remove-AutomateNOWTimeWindow', 'Remove-AutomateNOWUser', 'Remove-AutomateNOWUserReport', 'Remove-AutomateNOWVariable', 'Remove-AutomateNOWWorkflow', 'Remove-AutomateNOWWorkflowTemplate', 'Remove-AutomateNOWWorkflowTemplateItem', 'Remove-AutomateNOWWorkspace', 'Rename-AutomateNOWAdhocReport', 'Rename-AutomateNOWAgent', 'Rename-AutomateNOWApproval', 'Rename-AutomateNOWBusinessView', 'Rename-AutomateNOWCalendar', 'Rename-AutomateNOWDataSource', 'Rename-AutomateNOWDomain', 'Rename-AutomateNOWEndpoint', 'Rename-AutomateNOWEvent', 'Rename-AutomateNOWLock', 'Rename-AutomateNOWMetric', 'Rename-AutomateNOWNotificationChannel', 'Rename-AutomateNOWNotificationGroup', 'Rename-AutomateNOWNotificationMessageTemplate', 'Rename-AutomateNOWPhysicalResource', 'Rename-AutomateNOWResultMapping', 'Rename-AutomateNOWScheduleTemplate', 'Rename-AutomateNOWSemaphore', 'Rename-AutomateNOWServerNode', 'Rename-AutomateNOWServiceManagerTemplate', 'Rename-AutomateNOWStock', 'Rename-AutomateNOWTaskTemplate', 'Rename-AutomateNOWTimeWindow', 'Rename-AutomateNOWUserReport', 'Rename-AutomateNOWVariable', 'Rename-AutomateNOWWorkflowTemplate', 'Rename-AutomateNOWWorkspace', 'Resolve-AutomateNOWCodeRepository', 'Resolve-AutomateNOWEndpoinType2JavaScriptDefinition', 'Resolve-AutomateNOWMonitorType2ServerNodeType', 'Resolve-AutomateNOWSensorType2ServerNodeType', 'Resolve-AutomateNOWTaskType2ServerNodeType', 'Restart-AutomateNOWSchedule', 'Restart-AutomateNOWServiceManager', 'Restart-AutomateNOWTask', 'Restart-AutomateNOWWorkflow', 'Resume-AutomateNOWDomain', 'Resume-AutomateNOWSchedule', 'Resume-AutomateNOWScheduleTemplate', 'Resume-AutomateNOWServerNode', 'Resume-AutomateNOWServiceManager', 'Resume-AutomateNOWServiceManagerTemplate', 'Resume-AutomateNOWTask', 'Resume-AutomateNOWTaskTemplate', 'Resume-AutomateNOWTimeTrigger', 'Resume-AutomateNOWWorkflow', 'Resume-AutomateNOWWorkflowTemplate', 'Select-AutomateNOWCodeRepositoryBranch', 'Select-AutomateNOWCodeRepositoryTag', 'Send-AutomateNOWCodeRepository', 'Set-AutomateNOWAdhocReport', 'Set-AutomateNOWAgent', 'Set-AutomateNOWApproval', 'Set-AutomateNOWBusinessView', 'Set-AutomateNOWCodeRepository', 'Set-AutomateNOWDataSource', 'Set-AutomateNOWDomain', 'Set-AutomateNOWEndpoint', 'Set-AutomateNOWEvent', 'Set-AutomateNOWFolder', 'Set-AutomateNOWLock', 'Set-AutomateNOWMetric', 'Set-AutomateNOWNotificationChannel', 'Set-AutomateNOWNotificationGroup', 'Set-AutomateNOWNotificationGroupMember', 'Set-AutomateNOWNotificationMessageTemplate', 'Set-AutomateNOWPhysicalResource', 'Set-AutomateNOWScheduleTemplate', 'Set-AutomateNOWSemaphore', 'Set-AutomateNOWSemaphoreTimestamp', 'Set-AutomateNOWServiceManagerTemplate', 'Set-AutomateNOWStock', 'Set-AutomateNOWTag', 'Set-AutomateNOWTaskTemplate', 'Set-AutomateNOWTimeTrigger', 'Set-AutomateNOWTimeWindow', 'Set-AutomateNOWUser', 'Set-AutomateNOWUserPassword', 'Set-AutomateNOWUserReport', 'Set-AutomateNOWVariable', 'Set-AutomateNOWVariableTimestamp', 'Set-AutomateNOWWorkflowTemplate', 'Set-AutomateNOWWorkspace', 'Show-AutomateNOWCodeRepositoryConflictItemComparison', 'Show-AutomateNOWEndpointType', 'Show-AutomateNOWTaskTemplateType', 'Skip-AutomateNOWSchedule', 'Skip-AutomateNOWScheduleTemplate', 'Skip-AutomateNOWServerNode', 'Skip-AutomateNOWServiceManager', 'Skip-AutomateNOWServiceManagerTemplate', 'Skip-AutomateNOWTask', 'Skip-AutomateNOWTaskTemplate', 'Skip-AutomateNOWTimeTrigger', 'Skip-AutomateNOWWorkflow', 'Skip-AutomateNOWWorkflowTemplate', 'Start-AutomateNOWEvent', 'Start-AutomateNOWScheduleTemplate', 'Start-AutomateNOWServerNode', 'Start-AutomateNOWServiceManagerTemplate', 'Start-AutomateNOWTaskTemplate', 'Start-AutomateNOWWorkflowTemplate', 'Stop-AutomateNOWSchedule', 'Stop-AutomateNOWServerNode', 'Stop-AutomateNOWServiceManager', 'Stop-AutomateNOWTask', 'Stop-AutomateNOWWorkflow', 'Suspend-AutomateNOWDomain', 'Suspend-AutomateNOWSchedule', 'Suspend-AutomateNOWScheduleTemplate', 'Suspend-AutomateNOWServerNode', 'Suspend-AutomateNOWServiceManager', 'Suspend-AutomateNOWServiceManagerTemplate', 'Suspend-AutomateNOWTask', 'Suspend-AutomateNOWTaskTemplate', 'Suspend-AutomateNOWTimeTrigger', 'Suspend-AutomateNOWWorkflow', 'Suspend-AutomateNOWWorkflowTemplate', 'Switch-AutomateNOWDomain', 'Sync-AutomateNOWCodeRepository', 'Sync-AutomateNOWDomainResource', 'Sync-AutomateNOWDomainServerNode', 'Test-AutomateNOWUserPassword', 'Trace-AutomateNOWWorkFlow', 'Unprotect-AutomateNOWEncryptedString', 'UnPublish-AutomateNOWCodeRepository', 'Update-AutomateNOWCodeRepositoryObjectSource', 'Update-AutomateNOWToken', 'Wait-AutomateNOWServiceManager', 'Wait-AutomateNOWTask', 'Wait-AutomateNOWWorkFlow', 'Write-AutomateNOWIconData' ) #For performance, list functions explicitly

	CompatiblePSEditions   = @('Desktop', 'Core')
	
	# Cmdlets to export from this module
	CmdletsToExport        = '*' 
	
	# Variables to export from this module
	VariablesToExport      = '*'
	
	# Aliases to export from this module
	AliasesToExport        = '*' #For performance, list alias explicitly
	
	# DSC class resources to export from this module.
	#DSCResourcesToExport = ''
	
	# List of all modules packaged with this module
	ModuleList             = @()
	
	# List of all files packaged with this module
	FileList               = @()
	
	# Private data to pass to the module specified in ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData            = @{
		
		#Support for PowerShellGet galleries.
		PSData = @{
			
			# Tags applied to this module. These help with module discovery in online galleries.
			Tags       = @('AutomateNOW')
			
			# A URL to the license for this module.
			# LicenseUri = ''
			
			# A URL to the main website for this project.
			ProjectUri = 'https://github.com/AutomateNOW-Fan/AutomateNOW'
			
			# A URL to an icon representing this module.
			IconUri    = 'https://i.imgur.com/vqgEhoh.png'
			
			# ReleaseNotes of this module
			# ReleaseNotes = ''
			
		} # End of PSData hashtable
		
	} # End of PrivateData hashtable
}
