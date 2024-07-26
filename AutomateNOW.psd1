<#	
Developed against AutomateNOW! version 3.3.1.80 HF0

Be warned: this version *is not likely* to work correctly with any version below 3.3.1.80 HF0

#>
@{	
	# Author of this module
	Author                 = 'AutomateNOW-Fan'

	# Script module or binary module file associated with this manifest
	RootModule             = 'AutomateNOW.psm1'
	
	# Version number of this module.
	ModuleVersion          = '1.0.24'
	
	# ID used to uniquely identify this module
	GUID                   = '8b4222ab-e1ac-72d2-2543-2a13d1f25a3a'
	
	# Copyright statement for this module
	Copyright              = 'not affiliated with InfiniteDATA/Beta Systems'
	
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
	FunctionsToExport      = @('Add-AutomateNOWApprovalRule', 'Add-AutomateNOWCodeRepositoryItem', 'Add-AutomateNOWDataSourceItem', 'Add-AutomateNOWResultMappingRule', 'Add-AutomateNOWScheduleTemplateItem', 'Add-AutomateNOWWorkflowTemplateItem', 'Approve-AutomateNOWCodeRepositoryMergeRequest', 'Clear-AutomateNOWDomain', 'Compare-AutomateNOWCodeRepositoryOutOfSyncItem', 'Compare-ObjectProperty', 'Confirm-AutomateNOWCodeRepository', 'Confirm-AutomateNOWScheduleTemplate', 'Confirm-AutomateNOWSession', 'Confirm-AutomateNOWTaskTemplate', 'Confirm-AutomateNOWWorkflowTemplate', 'Connect-AutomateNOW', 'ConvertTo-QueryString', 'Copy-AutomateNOWAdhocReport', 'Copy-AutomateNOWAgent', 'Copy-AutomateNOWApproval', 'Copy-AutomateNOWCalendar', 'Copy-AutomateNOWDataSource', 'Copy-AutomateNOWDomain', 'Copy-AutomateNOWEndpoint', 'Copy-AutomateNOWLock', 'Copy-AutomateNOWNode', 'Copy-AutomateNOWResultMapping', 'Copy-AutomateNOWScheduleTemplate', 'Copy-AutomateNOWSemaphore', 'Copy-AutomateNOWStock', 'Copy-AutomateNOWTaskTemplate', 'Copy-AutomateNOWTimeWindow', 'Copy-AutomateNOWVariable', 'Copy-AutomateNOWWorkflowTemplate', 'Copy-AutomateNOWWorkspace', 'Deny-AutomateNOWCodeRepositoryMergeRequest', 'Disconnect-AutomateNOW', 'Dismount-AutomateNOWNode', 'Edit-AutomateNOWCodeRepositoryObjectSource', 'Export-AutomateNOWAdhocReport', 'Export-AutomateNOWAgent', 'Export-AutomateNOWApproval', 'Export-AutomateNOWAuditLog', 'Export-AutomateNOWCalendar', 'Export-AutomateNOWCodeRepository', 'Export-AutomateNOWContextVariable', 'Export-AutomateNOWDataSource', 'Export-AutomateNOWDataSourceItem', 'Export-AutomateNOWDomain', 'Export-AutomateNOWEndpoint', 'Export-AutomateNOWFolder', 'Export-AutomateNOWIcon', 'Export-AutomateNOWLock', 'Export-AutomateNOWNode', 'Export-AutomateNOWProcessingEventLog', 'Export-AutomateNOWResultMapping', 'Export-AutomateNOWSchedule', 'Export-AutomateNOWScheduleTemplate', 'Export-AutomateNOWSemaphore', 'Export-AutomateNOWStock', 'Export-AutomateNOWTag', 'Export-AutomateNOWTask', 'Export-AutomateNOWTaskTemplate', 'Export-AutomateNOWTimeTrigger', 'Export-AutomateNOWTimeWindow', 'Export-AutomateNOWTimeZone', 'Export-AutomateNOWUser', 'Export-AutomateNOWVariable', 'Export-AutomateNOWWorkflow', 'Export-AutomateNOWWorkflowTemplate', 'Export-AutomateNOWWorkspace', 'Find-AutomateNOWObjectReferral', 'Get-AutomateNOWAdhocReport', 'Get-AutomateNOWAgent', 'Get-AutomateNOWApproval', 'Get-AutomateNOWAuditLog', 'Get-AutomateNOWCalendar', 'Get-AutomateNOWCodeRepository', 'Get-AutomateNOWCodeRepositoryBranch', 'Get-AutomateNOWCodeRepositoryItem', 'Get-AutomateNOWCodeRepositoryMergeRequest', 'Get-AutomateNOWCodeRepositoryObjectSource', 'Get-AutomateNOWCodeRepositoryOutOfSyncItem', 'Get-AutomateNOWCodeRepositoryTag', 'Get-AutomateNOWContextVariable', 'Get-AutomateNOWDataSource', 'Get-AutomateNOWDataSourceItem', 'Get-AutomateNOWDomain', 'Get-AutomateNOWEndpoint', 'Get-AutomateNOWFolder', 'Get-AutomateNOWLock', 'Get-AutomateNOWNode', 'Get-AutomateNOWProcessingEventLog', 'Get-AutomateNOWResultMapping', 'Get-AutomateNOWSchedule', 'Get-AutomateNOWScheduleTemplate', 'Get-AutomateNOWSemaphore', 'Get-AutomateNOWSemaphoreTimestamp', 'Get-AutomateNOWStock', 'Get-AutomateNOWTag', 'Get-AutomateNOWTask', 'Get-AutomateNOWTaskTemplate', 'Get-AutomateNOWTimeTrigger', 'Get-AutomateNOWTimeWindow', 'Get-AutomateNOWTimeZone', 'Get-AutomateNOWUser', 'Get-AutomateNOWVariable', 'Get-AutomateNOWVariableTimestamp', 'Get-AutomateNOWWorkflow', 'Get-AutomateNOWWorkflowTemplate', 'Get-AutomateNOWWorkspace', 'Import-AutomateNOWIcon', 'Import-AutomateNOWLocalIcon', 'Import-AutomateNOWLocalTimeZone', 'Import-AutomateNOWTimeZone', 'Invoke-AutomateNOWAdhocReport', 'Invoke-AutomateNOWAPI', 'Merge-AutomateNOWCodeRepositoryBranch', 'Merge-AutomateNOWCodeRepositoryOutOfSyncItem', 'New-AutomateNOWAdhocReport', 'New-AutomateNOWAgent', 'New-AutomateNOWApproval', 'New-AutomateNOWApprovalRule', 'New-AutomateNOWCalendar', 'New-AutomateNOWCodeRepository', 'New-AutomateNOWCodeRepositoryBranch', 'New-AutomateNOWCodeRepositoryTag', 'New-AutomateNOWDataSource', 'New-AutomateNOWDefaultProcessingTitle', 'New-AutomateNOWDomain', 'New-AutomateNOWEndpoint', 'New-AutomateNOWFolder', 'New-AutomateNOWLock', 'New-AutomateNOWNode', 'New-AutomateNOWResultMapping', 'New-AutomateNOWResultMappingRule', 'New-AutomateNOWResultMappingRuleCondition', 'New-AutomateNOWResultMappingRuleConditionCriteria', 'New-AutomateNOWScheduleTemplate', 'New-AutomateNOWSemaphore', 'New-AutomateNOWServerDayTimestamp', 'New-AutomateNOWStock', 'New-AutomateNOWTag', 'New-AutomateNOWTaskTemplate', 'New-AutomateNOWTimeWindow', 'New-AutomateNOWUser', 'New-AutomateNOWVariable', 'New-AutomateNOWWorkflowTemplate', 'New-AutomateNOWWorkspace', 'New-WebkitBoundaryString', 'Protect-AutomateNOWEncryptedString', 'Publish-AutomateNOWCodeRepository', 'Read-AutomateNOWIcon', 'Read-AutomateNOWScheduleTemplateItem', 'Read-AutomateNOWWorkflowTemplateItem', 'Receive-AutomateNOWCodeRepository', 'Remove-AutomateNOWAdhocReport', 'Remove-AutomateNOWAgent', 'Remove-AutomateNOWApproval', 'Remove-AutomateNOWCalendar', 'Remove-AutomateNOWCodeRepository', 'Remove-AutomateNOWCodeRepositoryBranch', 'Remove-AutomateNOWCodeRepositoryItem', 'Remove-AutomateNOWCodeRepositoryTag', 'Remove-AutomateNOWDataSource', 'Remove-AutomateNOWDataSourceItem', 'Remove-AutomateNOWDomain', 'Remove-AutomateNOWEndpoint', 'Remove-AutomateNOWFolder', 'Remove-AutomateNOWLock', 'Remove-AutomateNOWNode', 'Remove-AutomateNOWResultMapping', 'Remove-AutomateNOWSchedule', 'Remove-AutomateNOWScheduleTemplate', 'Remove-AutomateNOWScheduleTemplateItem', 'Remove-AutomateNOWSemaphore', 'Remove-AutomateNOWStock', 'Remove-AutomateNOWTag', 'Remove-AutomateNOWTask', 'Remove-AutomateNOWTaskTemplate', 'Remove-AutomateNOWTimeTrigger', 'Remove-AutomateNOWTimeWindow', 'Remove-AutomateNOWUser', 'Remove-AutomateNOWVariable', 'Remove-AutomateNOWWorkflow', 'Remove-AutomateNOWWorkflowTemplate', 'Remove-AutomateNOWWorkspace', 'Rename-AutomateNOWAdhocReport', 'Rename-AutomateNOWAgent', 'Rename-AutomateNOWApproval', 'Rename-AutomateNOWCalendar', 'Rename-AutomateNOWDataSource', 'Rename-AutomateNOWDomain', 'Rename-AutomateNOWEndpoint', 'Rename-AutomateNOWLock', 'Rename-AutomateNOWNode', 'Rename-AutomateNOWResultMapping', 'Rename-AutomateNOWScheduleTemplate', 'Rename-AutomateNOWSemaphore', 'Rename-AutomateNOWStock', 'Rename-AutomateNOWTaskTemplate', 'Rename-AutomateNOWTimeWindow', 'Rename-AutomateNOWVariable', 'Rename-AutomateNOWWorkflowTemplate', 'Rename-AutomateNOWWorkspace', 'Resolve-AutomateNOWMonitorType2ServerNodeType', 'Resolve-AutomateNOWSensorType2ServerNodeType', 'Resolve-AutomateNOWTaskType2ServerNodeType', 'Restart-AutomateNOWSchedule', 'Restart-AutomateNOWTask', 'Restart-AutomateNOWWorkflow', 'Resume-AutomateNOWDomain', 'Resume-AutomateNOWNode', 'Resume-AutomateNOWSchedule', 'Resume-AutomateNOWScheduleTemplate', 'Resume-AutomateNOWTask', 'Resume-AutomateNOWTaskTemplate', 'Resume-AutomateNOWWorkflow', 'Resume-AutomateNOWWorkflowTemplate', 'Select-AutomateNOWCodeRepositoryBranch', 'Select-AutomateNOWCodeRepositoryTag', 'Send-AutomateNOWCodeRepository', 'Set-AutomateNOWAdhocReport', 'Set-AutomateNOWAgent', 'Set-AutomateNOWApproval', 'Set-AutomateNOWCodeRepository', 'Set-AutomateNOWDataSource', 'Set-AutomateNOWDomain', 'Set-AutomateNOWEndpoint', 'Set-AutomateNOWFolder', 'Set-AutomateNOWLock', 'Set-AutomateNOWPassword', 'Set-AutomateNOWScheduleTemplate', 'Set-AutomateNOWSemaphore', 'Set-AutomateNOWSemaphoreTimestamp', 'Set-AutomateNOWStock', 'Set-AutomateNOWTag', 'Set-AutomateNOWTask', 'Set-AutomateNOWTaskTemplate', 'Set-AutomateNOWTimeWindow', 'Set-AutomateNOWUser', 'Set-AutomateNOWVariable', 'Set-AutomateNOWVariableTimestamp', 'Set-AutomateNOWWorkflowTemplate', 'Set-AutomateNOWWorkspace', 'Show-AutomateNOWCodeRepositoryOutOfSyncItemComparison', 'Show-AutomateNOWEndpointType', 'Show-AutomateNOWTaskTemplateType', 'Skip-AutomateNOWNode', 'Skip-AutomateNOWSchedule', 'Skip-AutomateNOWScheduleTemplate', 'Skip-AutomateNOWTask', 'Skip-AutomateNOWTaskTemplate', 'Skip-AutomateNOWWorkflow', 'Skip-AutomateNOWWorkflowTemplate', 'Start-AutomateNOWNode', 'Start-AutomateNOWScheduleTemplate', 'Start-AutomateNOWTaskTemplate', 'Start-AutomateNOWWorkflowTemplate', 'Stop-AutomateNOWNode', 'Stop-AutomateNOWSchedule', 'Stop-AutomateNOWTask', 'Stop-AutomateNOWWorkflow', 'Suspend-AutomateNOWDomain', 'Suspend-AutomateNOWNode', 'Suspend-AutomateNOWSchedule', 'Suspend-AutomateNOWScheduleTemplate', 'Suspend-AutomateNOWTask', 'Suspend-AutomateNOWTaskTemplate', 'Suspend-AutomateNOWWorkflow', 'Suspend-AutomateNOWWorkflowTemplate', 'Switch-AutomateNOWDomain', 'Sync-AutomateNOWCodeRepository', 'Sync-AutomateNOWDomainResource', 'Sync-AutomateNOWDomainServerNode', 'Test-AutomateNOWUserPassword', 'Unprotect-AutomateNOWEncryptedString', 'UnPublish-AutomateNOWCodeRepository', 'Update-AutomateNOWCodeRepositoryObjectSource', 'Update-AutomateNOWToken', 'Write-AutomateNOWIconData' ) #For performance, list functions explicitly

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
