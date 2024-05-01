<#	
Developed against AutomateNOW! version 3.3.1.78 HF2

Be warned: this version *is not likely* to work correctly with any version below 3.3.1.78 HF2

#>
@{	
	# Author of this module
	Author                 = 'AutomateNOW-Fan'

	# Script module or binary module file associated with this manifest
	RootModule             = 'AutomateNOW.psm1'
	
	# Version number of this module.
	ModuleVersion          = '1.0.17'
	
	# ID used to uniquely identify this module
	GUID                   = '3b4326de-b1de-3aa2-2538-4a13d1a25b1f'
	
	# Copyright statement for this module
	Copyright              = 'not affiliated with InfiniteDATA'
	
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
	FunctionsToExport      = @('Add-AutomateNOWApprovalRule', 'Add-AutomateNOWDataSourceItem', 'Add-AutomateNOWProcessingTimeTrigger', 'Add-AutomateNOWResultMappingRule', 'Compare-ObjectProperty', 'Confirm-AutomateNOWSession', 'Confirm-AutomateNOWTaskTemplate', 'Confirm-AutomateNOWWorkflowTemplate', 'Connect-AutomateNOW', 'ConvertTo-QueryString', 'Copy-AutomateNOWAdhocReport', 'Copy-AutomateNOWAgent', 'Copy-AutomateNOWApproval', 'Copy-AutomateNOWCalendar', 'Copy-AutomateNOWDataSource', 'Copy-AutomateNOWEndpoint', 'Copy-AutomateNOWScheduleTemplate', 'Copy-AutomateNOWSemaphore', 'Copy-AutomateNOWTaskTemplate', 'Copy-AutomateNOWWorkflowTemplate', 'Disconnect-AutomateNOW', 'Export-AutomateNOWAdhocReport', 'Export-AutomateNOWAgent', 'Export-AutomateNOWApproval', 'Export-AutomateNOWAuditLog', 'Export-AutomateNOWCalendar', 'Export-AutomateNOWCodeRepository', 'Export-AutomateNOWDataSource', 'Export-AutomateNOWDataSourceItem', 'Export-AutomateNOWDomain', 'Export-AutomateNOWEndpoint', 'Export-AutomateNOWFolder', 'Export-AutomateNOWIcon', 'Export-AutomateNOWNode', 'Export-AutomateNOWProcessingTimeTrigger', 'Export-AutomateNOWResultMapping', 'Export-AutomateNOWSchedule', 'Export-AutomateNOWScheduleTemplate', 'Export-AutomateNOWSemaphore', 'Export-AutomateNOWTag', 'Export-AutomateNOWTask', 'Export-AutomateNOWTaskTemplate', 'Export-AutomateNOWTimeZone', 'Export-AutomateNOWUser', 'Export-AutomateNOWWorkflow', 'Export-AutomateNOWWorkflowTemplate', 'Export-AutomateNOWWorkspace', 'Find-AutomateNOWObjectReferral', 'Get-AutomateNOWAdhocReport', 'Get-AutomateNOWAgent', 'Get-AutomateNOWApproval', 'Get-AutomateNOWAuditLog', 'Get-AutomateNOWCalendar', 'Get-AutomateNOWCodeRepository', 'Get-AutomateNOWDataSource', 'Get-AutomateNOWDataSourceItem', 'Get-AutomateNOWDomain', 'Get-AutomateNOWEndpoint', 'Get-AutomateNOWFolder', 'Get-AutomateNOWNode', 'Get-AutomateNOWProcessingTimeTrigger', 'Get-AutomateNOWResultMapping', 'Get-AutomateNOWSchedule', 'Get-AutomateNOWScheduleTemplate', 'Get-AutomateNOWSemaphore', 'Get-AutomateNOWTag', 'Get-AutomateNOWTask', 'Get-AutomateNOWTaskTemplate', 'Get-AutomateNOWTimeZone', 'Get-AutomateNOWUser', 'Get-AutomateNOWWorkflow', 'Get-AutomateNOWWorkflowTemplate', 'Get-AutomateNOWWorkspace', 'Import-AutomateNOWIcon', 'Import-AutomateNOWLocalIcon', 'Import-AutomateNOWLocalTimeZone', 'Import-AutomateNOWTimeZone', 'Invoke-AutomateNOWAdhocReport', 'Invoke-AutomateNOWAPI', 'New-AutomateNOWAdhocReport', 'New-AutomateNOWAgent', 'New-AutomateNOWApproval', 'New-AutomateNOWApprovalRule', 'New-AutomateNOWCalendar', 'New-AutomateNOWDataSource', 'New-AutomateNOWDefaultProcessingTitle', 'New-AutomateNOWEndpoint', 'New-AutomateNOWFolder', 'New-AutomateNOWNode', 'New-AutomateNOWResultMapping', 'New-AutomateNOWResultMappingRule', 'New-AutomateNOWResultMappingRuleCondition', 'New-AutomateNOWResultMappingRuleConditionCriteria', 'New-AutomateNOWScheduleTemplate', 'New-AutomateNOWSemaphore', 'New-AutomateNOWTag', 'New-AutomateNOWTaskTemplate', 'New-AutomateNOWWorkflowTemplate', 'New-AutomateNOWWorkspace', 'New-WebkitBoundaryString', 'Protect-AutomateNOWEncryptedString', 'Read-AutomateNOWIcon', 'Read-AutomateNOWWorkflowTemplateTimeline', 'Remove-AutomateNOWAdhocReport', 'Remove-AutomateNOWAgent', 'Remove-AutomateNOWApproval', 'Remove-AutomateNOWCalendar', 'Remove-AutomateNOWDataSource', 'Remove-AutomateNOWDataSourceItem', 'Remove-AutomateNOWEndpoint', 'Remove-AutomateNOWFolder', 'Remove-AutomateNOWNode', 'Remove-AutomateNOWProcessingTimeTrigger', 'Remove-AutomateNOWResultMapping', 'Remove-AutomateNOWSchedule', 'Remove-AutomateNOWScheduleTemplate', 'Remove-AutomateNOWSemaphore', 'Remove-AutomateNOWTag', 'Remove-AutomateNOWTask', 'Remove-AutomateNOWTaskTemplate', 'Remove-AutomateNOWWorkflow', 'Remove-AutomateNOWWorkflowTemplate', 'Remove-AutomateNOWWorkspace', 'Rename-AutomateNOWScheduleTemplate', 'Rename-AutomateNOWTaskTemplate', 'Rename-AutomateNOWWorkflowTemplate', 'Resolve-AutomateNOWTaskType2ServerNodeType', 'Restart-AutomateNOWSchedule', 'Restart-AutomateNOWTask', 'Restart-AutomateNOWWorkflow', 'Resume-AutomateNOWSchedule', 'Resume-AutomateNOWScheduleTemplate', 'Resume-AutomateNOWTask', 'Resume-AutomateNOWTaskTemplate', 'Resume-AutomateNOWWorkflow', 'Resume-AutomateNOWWorkflowTemplate', 'Set-AutomateNOWAdhocReport', 'Set-AutomateNOWAgent', 'Set-AutomateNOWApproval', 'Set-AutomateNOWDataSource', 'Set-AutomateNOWEndpoint', 'Set-AutomateNOWFolder', 'Set-AutomateNOWPassword', 'Set-AutomateNOWScheduleTemplate', 'Set-AutomateNOWSemaphore', 'Set-AutomateNOWTag', 'Set-AutomateNOWTaskTemplate', 'Set-AutomateNOWUser', 'Set-AutomateNOWWorkflowTemplate', 'Set-AutomateNOWWorkspace', 'Show-AutomateNOWEndpointType', 'Show-AutomateNOWTaskTemplateType', 'Skip-AutomateNOWSchedule', 'Skip-AutomateNOWScheduleTemplate', 'Skip-AutomateNOWTask', 'Skip-AutomateNOWTaskTemplate', 'Skip-AutomateNOWWorkflow', 'Skip-AutomateNOWWorkflowTemplate', 'Start-AutomateNOWNode', 'Start-AutomateNOWScheduleTemplate', 'Start-AutomateNOWTaskTemplate', 'Start-AutomateNOWWorkflowTemplate', 'Stop-AutomateNOWNode', 'Stop-AutomateNOWSchedule', 'Stop-AutomateNOWTask', 'Stop-AutomateNOWWorkflow', 'Suspend-AutomateNOWSchedule', 'Suspend-AutomateNOWScheduleTemplate', 'Suspend-AutomateNOWTask', 'Suspend-AutomateNOWTaskTemplate', 'Suspend-AutomateNOWWorkflow', 'Suspend-AutomateNOWWorkflowTemplate', 'Switch-AutomateNOWDomain', 'Unprotect-AutomateNOWEncryptedString', 'Update-AutomateNOWToken', 'Write-AutomateNOWIconData' ) #For performance, list functions explicitly

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
