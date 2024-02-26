<#	
Developed against AutomateNOW! version 3.3.1.75HF3
#>
@{	
	# Author of this module
	Author = 'AutomateNOW-Fan'

	# Script module or binary module file associated with this manifest
	RootModule = 'AutomateNOW.psm1'
	
	# Version number of this module.
	ModuleVersion = '1.0.14'
	
	# ID used to uniquely identify this module
	GUID = '1a1214dc-b1ce-3aa1-2338-2d73e4a25b1f'
	
	# Copyright statement for this module
	Copyright = 'not affiliated with InfiniteDATA'
	
	# Description of the functionality provided by this module
	Description = 'Interact with the API of an AutomateNOW! instance'
	
	# Minimum version of the Windows PowerShell engine required by this module
	PowerShellVersion = '5.1'
	
	# Name of the Windows PowerShell host required by this module
	PowerShellHostName = ''
	
	# Minimum version of the Windows PowerShell host required by this module
	PowerShellHostVersion = ''
	
	# Minimum version of the .NET Framework required by this module
	DotNetFrameworkVersion = ''
	
	# Minimum version of the common language runtime (CLR) required by this module
	CLRVersion = ''
	
	# Processor architecture (None, X86, Amd64, IA64) required by this module
	ProcessorArchitecture = 'None'
	
	# Modules that must be imported into the global environment prior to importing
	# this module
	RequiredModules = @()
	
	# Assemblies that must be loaded prior to importing this module
	RequiredAssemblies = @()
	
	# Script files (.ps1) that are run in the caller's environment prior to
	# importing this module
	ScriptsToProcess = @()
	
	# Type files (.ps1xml) to be loaded when importing this module
	TypesToProcess = @()
	
	# Format files (.ps1xml) to be loaded when importing this module
	FormatsToProcess = @()
	
	# Modules to import as nested modules of the module specified in
	# ModuleToProcess
	NestedModules = @()
	
	# Functions to export from this module
	FunctionsToExport = @('Add-AutomateNOWDataSourceItem', 'Add-AutomateNOWResultMappingRule', 'Compare-ObjectProperty', 'Confirm-AutomateNOWSession', 'Confirm-AutomateNOWTaskTemplate', 'Confirm-AutomateNOWWorkflowTemplate', 'Connect-AutomateNOW', 'ConvertTo-QueryString', 'Copy-AutomateNOWTaskTemplate', 'Copy-AutomateNOWWorkflowTemplate', 'Disconnect-AutomateNOW', 'Export-AutomateNOWAuditLog', 'Export-AutomateNOWCodeRepository', 'Export-AutomateNOWDataSource', 'Export-AutomateNOWDataSourceItem', 'Export-AutomateNOWDomain', 'Export-AutomateNOWFolder', 'Export-AutomateNOWIcon', 'Export-AutomateNOWNode', 'Export-AutomateNOWResultMapping', 'Export-AutomateNOWTag', 'Export-AutomateNOWTask', 'Export-AutomateNOWTaskTemplate', 'Export-AutomateNOWTimeZone', 'Export-AutomateNOWUser', 'Export-AutomateNOWWorkflow', 'Export-AutomateNOWWorkflowTemplate', 'Export-AutomateNOWWorkspace', 'Find-AutomateNOWObjectReferral', 'Get-AutomateNOWAuditLog', 'Get-AutomateNOWCodeRepository', 'Get-AutomateNOWDataSource', 'Get-AutomateNOWDataSourceItem', 'Get-AutomateNOWDomain', 'Get-AutomateNOWFolder', 'Get-AutomateNOWNode', 'Get-AutomateNOWResultMapping', 'Get-AutomateNOWTag', 'Get-AutomateNOWTask', 'Get-AutomateNOWTaskTemplate', 'Get-AutomateNOWTimeZone', 'Get-AutomateNOWUser', 'Get-AutomateNOWWorkflow', 'Get-AutomateNOWWorkflowTemplate', 'Get-AutomateNOWWorkspace', 'Import-AutomateNOWIcon', 'Import-AutomateNOWLocalIcon', 'Import-AutomateNOWTimeZone', 'Invoke-AutomateNOWAPI', 'New-AutomateNOWAuthenticationEncryptedString', 'New-AutomateNOWDataSource', 'New-AutomateNOWDefaultProcessingTitle', 'New-AutomateNOWFolder', 'New-AutomateNOWNode', 'New-AutomateNOWResultMapping', 'New-AutomateNOWResultMappingRule', 'New-AutomateNOWResultMappingRuleCondition', 'New-AutomateNOWResultMappingRuleConditionCriteria', 'New-AutomateNOWTag', 'New-AutomateNOWTaskTemplate', 'New-AutomateNOWWorkflowTemplate', 'New-AutomateNOWWorkspace', 'New-WebkitBoundaryString', 'Read-AutomateNOWIcon', 'Remove-AutomateNOWDataSource', 'Remove-AutomateNOWDataSourceItem', 'Remove-AutomateNOWFolder', 'Remove-AutomateNOWNode', 'Remove-AutomateNOWResultMapping', 'Remove-AutomateNOWTag', 'Remove-AutomateNOWTask', 'Remove-AutomateNOWTaskTemplate', 'Remove-AutomateNOWWorkflow', 'Remove-AutomateNOWWorkflowTemplate', 'Remove-AutomateNOWWorkspace', 'Rename-AutomateNOWTaskTemplate', 'Rename-AutomateNOWWorkflowTemplate', 'Resolve-AutomateNOWTaskType2ServerNodeType', 'Restart-AutomateNOWTask', 'Restart-AutomateNOWWorkflow', 'Resume-AutomateNOWTask', 'Resume-AutomateNOWTaskTemplate', 'Resume-AutomateNOWWorkflow', 'Resume-AutomateNOWWorkflowTemplate', 'Set-AutomateNOWDataSource', 'Set-AutomateNOWFolder', 'Set-AutomateNOWPassword', 'Set-AutomateNOWTag', 'Set-AutomateNOWTaskTemplate', 'Set-AutomateNOWUser', 'Set-AutomateNOWWorkspace', 'Show-AutomateNOWTaskTemplateType', 'Skip-AutomateNOWTask', 'Skip-AutomateNOWTaskTemplate', 'Skip-AutomateNOWWorkflow', 'Skip-AutomateNOWWorkflowTemplate', 'Start-AutomateNOWNode', 'Start-AutomateNOWTaskTemplate', 'Start-AutomateNOWWorkflowTemplate', 'Stop-AutomateNOWNode', 'Stop-AutomateNOWTask', 'Stop-AutomateNOWWorkflow', 'Suspend-AutomateNOWTask', 'Suspend-AutomateNOWTaskTemplate', 'Suspend-AutomateNOWWorkflow', 'Suspend-AutomateNOWWorkflowTemplate', 'Switch-AutomateNOWDomain', 'Update-AutomateNOWToken', 'Write-AutomateNOWIconData') #For performance, list functions explicitly

	CompatiblePSEditions = @('Desktop', 'Core')
	
	# Cmdlets to export from this module
	CmdletsToExport = '*' 
	
	# Variables to export from this module
	VariablesToExport = '*'
	
	# Aliases to export from this module
	AliasesToExport = '*' #For performance, list alias explicitly
	
	# DSC class resources to export from this module.
	#DSCResourcesToExport = ''
	
	# List of all modules packaged with this module
	ModuleList = @()
	
	# List of all files packaged with this module
	FileList = @()
	
	# Private data to pass to the module specified in ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData = @{
		
		#Support for PowerShellGet galleries.
		PSData = @{
			
			# Tags applied to this module. These help with module discovery in online galleries.
			Tags = @('AutomateNOW')
			
			# A URL to the license for this module.
			# LicenseUri = ''
			
			# A URL to the main website for this project.
			ProjectUri = 'https://github.com/AutomateNOW-Fan/AutomateNOW'
			
			# A URL to an icon representing this module.
			IconUri = 'https://i.imgur.com/vqgEhoh.png'
			
			# ReleaseNotes of this module
			# ReleaseNotes = ''
			
		} # End of PSData hashtable
		
	} # End of PrivateData hashtable
}
