﻿<#	
Developed against AutomateNOW! version 3.2.1.77
#>
@{	
	# Author of this module
	Author = 'AutomateNOW-Fan'

	# Script module or binary module file associated with this manifest
	RootModule = 'AutomateNOW.psm1'
	
	# Version number of this module.
	ModuleVersion = '1.0.8'
	
	# ID used to uniquely identify this module
	GUID = '3a4214ab-a9cb-6aa1-2331-1d73e6a25b0b'
	
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
	FunctionsToExport = @('Confirm-AutomateNOWSession', 'Connect-AutomateNOW', 'Disconnect-AutomateNOW', 'Get-AutomateNOWAdhocReport', 'Get-AutomateNOWAuditLog', 'Get-AutomateNOWCalendar', 'Get-AutomateNOWDomain', 'Get-AutomateNOWFolder', 'Get-AutomateNOWNode', 'Get-AutomateNOWOverview', 'Get-AutomateNOWTag', 'Get-AutomateNOWTask', 'Get-AutomateNOWTriggerLog', 'Get-AutomateNOWUser', 'Get-AutomateNOWWorkflow', 'Import-AutomateNOWIcon', 'Invoke-AutomateNOWAPI', 'New-AutomateNOWFolder', 'New-AutomateNOWTag', 'Read-AutomateNOWTimeZone', 'Remove-AutomateNOWTag', 'Set-AutomateNOWPassword', 'Show-AutomateNOWDomain', 'Show-AutomateNOWTaskType', 'Start-AutomateNOWTask', 'Switch-AutomateNOWDomain', 'Update-AutomateNOWToken') #For performance, list functions explicitly
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
			ProjectUri = 'https://github.com/AutomateNOW-Fan'
			
			# A URL to an icon representing this module.
			IconUri = 'https://i.imgur.com/vqgEhoh.png'
			
			# ReleaseNotes of this module
			# ReleaseNotes = ''
			
		} # End of PSData hashtable
		
	} # End of PrivateData hashtable
}
