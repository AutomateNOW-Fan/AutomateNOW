﻿<#	

Developed and tested against AutomateNOW! version 3.3.1.90 HF2

#>
@{	
	# Author of this module
	Author                 = 'AutomateNOW-Fan'

	# Script module or binary module file associated with this manifest
	RootModule             = 'AutomateNOW.psm1'
	
	# Version number of this module.
	ModuleVersion          = '1.0.38'
	
	# ID used to uniquely identify this module
	GUID                   = 'a72582c2-7c4e-4dad-ac38-b04066e67cc3'
	
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
	FunctionsToExport      = @('Add-AutomateNOWApprovalRule', 'Add-AutomateNOWBusinessViewItem', 'Add-AutomateNOWCodeRepositoryItem', 'Add-AutomateNOWDashboardPortlet', 'Add-AutomateNOWDataSourceItem', 'Add-AutomateNOWLoadBalancerNode', 'Add-AutomateNOWNotificationGroupMember', 'Add-AutomateNOWResourceAnomaly', 'Add-AutomateNOWResultMappingRule', 'Add-AutomateNOWScheduleTemplateItem', 'Add-AutomateNOWSecurityAccessToken', 'Add-AutomateNOWSecurityRoleDomain', 'Add-AutomateNOWSecurityRoleUser', 'Add-AutomateNOWServerNodeEndpoint', 'Add-AutomateNOWServerNodeGroupItem', 'Add-AutomateNOWServiceManagerTemplateDependency', 'Add-AutomateNOWServiceManagerTemplateItem', 'Add-AutomateNOWTimeTrigger', 'Add-AutomateNOWWorkflowTemplateDependency', 'Add-AutomateNOWWorkflowTemplateItem', 'Approve-AutomateNOWCodeRepositoryMergeRequest', 'Clear-AutomateNOWDomain', 'Clear-AutomateNOWProcessingStateRegistry', 'Compare-AutomateNOWCodeRepositoryConflictItem', 'Confirm-AutomateNOWCodeRepository', 'Confirm-AutomateNOWMigrationImport', 'Confirm-AutomateNOWScheduleTemplate', 'Confirm-AutomateNOWServiceManagerTemplate', 'Confirm-AutomateNOWSession', 'Confirm-AutomateNOWTaskTemplate', 'Confirm-AutomateNOWWorkflowTemplate', 'Connect-AutomateNOW', 'ConvertFrom-AutomateNOWContextVariable', 'Copy-AutomateNOWAdhocReport', 'Copy-AutomateNOWAgent', 'Copy-AutomateNOWAnomaly', 'Copy-AutomateNOWApproval', 'Copy-AutomateNOWBusinessView', 'Copy-AutomateNOWCalendar', 'Copy-AutomateNOWDashboard', 'Copy-AutomateNOWDataSource', 'Copy-AutomateNOWDesignTemplate', 'Copy-AutomateNOWDomain', 'Copy-AutomateNOWEndpoint', 'Copy-AutomateNOWEvent', 'Copy-AutomateNOWLock', 'Copy-AutomateNOWMetric', 'Copy-AutomateNOWNotificationChannel', 'Copy-AutomateNOWNotificationGroup', 'Copy-AutomateNOWNotificationMessageTemplate', 'Copy-AutomateNOWPhysicalResource', 'Copy-AutomateNOWProcessingFunction', 'Copy-AutomateNOWResultMapping', 'Copy-AutomateNOWRuntimeAction', 'Copy-AutomateNOWScheduleTemplate', 'Copy-AutomateNOWSecurityRole', 'Copy-AutomateNOWSecurityRoleDomain', 'Copy-AutomateNOWSemaphore', 'Copy-AutomateNOWServerNode', 'Copy-AutomateNOWServerNodeGroup', 'Copy-AutomateNOWServiceManagerTemplate', 'Copy-AutomateNOWStock', 'Copy-AutomateNOWTag', 'Copy-AutomateNOWTaskTemplate', 'Copy-AutomateNOWTimeWindow', 'Copy-AutomateNOWUserReport', 'Copy-AutomateNOWVariable', 'Copy-AutomateNOWViewSetup', 'Copy-AutomateNOWWorkflowTemplate', 'Copy-AutomateNOWWorkspace', 'Deny-AutomateNOWCodeRepositoryMergeRequest', 'Disable-AutomateNOWAgentCentralManagement', 'Disconnect-AutomateNOW', 'Dismount-AutomateNOWAgentServerNode', 'Edit-AutomateNOWCodeRepositoryObjectSource', 'Edit-AutomateNOWDataSourceItem', 'Enable-AutomateNOWAgentCentralManagement', 'Export-AutomateNOWAdhocReport', 'Export-AutomateNOWAgent', 'Export-AutomateNOWAgentServerNode', 'Export-AutomateNOWAnomaly', 'Export-AutomateNOWApproval', 'Export-AutomateNOWAuditLog', 'Export-AutomateNOWBusinessView', 'Export-AutomateNOWCalendar', 'Export-AutomateNOWCodeRepository', 'Export-AutomateNOWCodeRepositoryObjectSource', 'Export-AutomateNOWContextVariable', 'Export-AutomateNOWDashboard', 'Export-AutomateNOWDataSource', 'Export-AutomateNOWDataSourceItem', 'Export-AutomateNOWDeletedDomain', 'Export-AutomateNOWDeletedObject', 'Export-AutomateNOWDesignTemplate', 'Export-AutomateNOWDomain', 'Export-AutomateNOWEndpoint', 'Export-AutomateNOWEvent', 'Export-AutomateNOWFolder', 'Export-AutomateNOWIcon', 'Export-AutomateNOWLock', 'Export-AutomateNOWMenuCustomization', 'Export-AutomateNOWMetric', 'Export-AutomateNOWMigration', 'Export-AutomateNOWMigrationImport', 'Export-AutomateNOWNotification', 'Export-AutomateNOWNotificationChannel', 'Export-AutomateNOWNotificationGroup', 'Export-AutomateNOWNotificationGroupMember', 'Export-AutomateNOWNotificationMessageTemplate', 'Export-AutomateNOWPhysicalResource', 'Export-AutomateNOWProcessingEventLog', 'Export-AutomateNOWProcessingFunction', 'Export-AutomateNOWProcessingState', 'Export-AutomateNOWProcessingTriggerLog', 'Export-AutomateNOWResourceAnomaly', 'Export-AutomateNOWResultMapping', 'Export-AutomateNOWRuntimeAction', 'Export-AutomateNOWSchedule', 'Export-AutomateNOWScheduleTemplate', 'Export-AutomateNOWSecurityAccessToken', 'Export-AutomateNOWSecurityEventLog', 'Export-AutomateNOWSecurityRole', 'Export-AutomateNOWSecurityRoleDomain', 'Export-AutomateNOWSecurityRoleUser', 'Export-AutomateNOWSecUser', 'Export-AutomateNOWSemaphore', 'Export-AutomateNOWSemaphoreTimestamp', 'Export-AutomateNOWServerNode', 'Export-AutomateNOWServerNodeEndpoint', 'Export-AutomateNOWServerNodeGroup', 'Export-AutomateNOWServiceManager', 'Export-AutomateNOWServiceManagerTemplate', 'Export-AutomateNOWStock', 'Export-AutomateNOWTag', 'Export-AutomateNOWTask', 'Export-AutomateNOWTaskTemplate', 'Export-AutomateNOWTimeTrigger', 'Export-AutomateNOWTimeWindow', 'Export-AutomateNOWTimeZone', 'Export-AutomateNOWUserReport', 'Export-AutomateNOWVariable', 'Export-AutomateNOWVariableTimestamp', 'Export-AutomateNOWViewSetup', 'Export-AutomateNOWWorkflow', 'Export-AutomateNOWWorkflowTemplate', 'Export-AutomateNOWWorkspace', 'Find-AutomateNOWObjectReferral', 'Get-AutomateNOWAdhocReport', 'Get-AutomateNOWAgent', 'Get-AutomateNOWAnomaly', 'Get-AutomateNOWApproval', 'Get-AutomateNOWAuditLog', 'Get-AutomateNOWBusinessView', 'Get-AutomateNOWCalendar', 'Get-AutomateNOWCodeRepository', 'Get-AutomateNOWCodeRepositoryBranch', 'Get-AutomateNOWCodeRepositoryConflictItem', 'Get-AutomateNOWCodeRepositoryMergeRequest', 'Get-AutomateNOWCodeRepositoryObjectSource', 'Get-AutomateNOWCodeRepositoryOutOfSyncItem', 'Get-AutomateNOWCodeRepositoryTag', 'Get-AutomateNOWContextVariable', 'Get-AutomateNOWDashboard', 'Get-AutomateNOWDataSource', 'Get-AutomateNOWDeletedDomain', 'Get-AutomateNOWDeletedObject', 'Get-AutomateNOWDesignTemplate', 'Get-AutomateNOWDomain', 'Get-AutomateNOWEndpoint', 'Get-AutomateNOWEvent', 'Get-AutomateNOWFolder', 'Get-AutomateNOWInterface', 'Get-AutomateNOWLock', 'Get-AutomateNOWMenuCustomization', 'Get-AutomateNOWMetric', 'Get-AutomateNOWMigrationImport', 'Get-AutomateNOWNotification', 'Get-AutomateNOWNotificationChannel', 'Get-AutomateNOWNotificationGroup', 'Get-AutomateNOWNotificationGroupMember', 'Get-AutomateNOWNotificationMessageTemplate', 'Get-AutomateNOWPhysicalResource', 'Get-AutomateNOWProcessingFunction', 'Get-AutomateNOWProcessingList', 'Get-AutomateNOWProcessingState', 'Get-AutomateNOWProcessingTemplate', 'Get-AutomateNOWProcessingTriggerLog', 'Get-AutomateNOWResourceList', 'Get-AutomateNOWResultMapping', 'Get-AutomateNOWRuntimeAction', 'Get-AutomateNOWSchedule', 'Get-AutomateNOWScheduleTemplate', 'Get-AutomateNOWSecurityEventLog', 'Get-AutomateNOWSecurityRole', 'Get-AutomateNOWSecUser', 'Get-AutomateNOWSemaphore', 'Get-AutomateNOWSemaphoreTimestamp', 'Get-AutomateNOWServerNode', 'Get-AutomateNOWServerNodeGroup', 'Get-AutomateNOWServiceManager', 'Get-AutomateNOWServiceManagerTemplate', 'Get-AutomateNOWStock', 'Get-AutomateNOWTag', 'Get-AutomateNOWTask', 'Get-AutomateNOWTaskTemplate', 'Get-AutomateNOWTimeWindow', 'Get-AutomateNOWTimeZone', 'Get-AutomateNOWUserReport', 'Get-AutomateNOWVariable', 'Get-AutomateNOWVariableTimestamp', 'Get-AutomateNOWViewSetup', 'Get-AutomateNOWWorkflow', 'Get-AutomateNOWWorkflowTemplate', 'Get-AutomateNOWWorkspace', 'Import-AutomateNOWIcon', 'Import-AutomateNOWLocalIcon', 'Import-AutomateNOWLocalTimeZone', 'Import-AutomateNOWTimeZone', 'Invoke-AutomateNOWAdhocReport', 'Invoke-AutomateNOWAPI', 'Merge-AutomateNOWCodeRepositoryBranch', 'Merge-AutomateNOWCodeRepositoryConflictItem', 'Mount-AutomateNOWAgentServerNode', 'New-AutomateNOWAdhocReport', 'New-AutomateNOWAgent', 'New-AutomateNOWAnomaly', 'New-AutomateNOWApproval', 'New-AutomateNOWApprovalRule', 'New-AutomateNOWBusinessView', 'New-AutomateNOWCalendar', 'New-AutomateNOWCodeRepository', 'New-AutomateNOWCodeRepositoryBranch', 'New-AutomateNOWCodeRepositoryTag', 'New-AutomateNOWDashboard', 'New-AutomateNOWDataSource', 'New-AutomateNOWDefaultProcessingTitle', 'New-AutomateNOWDesignTemplate', 'New-AutomateNOWDomain', 'New-AutomateNOWEndpoint', 'New-AutomateNOWEvent', 'New-AutomateNOWFolder', 'New-AutomateNOWLock', 'New-AutomateNOWMetric', 'New-AutomateNOWMigrationImport', 'New-AutomateNOWNotificationChannel', 'New-AutomateNOWNotificationGroup', 'New-AutomateNOWNotificationMessageTemplate', 'New-AutomateNOWPhysicalResource', 'New-AutomateNOWProcessingFunction', 'New-AutomateNOWProcessingState', 'New-AutomateNOWResultMapping', 'New-AutomateNOWResultMappingRule', 'New-AutomateNOWResultMappingRuleCondition', 'New-AutomateNOWResultMappingRuleConditionCriteria', 'New-AutomateNOWRuntimeAction', 'New-AutomateNOWScheduleTemplate', 'New-AutomateNOWSecurityRole', 'New-AutomateNOWSecUser', 'New-AutomateNOWSemaphore', 'New-AutomateNOWServerDayTimestamp', 'New-AutomateNOWServerNode', 'New-AutomateNOWServerNodeGroup', 'New-AutomateNOWServiceManagerTemplate', 'New-AutomateNOWStock', 'New-AutomateNOWTag', 'New-AutomateNOWTaskTemplate', 'New-AutomateNOWTimeWindow', 'New-AutomateNOWVariable', 'New-AutomateNOWWorkflowTemplate', 'New-AutomateNOWWorkspace', 'Pop-AutomateNOWApprovalRule', 'Pop-AutomateNOWDashboard', 'Pop-AutomateNOWLoadBalancerNode', 'Pop-AutomateNOWResultMappingRule', 'Pop-AutomateNOWServerNodeEndpoint', 'Pop-AutomateNOWServerNodeGroupItem', 'Protect-AutomateNOWEncryptedString', 'Publish-AutomateNOWCodeRepository', 'Push-AutomateNOWApprovalRule', 'Push-AutomateNOWDashboard', 'Push-AutomateNOWLoadBalancerNode', 'Push-AutomateNOWResultMappingRule', 'Push-AutomateNOWServerNodeEndpoint', 'Push-AutomateNOWServerNodeGroupItem', 'Read-AutomateNOWAgentServerNode', 'Read-AutomateNOWBusinessViewItem', 'Read-AutomateNOWCodeRepositoryItem', 'Read-AutomateNOWDashboardPortlet', 'Read-AutomateNOWDataSourceItem', 'Read-AutomateNOWIcon', 'Read-AutomateNOWProcessingEventLog', 'Read-AutomateNOWProcessingStateItem', 'Read-AutomateNOWResourceAnomaly', 'Read-AutomateNOWScheduleTemplateItem', 'Read-AutomateNOWSecurityAccessToken', 'Read-AutomateNOWSecurityRoleDomain', 'Read-AutomateNOWSecurityRoleUser', 'Read-AutomateNOWServerNodeAgent', 'Read-AutomateNOWServerNodeEndpoint', 'Read-AutomateNOWServerNodeGroupItem', 'Read-AutomateNOWServiceManagerTemplateDependency', 'Read-AutomateNOWServiceManagerTemplateItem', 'Read-AutomateNOWTimeTrigger', 'Read-AutomateNOWWorkflowTemplateDependency', 'Read-AutomateNOWWorkflowTemplateItem', 'Receive-AutomateNOWCodeRepository', 'Register-AutomateNOWProcessingState', 'Remove-AutomateNOWAdhocReport', 'Remove-AutomateNOWAgent', 'Remove-AutomateNOWAnomaly', 'Remove-AutomateNOWApproval', 'Remove-AutomateNOWApprovalRule', 'Remove-AutomateNOWBusinessView', 'Remove-AutomateNOWBusinessViewItem', 'Remove-AutomateNOWCalendar', 'Remove-AutomateNOWCodeRepository', 'Remove-AutomateNOWCodeRepositoryBranch', 'Remove-AutomateNOWCodeRepositoryItem', 'Remove-AutomateNOWCodeRepositoryTag', 'Remove-AutomateNOWDashboard', 'Remove-AutomateNOWDashboardPortlet', 'Remove-AutomateNOWDataSource', 'Remove-AutomateNOWDataSourceItem', 'Remove-AutomateNOWDeletedObject', 'Remove-AutomateNOWDesignTemplate', 'Remove-AutomateNOWDomain', 'Remove-AutomateNOWEndpoint', 'Remove-AutomateNOWEvent', 'Remove-AutomateNOWFolder', 'Remove-AutomateNOWLoadBalancerNode', 'Remove-AutomateNOWLock', 'Remove-AutomateNOWMenuCustomization', 'Remove-AutomateNOWMetric', 'Remove-AutomateNOWMigrationImport', 'Remove-AutomateNOWNotification', 'Remove-AutomateNOWNotificationChannel', 'Remove-AutomateNOWNotificationGroup', 'Remove-AutomateNOWNotificationGroupMember', 'Remove-AutomateNOWNotificationMessageTemplate', 'Remove-AutomateNOWPhysicalResource', 'Remove-AutomateNOWProcessingFunction', 'Remove-AutomateNOWProcessingState', 'Remove-AutomateNOWResourceAnomaly', 'Remove-AutomateNOWResultMapping', 'Remove-AutomateNOWResultMappingRule', 'Remove-AutomateNOWRuntimeAction', 'Remove-AutomateNOWSchedule', 'Remove-AutomateNOWScheduleTemplate', 'Remove-AutomateNOWScheduleTemplateItem', 'Remove-AutomateNOWSecurityAccessToken', 'Remove-AutomateNOWSecurityRole', 'Remove-AutomateNOWSecurityRoleDomain', 'Remove-AutomateNOWSecurityRoleUser', 'Remove-AutomateNOWSecUser', 'Remove-AutomateNOWSemaphore', 'Remove-AutomateNOWServerNode', 'Remove-AutomateNOWServerNodeEndpoint', 'Remove-AutomateNOWServerNodeGroup', 'Remove-AutomateNOWServerNodeGroupItem', 'Remove-AutomateNOWServiceManager', 'Remove-AutomateNOWServiceManagerTemplate', 'Remove-AutomateNOWServiceManagerTemplateDependency', 'Remove-AutomateNOWServiceManagerTemplateItem', 'Remove-AutomateNOWStock', 'Remove-AutomateNOWTag', 'Remove-AutomateNOWTask', 'Remove-AutomateNOWTaskTemplate', 'Remove-AutomateNOWTimeTrigger', 'Remove-AutomateNOWTimeWindow', 'Remove-AutomateNOWUserReport', 'Remove-AutomateNOWVariable', 'Remove-AutomateNOWViewSetup', 'Remove-AutomateNOWWorkflow', 'Remove-AutomateNOWWorkflowTemplate', 'Remove-AutomateNOWWorkflowTemplateDependency', 'Remove-AutomateNOWWorkflowTemplateItem', 'Remove-AutomateNOWWorkspace', 'Rename-AutomateNOWAdhocReport', 'Rename-AutomateNOWAgent', 'Rename-AutomateNOWAnomaly', 'Rename-AutomateNOWApproval', 'Rename-AutomateNOWBusinessView', 'Rename-AutomateNOWCalendar', 'Rename-AutomateNOWDashboard', 'Rename-AutomateNOWDataSource', 'Rename-AutomateNOWDesignTemplate', 'Rename-AutomateNOWDomain', 'Rename-AutomateNOWEndpoint', 'Rename-AutomateNOWEvent', 'Rename-AutomateNOWLock', 'Rename-AutomateNOWMetric', 'Rename-AutomateNOWNotificationChannel', 'Rename-AutomateNOWNotificationGroup', 'Rename-AutomateNOWNotificationMessageTemplate', 'Rename-AutomateNOWPhysicalResource', 'Rename-AutomateNOWProcessingFunction', 'Rename-AutomateNOWResultMapping', 'Rename-AutomateNOWScheduleTemplate', 'Rename-AutomateNOWSecurityRole', 'Rename-AutomateNOWSemaphore', 'Rename-AutomateNOWServerNode', 'Rename-AutomateNOWServerNodeGroup', 'Rename-AutomateNOWServiceManagerTemplate', 'Rename-AutomateNOWStock', 'Rename-AutomateNOWTaskTemplate', 'Rename-AutomateNOWTimeWindow', 'Rename-AutomateNOWUserReport', 'Rename-AutomateNOWVariable', 'Rename-AutomateNOWViewSetup', 'Rename-AutomateNOWWorkflowTemplate', 'Rename-AutomateNOWWorkspace', 'Reset-AutomateNOWJWTIssuerToken', 'Resolve-AutomateNOWCodeRepository', 'Resolve-AutomateNOWMonitorType2ServerNodeType', 'Resolve-AutomateNOWObject2TableName', 'Resolve-AutomateNOWSensorType2ServerNodeType', 'Resolve-AutomateNOWTaskType2ServerNodeType', 'Restart-AutomateNOWSchedule', 'Restart-AutomateNOWServiceManager', 'Restart-AutomateNOWTask', 'Restart-AutomateNOWWorkflow', 'Restore-AutomateNOWDeletedObject', 'Restore-AutomateNOWObjectVersion', 'Resume-AutomateNOWDomain', 'Resume-AutomateNOWSchedule', 'Resume-AutomateNOWScheduleTemplate', 'Resume-AutomateNOWServerNode', 'Resume-AutomateNOWServiceManager', 'Resume-AutomateNOWServiceManagerTemplate', 'Resume-AutomateNOWTask', 'Resume-AutomateNOWTaskTemplate', 'Resume-AutomateNOWTimeTrigger', 'Resume-AutomateNOWWorkflow', 'Resume-AutomateNOWWorkflowTemplate', 'Save-AutomateNOWDataSourceItem', 'Save-AutomateNOWDeletedDomain', 'Save-AutomateNOWMigrationImport', 'Select-AutomateNOWCodeRepositoryBranch', 'Select-AutomateNOWCodeRepositoryTag', 'Send-AutomateNOWAgentConfiguration', 'Send-AutomateNOWCodeRepository', 'Set-AutomateNOWAdhocReport', 'Set-AutomateNOWAgent', 'Set-AutomateNOWAnomaly', 'Set-AutomateNOWApproval', 'Set-AutomateNOWBusinessView', 'Set-AutomateNOWCodeRepository', 'Set-AutomateNOWContextVariable', 'Set-AutomateNOWDashboard', 'Set-AutomateNOWDataSource', 'Set-AutomateNOWDesignTemplate', 'Set-AutomateNOWDomain', 'Set-AutomateNOWEndpoint', 'Set-AutomateNOWEvent', 'Set-AutomateNOWFolder', 'Set-AutomateNOWLock', 'Set-AutomateNOWMetric', 'Set-AutomateNOWNotificationChannel', 'Set-AutomateNOWNotificationGroup', 'Set-AutomateNOWNotificationGroupMember', 'Set-AutomateNOWNotificationMessageTemplate', 'Set-AutomateNOWPhysicalResource', 'Set-AutomateNOWProcessingFunction', 'Set-AutomateNOWRuntimeAction', 'Set-AutomateNOWScheduleTemplate', 'Set-AutomateNOWSecurityRole', 'Set-AutomateNOWSecurityRoleDomain', 'Set-AutomateNOWSecUser', 'Set-AutomateNOWSecUserPassword', 'Set-AutomateNOWSemaphore', 'Set-AutomateNOWSemaphoreTimestamp', 'Set-AutomateNOWServerNode', 'Set-AutomateNOWServerNodeEndpoint', 'Set-AutomateNOWServerNodeGroup', 'Set-AutomateNOWServiceManagerTemplate', 'Set-AutomateNOWServiceManagerTemplateItem', 'Set-AutomateNOWStock', 'Set-AutomateNOWTag', 'Set-AutomateNOWTaskTemplate', 'Set-AutomateNOWTimeTrigger', 'Set-AutomateNOWTimeWindow', 'Set-AutomateNOWUserReport', 'Set-AutomateNOWVariable', 'Set-AutomateNOWVariableTimestamp', 'Set-AutomateNOWWorkflowTemplate', 'Set-AutomateNOWWorkflowTemplateItem', 'Set-AutomateNOWWorkspace', 'Show-AutomateNOWCodeRepositoryConflictItemComparison', 'Show-AutomateNOWEndpointType', 'Show-AutomateNOWTaskTemplateType', 'Skip-AutomateNOWSchedule', 'Skip-AutomateNOWScheduleTemplate', 'Skip-AutomateNOWServerNode', 'Skip-AutomateNOWServiceManager', 'Skip-AutomateNOWServiceManagerTemplate', 'Skip-AutomateNOWTask', 'Skip-AutomateNOWTaskTemplate', 'Skip-AutomateNOWTimeTrigger', 'Skip-AutomateNOWWorkflow', 'Skip-AutomateNOWWorkflowTemplate', 'Start-AutomateNOWEvent', 'Start-AutomateNOWScheduleTemplate', 'Start-AutomateNOWServerNode', 'Start-AutomateNOWServiceManagerTemplate', 'Start-AutomateNOWTaskTemplate', 'Start-AutomateNOWWorkflowTemplate', 'Stop-AutomateNOWSchedule', 'Stop-AutomateNOWServerNode', 'Stop-AutomateNOWServiceManager', 'Stop-AutomateNOWTask', 'Stop-AutomateNOWWorkflow', 'Suspend-AutomateNOWDomain', 'Suspend-AutomateNOWSchedule', 'Suspend-AutomateNOWScheduleTemplate', 'Suspend-AutomateNOWServerNode', 'Suspend-AutomateNOWServiceManager', 'Suspend-AutomateNOWServiceManagerTemplate', 'Suspend-AutomateNOWTask', 'Suspend-AutomateNOWTaskTemplate', 'Suspend-AutomateNOWTimeTrigger', 'Suspend-AutomateNOWWorkflow', 'Suspend-AutomateNOWWorkflowTemplate', 'Switch-AutomateNOWDomain', 'Sync-AutomateNOWCodeRepository', 'Sync-AutomateNOWDomainResource', 'Sync-AutomateNOWDomainServerNode', 'Test-AutomateNOWSecUserPassword', 'Trace-AutomateNOWProcessing', 'Unlock-AutomateNOWSecUser', 'Unprotect-AutomateNOWEncryptedString', 'Unpublish-AutomateNOWCodeRepository', 'Unregister-AutomateNOWProcessingState', 'Update-AutomateNOWCodeRepositoryObjectSource', 'Update-AutomateNOWSchedule', 'Update-AutomateNOWServiceManager', 'Update-AutomateNOWTask', 'Update-AutomateNOWToken', 'Update-AutomateNOWWorkflow', 'Wait-AutomateNOWProcessing', 'Write-AutomateNOWIconData' ) #For performance, list functions explicitly

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
