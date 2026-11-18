# Usage and recipes

[Getting started](../README.md#getting-started) · [FAQ](FAQ.md) ·
[Command catalogue](COMMANDS.md) · [Release notes](../CHANGELOG.md)

Start with the README for installation, connection and a first read. Replace
the example names, IDs, hostname and domain with your own. Examples in the
editing, starting and repository sections make changes when you run them.

## Other connection methods

The README uses interactive username/password authentication. If your organization
provides a complete native authentication response through an approved browser
workflow, copy it locally and use:

```powershell
Connect-AutomateNOW -Instance 'anow.example.org' -Domain 'YourDomain' -ReadJSONFromClipboard -Quiet
Confirm-AutomateNOWSession -Quiet -DoNotRefresh
```

This requires the complete authentication JSON, not just an access-token string.
Keep it local. A valid local session returns `True`; resolve a connection warning
before running the next command. Domain spelling is case-sensitive.

```powershell
Get-Help Connect-AutomateNOW -Full
Switch-AutomateNOWDomain -Domain 'AnotherDomain'
```

Normal token refresh happens in the connected PowerShell process. Start a new
session after changing module versions so code and loaded classes agree.

## Read a bounded page

```powershell
Get-AutomateNOWServerNode -startRow 0 -endRow 20 |
    Select-Object id, simpleId, serverNodeType

Get-AutomateNOWWorkflowTemplate -Tags 'TeamTag' -startRow 0 -endRow 20 |
    Select-Object id, title
```

These are single pages. Most collection commands default to rows 0–100, but
parameter sets and available sort/filter options differ. Check the owning
command's help before writing a paging loop. Use a stable ordering where the
command supports one, and stop if IDs repeat or page metadata contradicts the
requested range. Do not treat one full page as a complete inventory.

An exact run lookup uses a different parameter set:

```powershell
Get-AutomateNOWTask -Id 12345
Get-AutomateNOWWorkflow -Id 12346
```

## Use the pipeline and WhatIf

Typed objects carry identity and context into supported pipeline commands:

```powershell
$variable = Get-AutomateNOWVariable -Id 'ExampleVariable'
$variable | Set-AutomateNOWVariable -Description 'Updated description' -WhatIf
```

WhatIf suppresses the mutation request; prerequisite reads can still happen.
Across the reviewed paths, Force suppresses confirmation without defeating
WhatIf. When writing a wrapper, forward its local preference explicitly:

```powershell
function Set-ExampleVariableDescription {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] $Variable,
        [Parameter(Mandatory = $true)] [string] $Description
    )

    Set-AutomateNOWVariable -Variable $Variable -Description $Description -WhatIf:$WhatIfPreference
}
```

Quiet suppresses successful output according to the command's contract. It does
not disable identity checks or promised readbacks. Check each command's output
help; Quiet is not a universal Boolean-success mode.

## Start a workflow, then wait

This starts the selected template. Capture the returned run instead of searching
for it afterward:

```powershell
$template = Get-AutomateNOWWorkflowTemplate -Id 'ExampleWorkflow.WST'
$run = $template | Start-AutomateNOWWorkflowTemplate -Synchronous
$run | Wait-AutomateNOWProcessing
```

Synchronous chooses the actual-run start route; it does not wait for completion.
Name/description inputs belong to the start request or trigger and need not
become the name/description of every child run. If a start reports an uncertain
outcome, retain any returned run ID and establish its state before trying again.

For related processing and context variables, inspect the traversal options:

```powershell
Get-Help Trace-AutomateNOWProcessing -Full
```

`-DoNotIncludeTriggers` filters triggers; `-PerformDeepSearch` expands the work
and can take longer. Trace does not accept every filter exposed by Get commands.

## Read and edit context variables

```powershell
# A lightweight list of previews for an existing run:
Get-AutomateNOWContextVariable -RunId 12345 -PreviewOnly

# Full values; missing collection values can require exact detail reads:
Get-AutomateNOWContextVariable -RunId 12345
```

To update one existing variable, resolve one exact match and keep its typed object:

```powershell
$contextMatches = @(Get-AutomateNOWContextVariable -RunId 12345 -Name 'ExampleName')
if ($contextMatches.Count -ne 1) {
    throw 'Expected exactly one context variable.'
}
$contextMatches[0] | Set-AutomateNOWContextVariable -Value 'Updated value'
```

The setter verifies the full resulting value, including with Quiet. Preview
reads are useful for menus; use complete values for editing or conversion.

## Author dependency conditions

Ordinary condition creation and editing are separate from synchronized Stock/
Lock allocation. Supported ordinary Workflow root/item edits keep owner, target,
type and group placement fixed and verify an independent readback.

```powershell
Get-Help Add-AutomateNOWProcessingTemplateDependency -Examples
Get-Help Set-AutomateNOWProcessingTemplateDependency -Examples
Get-Help Add-AutomateNOWProcessingTemplateResourceDependency -Examples
```

Use the help for the selected dependency family; value, state, status-code and
timestamp options are conditional. Calculated names, existing-row reparenting
and broader owner contexts are outside the new ordinary editor's scope.

## Send live ANOW changes to a remote repository

ANOW's live objects, its managed server-side Git checkout and the external remote
repository are three different states. This example selects a branch, commits
eligible live-object changes to the managed checkout, then pushes its commits:

```powershell
$repository = Get-AutomateNOWCodeRepository -Id 'ExampleRepository'
$branch = Get-AutomateNOWCodeRepositoryBranch -CodeRepository $repository -Name 'development'
$branch | Select-AutomateNOWCodeRepositoryBranch
Publish-AutomateNOWCodeRepository -CodeRepository $repository
Send-AutomateNOWCodeRepository -CodeRepository $repository
```

Make the intended live-object edits before Publish. Default Publish commits
eligible changed items; ForceCommit has a broader meaning. Check the branch,
repository status and each result before proceeding.

## Apply remote Git changes to live ANOW objects

```powershell
$repository = Get-AutomateNOWCodeRepository -Id 'ExampleRepository'
$branch = Get-AutomateNOWCodeRepositoryBranch -CodeRepository $repository -Name 'development'
$branch | Select-AutomateNOWCodeRepositoryBranch
Receive-AutomateNOWCodeRepository -CodeRepository $repository
Sync-AutomateNOWCodeRepository -CodeRepository $repository
```

Receive pulls into ANOW's managed checkout; Sync applies/reconciles that state
with live objects. They are separate commands even if a UI workflow chains them.
Check the result and repository status after Receive before invoking Sync, and
verify the intended object metadata afterward. Sync returns native objects by
default; use AsTable only when you want formatted presentation.

## Inspect repository conflicts

```powershell
$repository = Get-AutomateNOWCodeRepository -Id 'ExampleRepository'
$outOfSync = $repository | Get-AutomateNOWCodeRepositoryOutOfSyncItem -startRow 0 -endRow 100
$conflicts = $repository | Get-AutomateNOWCodeRepositoryConflictItem -startRow 0 -endRow 100
```

OutOfSync records describe object/repository divergence; ConflictItem records
represent file-based Git conflicts. Only the latter belong in Compare/Merge
commands. Compare retrieves source; showing a comparison writes temporary files
and invokes local git diff. Inspect the exact conflict before choosing a side:

```powershell
$conflict = $conflicts | Select-Object -First 1
$comparison = $conflict | Compare-AutomateNOWCodeRepositoryConflictItem
$comparison | Show-AutomateNOWCodeRepositoryConflictItemComparison
```

For a later explicit merge, AcceptYours means ANOW's managed local version;
AcceptTheirs means the external remote branch version. These are file conflicts,
not a substitute for resolving an OutOfSync object record.

## Report account permissions

On a Windows desktop, open the signed-in non-admin user's cached permissions:

```powershell
Show-AutomateNOWSecUserPermission
```

The window includes denied permissions and waits until closed. It reads the
existing session roles; reconnect normally when those roles need updating.
For text output or CSV export, use:

```powershell
Measure-AutomateNOWSecUserPermission -Me -IncludeUndocumented -FullReport |
    Resolve-AutomateNOWSecUserPermission

Measure-AutomateNOWSecUserPermission -Me |
    Export-AutomateNOWSecUserPermission
```

FullReport includes privileges whether granted or not. Account/domain rights
still control what the server permits. See the FAQ for more command conventions,
resource details and common troubleshooting questions.

Archive Access describes the feature grant. Monitoring tags can restrict
archived rows even when Archive is reported as unrestricted or displayed as
"Allowed - all tags". A cached permission report is not an endpoint or action
authorization check.
