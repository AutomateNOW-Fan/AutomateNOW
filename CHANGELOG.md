# Changelog

[Getting started](README.md#getting-started) · [FAQ](docs/FAQ.md) · [Usage and recipes](docs/USAGE.md) · [Command catalogue](docs/COMMANDS.md)

## 1.0.47

Released November 17, 2026.

### Compatibility

- Bumped the application model to AutomateNOW! **3.3.1.102**. The last validated
  baseline is **3.3.1.101**; v102 testing covers selected operations.
- Supports **Windows PowerShell 5.1** and **PowerShell 7**.

### Added

- Added `Show-AutomateNOWSecUserPermission` to open a Windows permissions window
  for the signed-in non-admin user. It shows cached grants, denied permissions,
  tag restrictions and granting roles without required arguments or network calls.
- Added `Add-AutomateNOWProcessingTemplateDependency` support for Semaphore,
  Time Window, Variable, Physical Resource, Metric, Event, Processing Cross and
  Workflow Item Cross conditions on Workflow template roots/items. Supports
  logical groups, nested groups and root-level Chronology conditions.
- Added `Set-AutomateNOWProcessingTemplateDependency` to edit supported state,
  value, status-code, Optional and timestamp settings. Omitted settings and
  owner/target/group placement are preserved; results are independently verified,
  including with `-Quiet`.
- Added `Set-AutomateNOWContextVariable` to update an existing variable and verify
  its full value, including long strings.
- Enhanced `Get-AutomateNOWContextVariable` with `-PreviewOnly` for lightweight
  previews. Normal reads retrieve full values when collection rows omit them.

### Fixed and enhanced

#### Workflows and templates

- Fixed `Wait-AutomateNOWProcessing` and `Trace-AutomateNOWProcessing -WaitForExecution`
  skipping READY items or stopping when an item transitions to READY. WAITING,
  READY and EXECUTING are active states until completion or timeout.
- Fixed `Trace-AutomateNOWProcessing` returning pre-wait snapshots. Results and
  context-variable filters use the latest returned state, with seen-ID traversal
  guards preserved.
- Fixed an issue with `Start-AutomateNOWTaskTemplate` and other template starts -
  generated names no longer carry across pipeline inputs. Supplied names,
  descriptions and timestamps are honored. `Start-AutomateNOWWorkflowTemplate`
  honors `-VerboseMode`; `Start-AutomateNOWScheduleTemplate` sends `-DelayedStartTime`.
- Enhanced `Start-AutomateNOWTaskTemplate -Synchronous` to return the actual task
  run. Use a Wait command when you also need to wait for completion.
- Fixed an issue with `Set-AutomateNOWTaskTemplate` and `Set-AutomateNOWWorkflowTemplate` -
  omitted settings, supported false/zero/unset values and explicit Task command
  replacements are preserved, with independent state for each pipeline input.
- Fixed an issue with `Set-AutomateNOWServiceManagerTemplate` - omitted command
  and run settings are retained.
- Fixed an issue with `Set-AutomateNOWServiceManagerTemplate` - description,
  priority and hold edits now work for SLA Service Managers with no processing command.
- Fixed an issue with `Set-AutomateNOWRuntimeAction` - caller rules are preserved
  and bulk updates build independent requests.
- Fixed an issue with `Copy-AutomateNOWTaskTemplate` and the Workflow, Service
  Manager and Schedule copy commands - destinations are verified, inherited tags
  are preserved and explicitly empty descriptions are honored. Collision lookups
  occur after confirmation.
- Fixed an issue with `Copy-AutomateNOWServerNode` and `Copy-AutomateNOWRuntimeAction` -
  empty descriptions are preserved and copied identities are verified, including
  with `-Quiet`.
- Fixed an issue with `Remove-AutomateNOWTaskTemplate` and the other template
  removal commands - in-use refusals and invalid responses no longer report
  success. Uncertain results stop later pipeline inputs.
- Fixed an issue with `Remove-AutomateNOWProcessingTemplateDependency` and
  `Remove-AutomateNOWProcessingTemplateResourceDependency` - invalid success
  responses or mismatched prerequisites stop later removals.
- Fixed an issue with Approval and Result Mapping rule edits - order, nested
  conditions and returned properties are retained. `Pop-AutomateNOWApprovalRule`
  and `Pop-AutomateNOWResultMappingRule` no longer emit an extra numeric index.
- Fixed rule serialization for zero, one or many entries. Failed aggregate
  preparation can no longer submit a partial rule removal.
- Enhanced `Set-AutomateNOWDesignTemplate` to clear descriptions with
  `-UnsetDescription` or an explicit empty `-Description`; omitting it keeps the text.
- Fixed an issue with `Add-AutomateNOWProcessingTemplateItem`,
  `Set-AutomateNOWProcessingTemplateItem` and `Remove-AutomateNOWProcessingTemplateItem` -
  response checks and task/node/endpoint state are independent per item. Corrected
  paths verify the exact identity, including with `-Quiet`.
- Fixed an issue with `Add-AutomateNOWProcessingTemplateItem` - valid simple child
  references are accepted and the returned Workflow item is retained, including
  its enriched metadata in PowerShell 5.1.
- Fixed an issue with `New-AutomateNOWProcessingState` - workflow/item ownership
  and returned context are verified, and declared status inputs are processed
  independently through the pipeline.
- Fixed an issue with `New-AutomateNOWBusinessView`, `New-AutomateNOWServerNodeGroup`
  and `New-AutomateNOWWorkspace` ignoring `-Quiet`.
- Fixed truncation of large oldValues payloads, including Unicode surrogate pairs.

#### Resources and Server Nodes

- Enhanced `Set-AutomateNOWMetric -Value` and `-UnsetValue` with exact readbacks
  and verified Metric results, including with `-Quiet`. Failed verification reports
  that the write may have succeeded.
- Fixed an issue with `Set-AutomateNOWMetric` - repeated metadata, ValueUnit, Value
  and UnsetValue updates no longer collide on a reused request key.
- Fixed an issue with `Set-AutomateNOWMetric` - threshold edits no longer inherit
  another object's bounds, compare absent bounds or lose a separate edit when
  ValueUnit is unchanged. All six threshold/bound string parameters validate Int64 values.
- Fixed an issue with `Set-AutomateNOWVariable` and `Set-AutomateNOWSemaphore` -
  omitted fresh values are preserved and matching resources are verified.
  Semaphore pipeline inputs prepare their own state; failed tag preparation
  cannot submit a partial update.
- Fixed `Set-AutomateNOWLock`, `Set-AutomateNOWStock` and
  `Set-AutomateNOWPhysicalResource` - pipeline inputs build independent requests,
  omitted fields stay unchanged, and results are verified even with `-Quiet`.
  Invalid prerequisites or responses stop later updates.
- Fixed `Set-AutomateNOWStock -TotalPermits 0` taking the metadata update route;
  zero now uses the permit-adjustment request.
- Fixed `Set-AutomateNOWStock` rejecting valid `status:0,data:[null]` permit
  acknowledgments. Permit updates verify and return an independent detailed read
  of the exact Stock, including verification with `-Quiet`. Missing, invalid or
  mismatched raw permit totals fail verification.

- Fixed an issue with `Set-AutomateNOWVariableTimestamp` returning the wrong type -
  it now returns the existing `ANOWResourceTimestampState` object.
- Enhanced synchronized Stock/Lock Add and Set operations with owner/resource
  checks and verified responses. `Add-AutomateNOWResourceAnomaly` now attaches
  the verified typed Metric.
- Fixed an issue with `Set-AutomateNOWServerNode` - ordinary metadata edits verify
  the returned identity and reject incomplete tag preparation before writing.
- Enhanced `Add-AutomateNOWServerNodeEndpoint` and `Add-AutomateNOWServerNodeGroupItem`
  to return complete typed relationships with parent details. Ordering is verified
  per parent; duplicate Group Items are refused.
- Fixed an issue with those relationship additions - `-WhatIf` sends no prerequisite
  or create requests, and ordering advances only after verified creation.
- Fixed an issue with `Set-AutomateNOWAgent` resetting omitted configuration or
  unrelated loggers.

#### Users and permissions

- Normalized comma-separated role tag names in permission reports, effective-scope
  comparisons and explanations. Names retain exact case; existing empty-scope,
  denied-grant and role-provenance behavior is preserved.
- Fixed an issue with `Set-AutomateNOWSecUser` and Unlock/Enable/Disable result
  checks, PowerShell 5.1 role/timezone enrichment and empty roles triggering an
  unscoped lookup.
- Fixed an issue with `New-AutomateNOWSecUser` - API-user password validation,
  role copying, optional phone values, leading zeroes and encoded metadata are
  handled correctly.
- Corrected user-creation password checks to accept any two of four character
  groups. API users no longer require a role-copy source; omitted phone numbers
  are no longer sent as zero. Creation honors `-WhatIf` and `-Confirm`.
- Corrected Interface/DataSource permission parameter spellings. Previous
  spellings remain aliases for existing scripts (issues #5, #6 and #8).

#### Data and context variables

- Fixed an issue with `Add-AutomateNOWDataSourceItem` - UTF-8 text, percent
  sequences, line endings and binary bytes are preserved. Generated text MIME
  types are accepted; binary creation gets an exact verification read.
- Fixed an issue with `Edit-AutomateNOWDataSourceItem` - edits require a matching
  dictionary/key-value item type and explicit replacement input. Responses are
  verified; uncertain outcomes stop later edits.
- Fixed an issue with `New-AutomateNOWContextVariable` - named, numeric and typed
  Processing targets are honored. One positive target is required; supplied
  values, array/file flags and `-Quiet` behavior are preserved.
- Fixed an issue with `Get-AutomateNOWContextVariable` - queries send the requested
  sort key and `-Ascending` direction. Name filters use JSON serialization for
  literal text, reserved characters, backslashes and Unicode.
- Fixed an issue with `ConvertFrom-AutomateNOWContextVariable` converting singleton
  JSON in PowerShell 5.1. Typed context-variable results also retain nullable file
  flags and audit fields.
- Corrected `ConvertFrom-AutomateNOWContextVariable` XML Document, Stream and String
  output types. Conversion uses the supplied Value, including an empty string,
  without substituting a preview or fetching data. Failures withhold value-bearing diagnostics.

#### Logs, queries and exports

- Fixed an issue with `Get-AutomateNOWAgentSysOutLog` and `Save-AutomateNOWAgentSysOutLog` -
  restart/node selection, pipeline state and blank filenames are handled correctly.
  Saved logs preserve text and line endings, honor relative or explicit paths and
  are verified before success is reported, including with `-NoStats`.
- Fixed an issue with `Get-AutomateNOWProcessingList` - combined predicates and
  literal/multi-tag JSON filters are preserved. Exact ProcessingList and Group
  Item reads reject ambiguous identities.
- Fixed Code Repository Branch, Conflict, OutOfSync and Tag readers, plus
  `Read-AutomateNOWServerNodeGroupItem`, to check parent identity before enriching
  results. Named repository Branch matching is case-sensitive.
- Fixed an issue with `Read-AutomateNOWServerNodeGroupItem` accepting malformed
  Group Item GUIDs - they are rejected before a request is sent.
- Fixed an issue with `Get-AutomateNOWUserReport` handling status keys that differ
  only by case, such as `FAILED` and `Failed`. Both values survive without leaking
  a handled JSON error into the caller's ErrorVariable.
- Fixed an issue with `Get-AutomateNOWDomain` filters, paging and sort order;
  `Get-AutomateNOWCommunicationNote` subject/source filters; and
  `Read-AutomateNOWProcessingTemplateAction` sorting and item-name encoding.
- Fixed an issue with `Get-AutomateNOWSecurityEventLog` defaulting to the wrong
  100-row range, `Read-AutomateNOWProcessingStateItem` paging and
  `Read-AutomateNOWProcessingLog` sending duplicate LogType criteria.
- Fixed Domain hold/resume result checks and PowerShell 5.1 timezone/endpoint
  enrichment. False/zero references no longer silently clear metadata or select a fallback.
- Fixed an issue with `Export-AutomateNOWAgent` and Service Manager, Workflow and
  TimeZone exports - selected objects are honored and pipeline inputs stay independent.
- Enhanced `Export-AutomateNOWAuditLog` CSV output to retain text and metadata while
  excluding raw oldValues/newValues/changedValues columns in both PowerShell hosts.
- Enhanced `Sync-AutomateNOWCodeRepository` with native object output for further
  processing and optional `-AsTable` presentation (issue #9).
- Fixed migration validation reporting success without a valid response.
  `-Quiet` returns True only after verified numeric-zero success.
- Corrected Server Node load-balancer and paging help examples, template-copy
  output/Quiet descriptions and Schedule copy examples.

#### Requests and diagnostics

- Fixed an issue with `Import-AutomateNOWDomainJSON` ignoring declined confirmation.
  Improved sensitive diagnostic handling in import, password, vault, DataSourceItem
  and transport failures; temporary unmanaged credential buffers are released after use.
- Fixed an issue with `Invoke-AutomateNOWAPI` - caller headers are copied, session
  headers are preserved, and binary status/GUID/zero/error responses work in PowerShell 5.1.
- Fixed an issue with `Connect-AutomateNOW` - its handled missing-session probe no
  longer leaks an internal VariableNotFound error into the caller's ErrorVariable.
- Improved Code Repository/Secret Vault credential handling and cleanup of
  temporary unmanaged password buffers, including partial failures. Selected
  credential-failure diagnostics withhold sensitive values and raw exceptions.
- Fixed PowerShell 5.1 collection/parent replacement losing typed metadata in
  repository, dependency, user, rule and processing-state results.

#### Application model and lookups

- Added v102 typed response properties for Application Configuration, Domain,
  Processing, Processing Templates/items, Server Nodes and View Setup objects,
  including propagation through the affected copy constructors.
- Added nullable `ANOWDashboard.autoRefresh` and optional Result Mapping selection
  metadata, fixing conversion failures when those response fields are present.
- Added REDSHIFT endpoint/node enum values and RDBMS task mappings, plus the
  SQS_SENSOR-to-SQS sensor mapping. Updated all affected enum declarations.
- Corrected SNMP_SENSOR's node mapping to the native empty list; lookups no
  longer return a blank node.
- Fixed task, monitor and sensor lookups in Windows PowerShell 5.1 by removing
  unsupported JSON parser arguments.

### Upgrade notes

- **Start a fresh PowerShell session after upgrading** to load the new classes.
- **Sync returns objects by default.** Use `-AsTable` for table presentation;
  `-Quiet` suppresses results and execution diagnostics. Receive pulls remote Git
  changes; Sync applies the managed checkout to live objects.
- **Force respects WhatIf.** Prerequisite reads can still occur. In wrappers,
  forward `-WhatIf:$WhatIfPreference` explicitly to the module command.
- **Quiet keeps verification enabled.** After an uncertain write or start,
  check the actual outcome before repeating it.
- **Stricter input checks:** DataSourceItem edits require a matching supported
  type and explicit replacement input. `Set-AutomateNOWSecUser -Admin` rejects
  both true and false. Context-variable creation requires one target and
  compatible array/file flags.
- **Timezone data is now `timezones.json`.** Legacy `timezones.txt` is read only
  when JSON is absent; malformed JSON reports an error. Catalogue contents are unchanged.

### Validation and known issues

- Offline validation: **8,306 cases across 53 suites in each supported host**,
  plus schema, help and source/ZIP checks.
- Native validation: cached self-permissions windows are accepted in Windows
  PowerShell 5.1 and PowerShell 7. Bounded positive and zero
  `Set-AutomateNOWStock` permit updates pass, including `-Quiet` readback checks.
- Permission-report limitation: Archive Access describes a feature grant.
  Monitoring tags can restrict archived rows even when Archive is reported as
  unrestricted or displayed as "Allowed - all tags".
- Known issues: an observed Agent process-launch limitation, and Windows
  PowerShell 5.1 custom Metric Value comparisons involving a negative minimum.

See the [usage guide](docs/USAGE.md), [FAQ](docs/FAQ.md) and
[command catalogue](docs/COMMANDS.md) for recipes and all 605 functions and 40 aliases.

## 1.0.46

### Major updates

- New Functions: `Invoke-AutomateNOWCodeRepositoryItemCommit`, `Invoke-AutomateNOWCodeRepositoryItemRollback`

- Fixed the Code Repository Git merge-conflict workflow. File-based conflicts
  are now listed, compared, and resolved through the correct
  `codeRepositoryConflict` API contract.
- `Get-AutomateNOWCodeRepositoryConflictItem` now returns the correct typed
  conflict records for Git files. The conflict model now retains the file,
  file path, simple ID, and domain class information needed by follow-on
  commands.
- `Compare-AutomateNOWCodeRepositoryConflictItem` and
  `Merge-AutomateNOWCodeRepositoryConflictItem` now distinguish ANOW-local
  content (`yours`) from remote Git branch content (`theirs`) correctly.

### Minor updates

- Removed credential-bearing and token-bearing values from authentication and
  request diagnostics. Passwords, access and refresh tokens, Authorization
  header values, clipboard authentication JSON, request bodies, and raw
  authentication responses are no longer written to verbose, debug, warning,
  or error output. Request diagnostics now contain safe metadata such as the
  method, URI, content type, header names, body presence/length, and whether a
  proxy was used.
- Added shared opaque-token validation for connection, confirmation, refresh
  prerequisites, and the API wrapper. Empty, whitespace-containing, malformed,
  or inconsistent token/header state is rejected without echoing the rejected
  value.
- Direct-credential authentication now constrains `-Key` to exactly 16 bytes
  and passes the selected key consistently through password protection and the
  authentication request helper.
- Secure-string conversion now uses a BSTR in both Windows PowerShell and
  PowerShell 7. BSTR allocation, conversion, and cleanup pass through small
  private boundaries, and `ZeroFreeBSTR` runs from `finally` after both success
  and failure so unmanaged plaintext is not left allocated.
- Authentication responses are parsed as JSON rather than matched as strings.
  Token type, lifetime, expiration, access token, and refresh token fields are
  validated independently, and malformed or partial responses fail with
  sanitized messages.
- `Connect-AutomateNOW -ReadJSONFromClipboard` now requires a usable access
  token and safely validates numeric fields with `Int64.TryParse` on both
  supported PowerShell editions. Invalid clipboard input returns without
  falling through to an interactive username/password prompt.

- Connection setup now builds a local candidate session and publishes
  `$global:anow_session` only after authentication, instance discovery, domain
  selection, timezone resolution, and user hydration all succeed. A failed
  replacement leaves the existing global session object untouched.
- Authentication and discovery locals—including user id, default domain,
  server timezone, and token-response state—are initialized explicitly and no
  longer inherit stale values from the caller or an earlier attempt.
- Instance metadata is extracted from the AutomateNOW home page with a
  quote-aware, balanced-object parser. The parser tolerates property-order,
  indentation, line-ending, nested-object, and braces-inside-string differences
  instead of depending on one exact JavaScript line format.
- Required instance discovery remains mandatory. `-SkipMOTD` suppresses only
  the welcome message and is no longer suggested as a remedy for home-page or
  instance-metadata failures.
- Non-quiet connection success returns an unformatted, safe `PSCustomObject`
  containing connection facts rather than token fragments or formatting
  objects. `-Quiet -SkipMOTD` produces no connection success object.
- License-status warnings now include the entire documented zero-through-30-day
  range, including zero days. Negative values retain the prior sentinel policy
  until the vendor contract distinguishes perpetual and expired negative
  values.
- Proxy validation now requires a clean absolute HTTP or HTTPS URI with a host
  and an explicit port from 1 through 65535. Credentials, outer whitespace,
  paths, queries, and fragments are rejected; valid IPv4 and bracketed IPv6
  proxy forms are passed to the request layer without changing certificate
  policy.

- PowerShell 7 now retains normal HTTPS certificate validation unless
  `-SkipCertificateCheck` is explicitly supplied. Proxy use no longer implies a
  certificate bypass.
- In Windows PowerShell 5.1, the temporary certificate callback is installed
  only for an explicit bypass and is always restored in `finally`, including
  when the web request throws. A request cannot leave the process-wide callback
  altered after it completes.
- The chosen certificate policy is retained in the completed session so
  authentication, instance discovery, token refresh, and later API calls use
  one consistent transport policy.

- `-Domain` remains optional during Connect bootstrap so the logged-on user's
  available and default domains can be discovered. After selection, however,
  the session is not considered domain-ready until both canonical domain fields
  contain the same exact-case value.
- Domain names are treated as case-sensitive throughout connection and domain
  switching. Available-domain membership and default-domain selection use exact
  case rather than PowerShell's default case-insensitive collection operators.
- An explicitly requested domain is now checked against the logged-on user's
  exact-case domain membership before it is placed in `header.domain` or used
  for server timezone discovery. Wrong-case and unavailable domains therefore
  fail transactionally with useful domain guidance instead of first failing a
  request under a provisional header.
- Once a domain is selected, `current_domain` and `header.domain` are updated
  together and must remain exactly equal. The incorrect legacy header key used
  by earlier switching logic is no longer written.
- Connection bootstrap first uses the local timezone catalogue while domain
  membership is unknown, then replaces it with the authoritative server
  catalogue after domain validation. Server and user timezones are resolved
  from the selected catalogue on every connection path rather than being
  inherited from ambient state.
- `Switch-AutomateNOWDomain` now requires a non-empty `-Domain` during parameter
  binding, performs only local exact-case validation, and cannot refresh a token
  or contact the server as a side effect. Successful switching updates both
  canonical domain fields atomically.

- Unix expiration conversion now uses `DateTimeOffset`. Connection timestamps
  use the documented millisecond form, while refresh compatibility accepts the
  vendor's observed seconds-or-milliseconds values.
- Tokens with one through 60 seconds remaining are treated as still valid.
  Failed connection replacement or refresh no longer destroys an existing
  session merely because it is near expiration.
- Refresh responses are fully staged and validated before any session field is
  committed. Null, malformed, partial, non-advancing, unexpected-token-type, or
  failed refresh responses preserve the prior access token, refresh token,
  Authorization header, and expiration.
- Refresh request fields are encoded through `ConvertTo-QueryString`, so
  reserved characters in a refresh token are preserved correctly in the form
  body.
- `Confirm-AutomateNOWSession` catches refresh failures and returns `True` only
  after the session is structurally valid and, when refresh was required, the
  new expiration is future-dated and strictly later than the previous value. A
  successful confirmation emits exactly one Boolean.
- Shared session validation now checks the instance, access-token and
  Authorization-header identity, refresh-token state, expiration shape and
  policy, and canonical domain consistency appropriate to each operation.
- `MaximumTokenRefreshAge` is documented and implemented as a remaining token
  lifetime threshold, defaults to 3300 seconds, and rejects negative values.
- `Update-AutomateNOWToken` retains its historical no-success-output contract,
  supports `WhatIf`, and uses sanitized terminating errors for refresh failure.
- `-Quiet` suppresses successful refresh information and verbose confirmation
  while preserving warnings for an invalid session. Help now describes this
  behavior accurately.
- Future sessions created with `-DoNotRefresh` remain valid for bounded work;
  expired or malformed expirations fail. The Unix epoch remains the explicit
  unknown-expiration sentinel for compatibility and produces a warning rather
  than being silently treated as a normal future token.

- Ordinary failure exits in Connect, Disconnect, Update, Confirm, Switch, and
  JWT issuer reset now return to the caller or raise a deliberate sanitized
  terminating error instead of using `Break` to terminate caller-owned scripts,
  loops, or switch statements.
- `Disconnect-AutomateNOW` attempts the server logout notification whenever the
  session contains the minimum request fields, even when expiration is unknown,
  and then completes the requested local session disposition.
- `-KeepSessionVariable` is honored consistently on valid, invalid, expired,
  partial, and server-notification-failure paths. Status information accurately
  reports whether the global session was retained or removed.

- `Reset-AutomateNOWJWTIssuerToken` now always routes the destructive operation
  through `ShouldProcess`. `-Force` suppresses the confirmation prompt but never
  bypasses `-WhatIf`; `-Force -WhatIf` sends no API request.
- Invalid-session, request-failure, missing-response, malformed-status, and
  nonzero-response paths return normally with sanitized diagnostics. Caller
  control flow is no longer terminated by `Break`, and response data is not
  embedded in warning or error messages.
- The command no longer converts or returns the complete application
  configuration, which can contain OAuth secrets, certificate passwords,
  messaging credentials, passphrases, and license data. Normal success returns
  only a minimal acknowledgement containing the instance, reset status, and the
  fact that API-user tokens were revoked; `-Quiet` suppresses that object.
- Help now clarifies the blast radius: resetting the JWT issuer invalidates API
  user tokens, not ordinary logged-in user sessions. No live reset is required
  to validate the command's PowerShell safety contract.

- `New-AutomateNOWCodeRepository` now returns the newly created typed
  `[ANOWCodeRepository]` object after successful creation.

- Improved Security Role safety and reliability:
  - `New-AutomateNOWSecurityRole` now supports `-WhatIf` and `-Confirm`.
  - `Set-AutomateNOWSecurityRoleDomain` now requires explicit
    `-AllowAdminDowngrade` acknowledgement before a granular update can remove
    Domain Admin access. `-Force` does not bypass this safeguard.
  - `Copy-AutomateNOWSecurityRoleDomain` now preserves Boolean permissions and
    tag-scoped permissions while omitting server-managed metadata.
  - `Add-AutomateNOWSecurityRoleUser` and
    `Remove-AutomateNOWSecurityRoleUser` now page through role assignments in
    10,000-record batches before making membership decisions.
  - `Set-AutomateNOWSecurityRole` now rejects contradictory `-LDAPMapping` and
    `-UnsetLDAPMapping` input.
  - `Set-AutomateNOWSecurityRoleDomain -AllowDesignCoreModificationTags` now
    writes the supported `designModifyTags` permission field rather than the
    non-persisting legacy field used by earlier module versions.
  - `Set-AutomateNOWSecurityRoleDomain -AllowDesignCoreModifyTags` blocks
    every explicitly bound value, including empty and null input, for the
    unsupported legacy field before an API request.
  - `designVerification` is now included in the normal Security User
    permission catalogue and effective-permission reports. `designCoreModify`
    and `taskLog` remain available only as hidden compatibility properties
    when `-IncludeUndocumented` is explicitly requested.
  - The module does not expose browser-only Design Action, Workflow Items,
    Notification, or Design Resource companion fields as public permissions.
    The Design Action and Workflow Items tag candidates did not persist on
    exact read-back; the remaining browser-only candidates are unsupported by
    product policy.
  - Domain-role reads and mutations when `-Quiet` is not used now return a safe
    typed result when ANOW supplies nested role data, a null creation date, or
    unsupported raw response fields.
  - `Read-AutomateNOWSecurityRoleDomain -Id` now has a direct-id parameter
    set that does not require a parent Security Role.
  - `Read-AutomateNOWSecurityRoleUser` removed obsolete `-ItemId` and
    now hydrates an exact assignment's role from the returned role id.
  - `New-AutomateNOWSecurityRole` treats an absent exact-id preflight as a
    normal create condition even when warning preference is `Stop`.
  - Corrected public simple-ID validation to use `A-Z` rather than the
    unintended `A-z` ASCII range. IDs containing punctuation that previously
    fell between uppercase and lowercase letters are now rejected.
- Repaired Security User permission reporting:
  `Measure-AutomateNOWSecUserPermission` now calculates per-domain effective
  access (`Denied`, `Unrestricted`, or `TagRestricted`) across Security Role
  Domain grants; supported `*Tags` selections are provenance rather than
  standalone grants. `Compare-AutomateNOWSecUserPermission` retains Boolean
  `-Basic` and adds tag-aware `-EffectiveScope`; its equality filters include
  permissions denied to both users. `Resolve-AutomateNOWSecUserPermission`
  accepts direct and pipeline input without cross-domain tag inference, and
  `Export-AutomateNOWSecUserPermission` preserves effective-scope and
  role-provenance columns. Measure and Compare explicitly reject
  instance-admin accounts because instance-wide access is not modeled.
  A selected `-PermissionList` with no effective grant now emits an empty
  success stream rather than a null record, avoiding downstream pipeline
  binding failures present in earlier module versions.
- Added optional, case-sensitive `-ConflictResolutionType 'yours'|'theirs'`
  parameters to `Receive-AutomateNOWCodeRepository` and
  `Sync-AutomateNOWCodeRepository`. The choice applies only when the initial
  Pull or Synchronize operation encounters a merge conflict; it does not
  resolve a conflict already persisted by an earlier operation.
- Corrected the `ANOWCodeRepositoryOutOfSyncItem` response model so
  `Get-AutomateNOWCodeRepositoryOutOfSyncItem` can parse the object-oriented
  identity, provenance, timestamp, and conflict metadata returned by the
  `/outOfSyncObject/read` endpoint.
- `Resolve-AutomateNOWCodeRepository` now sends the repository simple ID to
  the vendor resolve-conflicts operation and correctly processes each
  repository in a multi-item pipeline.
- Added `Connect-AutomateNOW -DoNotRefresh` for bounded work with a verified,
  non-expired token when automatic refresh is unavailable. Automatic refresh
  remains the default and is recommended for normal or long-running work.
- Repaired `Sync-AutomateNOWCodeRepository` for direct `-CodeRepository`
  invocation and multi-repository pipeline input; successful `-Quiet` calls
  remain silent apart from verbose confirmation.
- Corrected `Set-AutomateNOWVariable -Value` to include the target variable's
  required domain in the value-update request.
- `Get-AutomateNOWTimeZone -Id` now accepts time-zone identifiers containing
  underscores.
- Clarified `Publish-AutomateNOWCodeRepository`: default Publish commits
  changed items, `-ForceCommit` commits all items, and `-Force` only bypasses
  the PowerShell confirmation prompt.
- Tightened Code Repository command contracts: `Confirm-AutomateNOWCodeRepository`
  now requires a repository object; `Approve-AutomateNOWCodeRepositoryMergeRequest`
  and `Deny-AutomateNOWCodeRepositoryMergeRequest` now require an explicit
  merge-request object; named branch and merge-request lookups can select a
  requested page; and `Get-AutomateNOWCodeRepository -Id` cannot be combined
  with list filters that the endpoint would ignore.
- `Export-AutomateNOWCodeRepositoryObjectSource` now writes a tab-delimited
  `.tsv` file and preserves the supplied source object while escaping control
  characters in exported content.
- `Get-AutomateNOWCodeRepositoryObjectSource -RuntimeAction` now sends the
  Runtime Action simple ID required by the vendor source endpoint, restoring
  typed source retrieval for Runtime Actions.

## 1.0.45
### Major updates
- Bump compatibility to ANOW version _3.3.1.100_

### Minor updates
- Clarified the warning emitted by `Get-AutomateNOWAgentSysOutLog` when the task has an empty `logFileName`

## 1.0.44
### Major updates
- Bump compatibility to ANOW version _3.3.1.99 HF3_
- Documention Items are added and fully supported 📚
- `Trace-AutomateNOWProcessing` is working correctly again (again!)

### Minor updates
- Added new functions: `Add-AutomateNOWDocumentation`, `Export-AutomateNOWDocumentation`, `Read-AutomateNOWDocumentation`, `Remove-AutomateNOWDocumentation`, `Set-AutomateNOWDocumentation`
- Added new parameters `-processingStatus` and `-LogLocationType` to `Read-AutomateNOWProcessingLog`
- Added new parameters `-AsJson` to `Show-AutomateNOWEndpointType`
- Fixed an issue with `Get-AutomateNOWProcessingList` which in turn fixed an issue in `Trace-AutomateNOWProcessing`
- Fixed an issue with `Get-AutomateNOWContextVariable` that prevented it from working with some context variables
- Fixed an issue with `Save-AutomateNOWDataSourceItem` where it didn't exit cleanly when receiving a data source item of an unsupported data source type
- Fixed an issue with `Export-AutomateNOWMigration` exporting multiple objects to a single .json (`-IndividualExportFile` still worked)
- Optimized the warning that `Save-AutomateNOWAgentSysOutLog` emits when the log is not available from the Agent
- Added a guard to `Save-AutomateNOWAgentSysOutLog` for when the log file doesn't exist on the Agent
- Renamed `Get-AutomateNOWAuditLog` to `Read-AutomateNOWAuditLog`
- Removed the `-IncludeArchived` and `-OnlyArchived` parameters from `Trace-AutomateNOWProcessing` as the archive searching is implied
- Changed `Get-AutomateNOWAgentSysOutLog` to throw a warning instead of breaking when the task has an empty log filename
- Processing Template Change Requests are scheduled to be added in the next version

## 1.0.43 (Major bug-fix version)
### Major updates
- Bump compatibility to ANOW version _3.3.1.97 HF2_
- Fixed the debilitating issue "The script failed due to call depth overflow." that was introduced in 1.0.42
- `Trace-AutomateNOWProcessing` is working correctly again
- Fetching Processing Logs (e.g. AE Script Execution) is added and fully supported!
- Processing Template Resource Dependencies (i.e. the Resources tab) are added and partially supported
- Processing Template Actions (i.e. the Actions tab) are added and partially supported
- Processing Template Design Parameters (i.e. Inputs and Outputs tab) are added and partially supported

### Minor updates
- You can now "Preload" (Import) Schedule Templates
- The functions for Workflow/Service Manager Template Items have been consolidated to `*-AutomateNOWProcessingTemplateItem` (with aliases for backwards compatibility)
- The Monitor -> Overview menu selection is now supported via the -Overview parameter in `Get-AutomateNOWProcessingList`
- Tag validation now occurs for all functions (previously the coverage was about 50%)
- Fixed an issue in 1.0.42 with `Get-AutomateNOWWorkflow` where it only ever will return the first result (row)
- `Get-AutomateNOWAgentSysOutLog` will now provide advice when you pass a TRIGGER object to it by accident
- `New-AutomateNOWMigrationImport` will now inform you if you the import operation does not complete successfully

### Detailed Change Log
- Added new functions: `Add-AutomateNOWProcessingTemplateDependency`, `Add-AutomateNOWProcessingTemplateItem`, `Add-AutomateNOWProcessingTemplateResourceDependency`, `Export-AutomateNOWProcessingLog`, `Export-AutomateNOWProcessingTemplateAction`, `Export-AutomateNOWProcessingTemplateDependency`, `Export-AutomateNOWProcessingTemplateDesignParameter`, `Export-AutomateNOWProcessingTemplateItem`, `Export-AutomateNOWProcessingTemplateResourceDependency`, `Import-AutomateNOWScheduleTemplate`, `Pop-AutomateNOWProcessingTemplateAction`, `Push-AutomateNOWProcessingTemplateAction`, `Read-AutomateNOWProcessingLog`, `Read-AutomateNOWProcessingTemplateAction`, `Read-AutomateNOWProcessingTemplateDependency`, `Read-AutomateNOWProcessingTemplateDesignParameter`, `Read-AutomateNOWProcessingTemplateItem`, `Read-AutomateNOWProcessingTemplateResourceDependency`, `Remove-AutomateNOWProcessingTemplateAction`, `Remove-AutomateNOWProcessingTemplateDependency`, `Remove-AutomateNOWProcessingTemplateDesignParameter`, `Remove-AutomateNOWProcessingTemplateItem`, `Remove-AutomateNOWProcessingTemplateResourceDependency`, `Save-AutomateNOWProcessingLog`, `Set-AutomateNOWProcessingTemplateItem`, `Set-AutomateNOWProcessingTemplateResourceDependency`
- Converted functions to alias: `Add-AutomateNOWScheduleTemplateItem`, `Add-AutomateNOWServiceManagerTemplateDependency`, `Add-AutomateNOWServiceManagerTemplateItem`, `Add-AutomateNOWWorkflowTemplateDependency`, `Add-AutomateNOWWorkflowTemplateItem`, `Export-AutomateNOWScheduleTemplateItem`, `Export-AutomateNOWServiceManagerTemplateDependency`, `Export-AutomateNOWServiceManagerTemplateItem`, `Export-AutomateNOWWorkflowTemplateDependency`, `Export-AutomateNOWWorkflowTemplateItem`, `Read-AutomateNOWScheduleTemplateItem`, `Read-AutomateNOWServiceManagerTemplateDependency`, `Read-AutomateNOWServiceManagerTemplateItem`, `Read-AutomateNOWWorkflowTemplateDependency`, `Read-AutomateNOWWorkflowTemplateItem`, `Remove-AutomateNOWScheduleTemplateItem`, `Remove-AutomateNOWServiceManagerTemplateDependency`, `Remove-AutomateNOWServiceManagerTemplateItem`, `Remove-AutomateNOWWorkflowTemplateDependency`, `Remove-AutomateNOWWorkflowTemplateItem`, `Set-AutomateNOWScheduleTemplateItem`, `Set-AutomateNOWServiceManagerTemplateItem`, `Set-AutomateNOWWorkflowTemplateItem`
- Removed the token expiration check that was added to `Invoke-AutomateNOWAPI` in the previous version
- Improved pipeline support for `Select-AutomateNOWCodeRepositoryBranch` & `Remove-AutomateNOWCodeRepositoryBranch`
- Fixed an issue with `Save-AutomateNOWAgentSysOutLog` that only occurred when sending more than 1 Task across the pipeline
- Fixed an issue with `Get-AutomateNOWProcessingList` and filtering by Tags
- Fixed an issue with `Set-AutomateNOWWorkspace` and setting the Workspace Tags
- Fixed an issue with `Set-AutomateNOWViewSetup` and setting the View Setup to non-public
- Fixed an issue with a few of the `Set-*` functions and setting the Description
- Fixed an issue with `Export-AutomateNOWMigration` and the exporting of Business Views & Server Node Groups
- Fixed an issue with `Read-AutomateNOWProcessingEventLog` that prevented it from working as expected
- Fixed an issue with `Read-AutomateNOWAgentServerNode` that prevented it from working as expected
- Fixed a minor issue with some of the `Rename-*` functions where old object was returned instead of the newly renamed object
- Fixed a minor issue with many of the `Add-*` functions where no obect was returned after a successful add operation
- Fixed a minor issue with some of the `New-*` functions where the `-Quiet` parameter was ignored
- Added parameters `-ProcessingStatus`, `-ProcessingType` and `-Overview` to `Get-AutomateNOWProcessingList`
- Added parameter `-AsJson` to `Show-AutomateNOWEndpointType`
- Added parameter `-All` to `Export-AutomateNOWTimeZone`
- Removed parameter `-timeTriggerType` from `Set-AutomateNOWTimeTrigger` as it was superfluous
- Fixed many small inconsequential cosmetic errors within the module error messages

## 1.0.42
### Major updates
- A `copilot-instructions.md` file is now included with this project (defensive documentation 🛡️)
- Importing and Exporting Domain JSON is added and fully supported
- All 5 types of Secret Vaults 🔒 are added and partially supported
- You can now easily write to disk 💾 each of the sysout logs from restarted Tasks (including round-robin)
- Bump compatibility to ANOW version _3.3.1.95 HF2_

### Minor updates
- A code repository object is no longer required for `Compare-AutomateNOWCodeRepositoryConflictItem` (improves pipeline capability)
- When auditing a users security roles, you can now specify a limited array of permissions to check
- Added filtering options to `Show-AutomateNOWTaskTemplateType`
- `Read-AutomateNOWWorkflowTemplateItem` no longer returns an empty object when the Workflow Template is empty
- Strengthened the filtering within `Get-AutomateNOWTask` & `Get-AutomateNOWServiceManager` to ensure correct results
- Non-domain-admins can now change the properties of an existing View

### Detailed Change Log
- Added new functions: `Add-AutomateNOWSecretVaultSecret`, `Clear-AutomateNOWSecretVaultCache`, `Copy-AutomateNOWSecretVault`, `Export-AutomateNOWDomainJSON`, `Export-AutomateNOWSecretVault`, `Get-AutomateNOWSecretVault`, `Import-AutomateNOWDomainJSON`, `New-AutomateNOWSecretVault`, `New-AutomateNOWViewSetup`, `Read-AutomateNOWIconSet`, `Read-AutomateNOWNotificationGroupMember`, `Remove-AutomateNOWSecretVault`, `Rename-AutomateNOWSecretVault`, `Set-AutomateNOWSecretVault`, `Set-AutomateNOWSecretVaultDefault`, `Set-AutomateNOWViewSetup`, `Test-AutomateNOWSecretVault`, `Write-AutomateNOWObjectVersion`
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
- Moved older Change Log entries to [README-OLD.md](#1038)
- Many tiny clean-ups & optimizations 🧹

<br/><br/>

## 1.0.38
### Major updates
- The Exporting and Saving 💾 of Data Source Items is much improved
- You can now modify the attributes of Items within Workflow Templates & Service Manager Templates
- Server Nodes can now be removed or added from Load Balancer Server Nodes
- Configuring Agent telemetry settings is now supported
- Pushing (Sending) Agent settings is now supported
- `Get-AutomateNOWAuditLog` no longer always requires domain admin rights
- Bump compatibility to ANOW version _3.3.1.90 HF2_

### Minor updates
- Central Management can now be enabled/disabled on Agents (disabling is experimental 🧪)
- You can now modify the `Run Mode` of Service Manager Templates
- You can now fetch Workflow Template Items by id, name or title (same for Service Manager Template Items)
- You can now fetch Context Variables by their name
- You can now reload (update) Tasks, Workflows, Service Managers and Schedules
- Capabilities to manage Service Manager Template Items are now on par with managing Workflow Template Items
- `Export-AutomateNOWMigration` now includes a [System.IO.FileInfo] object in the output
- `Restore-AutomateNOWObjectVersion` no longer requires a .json file
- `Get-AutomateNOWContextVariable` now accepts Processing objects as input
- Slight change to dealing with Out Of Sync (Conflict) repository items (see FAQ for more)

### Detailed Change Log
- Added new functions: `Add-AutomateNOWLoadBalancerNode`, `Add-AutomateNOWServiceManagerTemplateDependency`, `Disable-AutomateNOWAgentCentralManagement`, `Enable-AutomateNOWAgentCentralManagement`, `Get-AutomateNOWCodeRepositoryOutOfSyncItem`, `Read-AutomateNOWServiceManagerTemplateDependency`, `Remove-AutomateNOWLoadBalancerNode`, `Remove-AutomateNOWServiceManagerTemplateDependency`, `Resolve-AutomateNOWObject2TableName`, `Send-AutomateNOWAgentConfiguration`, `Set-AutomateNOWContextVariable`, `Set-AutomateNOWServiceManagerTemplateItem`, `Set-AutomateNOWWorkflowTemplateItem`, `Update-AutomateNOWSchedule`, `Update-AutomateNOWServiceManager`, `Update-AutomateNOWTask`, `Update-AutomateNOWWorkflow`
- Added the parameter `-IgnoreProcessingRegistry` to `Set-AutomateNOWWorkflowTemplate` and `Set-AutomateNOServiceManagerTemplate`
- Added the parameter `-DisableManualExecution` to `Set-AutomateNOWScheduleTemplate`
- Added the parameters `-Name` and `-Processing` to `Get-AutomateNOWContextVariable`
- Added the parameters `-Status`, `-CentralManagement` and `-IPAddress` to `Get-AutomateNOWAgent`
- Fixed an issue with `Set-AutomateNOWWorkflowTemplate` and setting the Folder
- Fixed an issue with `Add-AutomateNOWServiceManagerTemplateItem` and adding Items
- Fixed an issue with `Save-AutomateNOWDataSourceItem` and saving Local File Text Store objects to disk
- Fixed an issue with `Get-AutomateNOWProcessingList` where the `-launchedById` parameter was mandatory
- Fixed an issue with `Get-AutomateNOWContextVariable` where empty results could be included
- Fixed an issue with `Get-AutomateNOWContextVariable` when using the -Id parameter
- Fixed an issue with `Remove-AutomateNOWWorkflowTemplateItem`
- Fixed an issue with `Show-AutomateNOWTaskTemplateType`
- Removed the informational message about token expiration for users without an expiration (typically API users)
- Tiny fixes, improvements and alignments for `Set-AutomateNOWWorkflowTemplate`, `Set-AutomateNOWTaskTemplate`, `Set-AutomateNOWServiceManagerTemplate`

## 1.0.37
### Major updates
- The new endpoint _/executeProcessingSync_ is supported by way of the `-Synchronous` parameter. This means we get back the Id of the Processing Template that we want instead of the trigger id. This is particularly helpful for users with limited privileges.
- Data Source Items (binary & text files) can now easily be saved (downloaded) to disk 💾

### Minor updates
- The object id is now included in the filename for the output .json file created by `Export-AutomateNOWMigration`
- You now have the option to export multiple objects to individual .json files (in addition to the default behavior of merging them into a single .json file)
- A warning (instead of an error) will now be thrown whenever duplicate keys are detected (within the .json file payload) by `New-AutomateNOWMigrationImport`
- ConvertTo-Json will now always convert at a depth of 100 (this fixes an issue with the Start-* functions and accepting a parameter hashtable of high depth)

### Detailed Change Log
- Added new functions: `Remove-AutomateNOWMigrationImport`, `Save-AutomateNOWDataSourceItem`
- Added the parameter `-Synchronous` to `Start-AutomateNOWWorkflowTemplate`, `Start-AutomateNOWTaskTemplate`, `Start-AutomateNOWScheduleTemplate` and `Start-AutomateNOWServiceManagerTemplate`
- Added the parameters `-IndividualExportFile` and `-DoNotIncludeObjectIdInFileName` to `Export-AutomateNOWMigration`
- Added the parameter `-IgnoreProcessingRegistry` to `Set-AutomateNOWTaskTemplate`
- Added pipeline input for sending .json files to `New-AutomateNOWMigrationImport`
- Fixed an issue with `Start-AutomateNOWEvent` that prevented it from returning the result
- Fixed an issue with `Trace-AutomateNOWProcessing` not being able to perform deep searches

## 1.0.36
### Major updates
+ You can now reconstitute 🍊 previous versions of an object from the Audit Log (see `Restore-AutomateNOWObjectVersion`)
+ You can now search the Audit Log by specific object id or table name
+ You can now fetch a specific item from a Data Source by its key or filename
+ Migration Imports are added and fully supported ✅
+ Support for HTTP proxies
+ Bump compatibility to ANOW version _3.3.1.89 HF1_

### Minor updates
- All Applicable Set-* functions will now output their object type by default (use -Quiet to suppress this)
- All applicable Set-* functions now support adding/removing to Code Repositories
- Modifying Server Nodes is _partially_ supported 🔰

### Detailed Change Log
- Added new functions: `Confirm-AutomateNOWMigrationImport`, `Export-AutomateNOWMigrationImport`, `Get-AutomateNOWMigrationImport`, `New-AutomateNOWMigrationImport`, `Restore-AutomateNOWObjectVersion`, `Save-AutomateNOWMigrationImport`, `Set-AutomateNOWServerNode`
- Fixed an issue with `New-AutomateNOWFolder` being unable to create the Folder
- Fixed an issue with `Add-AutomateNOWScheduleTemplateItem` and not being able to return back the updated Schedule Template Item
- Fixed an issue with `Remove-AutomateNOWScheduleTemplateItem` that prevented the removal from happening
- Fixed an issue with `Disconnect-AutomateNOW` the prevented it from disconnecting from insecure instances
- Fixed an issue where `Trace-AutomateNOWProcessing` would still return back the 128-character "preview value" of Context Variables
- Fixed an issue where `Get-AutomateNOWSecUser` would fail if a user with a clientId was encountered
- Fixed an issue with `Read-AutomateNOWServiceManagerTemplateItem` and reading Service Manager Template Items
- Fixed another issue with `Get-AutomateNOWSecUser` encountering non-Gregorian date values in a user's passwordValidUntil property
- Added some missing parameters to `Set-AutomateNOWWorkspace` and re-organized the parameter sets
- Added the `-Proxy` parameter to `Connect-AutomateNOW`
- Added the `-Quiet` parameter to most Set-* functions and set the OutputType of the function
- Added the `-Key`, `-Value` and `-Filename` parameters to `Read-AutomateNOWDataSourceItem`
- Added the `-TableName` and `-ObjectId` parameters to `Get-AutomateNOWAuditLog`
- Added the `-Length` parameter to `New-WebkitBoundaryString`
- Removed the `-All` parameter from `Read-AutomateNOWDataSourceItem`
- Renamed the parameter `-Count` to `-Sum` for `Find-AutomateNOWObjectReferral`
- Added a workaround for when the API sends byte streams when it is not expected (a scenario that occurs when downloading some types of Migration Import files)
- Repaired the in-line help for `Write-AutomateNOWIconData`
- Added tiny fixes and aligned `Set-AutomateNOWTag`, `Set-AutomateNOWBusinessView`, `Set-AutomateNOWFolder`

## 1.0.35

### Major updates
+ Big improvements with `Trace-AutomateNOWProcessing`
+ The Wait-* functions were consolidated to a single function
+ Migrations (exports only) are added and fully supported ✅
+ Trigger Logs are added and fully supported ✅
+ The ANOW Recycle Bin 🗑️ (i.e. deleted objects) is added and fully supported ✅
+ Agent Server Node objects are added and fully supported ✅
+ Deleted Domains are added and fully supported ✅
+ Design Templates are added and fully supported ✅
+ Processing Template Dependencies are added and _partially_ supported (experimental 🧪)
+ Menu Customizations are added and _partially_ supported 🔰
+ Views (a.k.a. View Setups) are added and _partially_ supported 🔰
+ The menu functionality 👉 **Processing Templates** is now available with `Get-AutomateNOWProcessingTemplate`
+ Bump compatibility to ANOW version _3.3.1.89_

### Minor updates
- Internal Security Roles are now accessible
- Workflow Template Items can now be fetched directly by name
- Processing Templates can now be fetched by the name of its Workspace
- Code Repositories can now be added/removed from Task Templates, Workflow Templates, Data Sources and Tags

### Detailed Change Log
- Added new functions: `Add-AutomateNOWWorkflowTemplateDependency`,  `Copy-AutomateNOWDesignTemplate`,  `Copy-AutomateNOWViewSetup`,  `Export-AutomateNOWAgentServerNode`,  `Export-AutomateNOWDeletedDomain`,  `Export-AutomateNOWDeletedObject`,  `Export-AutomateNOWDesignTemplate`,  `Export-AutomateNOWMenuCustomization`,  `Export-AutomateNOWMigration`,  `Export-AutomateNOWProcessingTriggerLog`,  `Export-AutomateNOWViewSetup`,  `Get-AutomateNOWDeletedDomain`,  `Get-AutomateNOWDeletedObject`,  `Get-AutomateNOWDesignTemplate`,  `Get-AutomateNOWMenuCustomization`,  `Get-AutomateNOWProcessingTemplate`,  `Get-AutomateNOWProcessingTriggerLog`,  `Get-AutomateNOWViewSetup`,  `Mount-AutomateNOWAgentServerNode`,  `New-AutomateNOWDesignTemplate`,  `Read-AutomateNOWAgentServerNode`,  `Read-AutomateNOWServerNodeAgent`,  `Read-AutomateNOWWorkflowTemplateDependency`,  `Remove-AutomateNOWDeletedObject`,  `Remove-AutomateNOWDesignTemplate`,  `Remove-AutomateNOWMenuCustomization`,  `Remove-AutomateNOWViewSetup`,  `Remove-AutomateNOWWorkflowTemplateDependency`,  `Rename-AutomateNOWDesignTemplate`,  `Rename-AutomateNOWViewSetup`,  `Restore-AutomateNOWDeletedObject`,  `Save-AutomateNOWDeletedDomain`,  `Set-AutomateNOWDesignTemplate`
- Consolidated all of the Wait-* functions into a single Wait-AutomateNOWProcessing. Aliases for the previous functions still exist.
- Fixed an issue with `Read-AutomateNOWServerNodeGroupItem` that prevented it from working under Windows PowerShell
- Fixed an issue with `New-AutomateNOWTaskTemplate` that prevented some types of Tasks from being created
- Fixed an issue with `Get-AutomateNOWorkflow` where the -WorkflowTemplate parameter was ignored
- Fixed an issue with (quite a few) of the Get-* functions where receiving Id's across the pipeline didn't work. All Get functions may receive Id's across the pipeline now.
- Fixed an issue with `New-AutomateNOWCodeRepository` that prevented creation of SSH-based repositories
- Fixed an issue with `Set-AutomateNOWWorkspace` that prevented the changing of the tags
- Fixed an issue with the validating regex used in the `-iconCode` parameter on all of the functions that use that parameter
- Fixed an issue with the -Folder parameter causing an error in some of the New-* functions
- Fixed an issue with `Read-AutomateNOWDashboardPortlet` where it would unintentionally halt if the Dashboard had no portlets
- Improved the functionality of `Add-AutomateNOWWorkflowTemplateItem`
- Improved the functionality of `Trace-AutomateNOWProcessing`
- Renamed `Dismount-AutomateNOWServerNode` to `Dismount-AutomateNOWAgentServerNode`
- Added parameters `-NoHeaders` and `-IncludeAttachmentFilename` to `Invoke-AutomateNOWAPI` (to assist downloading JSON downloads)
- Added parameter `-JustGiveMeTheJSON` to `Show-AutomateNOWTaskTemplateType`
- Added parameter `-isProcessing` to `Get-AutomateNOWProcessingList` (see the in-line help)
- Added parameters `-IncludeInternalRoles` and `-OnlyInternalRoles` to `Get-AutomateNOWSecurityRole`
- Added parameter `-Workspace` to `Get-AutomateNOWProcessingTemplate`
- Added case-sensitive enforcement to the -iconCode parameter to all applicable functions
- Added pipeline capabilty to `Get-AutomateNOWProcessingList`
- Added pipeline capabilty to `Get-AutomateNOWResourceList`

## 1.0.34
### Major updates
+ All Get functions support filtering by Tags & Folder 🥳
+ The menu functionality 👉 **Processing List** is now available with `Get-AutomateNOWProcessingList`
+ The menu functionality 👉 **Resource List** is now available with `Get-AutomateNOWResourceList`
+ Processing States are added and fully supported
+ Processing Functions are added and fully supported
+ Bump compatibility to _ANOW version 3.3.1.88 HF1_

### Minor updates
+ The new Code Repository domainClass `ItemList` from Patch 87 is recognized by `Read-AutomateNOWCodeRepositoryItem`
+ Rules within an Approval can now be individually removed
+ Rules within a Result Mapping can now be removed
+ Rules within Approvals can now be re-ordered
+ Rules within Result Mappings can now be re-ordered
+ Processing States now include the parent processing template object
+ Tags can now be copied

### Detailed Change Log
- Added new functions: `Clear-AutomateNOWProcessingStateRegistry`, `Copy-AutomateNOWProcessingFunction`, `Copy-AutomateNOWTag`, `Export-AutomateNOWProcessingFunction`, `Export-AutomateNOWProcessingState`, `Get-AutomateNOWProcessingFunction`, `Get-AutomateNOWProcessingList`, `Get-AutomateNOWProcessingState`, `Get-AutomateNOWResourceList`, `New-AutomateNOWProcessingFunction`, `New-AutomateNOWProcessingState`, `Pop-AutomateNOWApprovalRule`, `Pop-AutomateNOWResultMappingRule`, `Push-AutomateNOWApprovalRule`, `Push-AutomateNOWResultMappingRule`, `Read-AutomateNOWProcessingStateItem`, `Register-AutomateNOWProcessingState`, `Remove-AutomateNOWApprovalRule`, `Remove-AutomateNOWProcessingFunction`, `Remove-AutomateNOWProcessingState`, `Remove-AutomateNOWResultMappingRule`, `Rename-AutomateNOWProcessingFunction`, `Reset-AutomateNOWJWTIssuerToken`, `Set-AutomateNOWProcessingFunction`, `Unregister-AutomateNOWProcessingState`
- Fixed an issue with `Read-AutomateNOWCodeRepositoryItem` where Server Node Group items were not recognized
- Fixed an issue with `Set-AutomateNOWRuntimeAction` where Runtime Actions without a rule definition could not be modified
- Fixed an issue with `Get-AutomateNOWResultMapping` where the definition in the returned results could be empty
- Fixed an issue with `Get-AutomateNOWResourceList` where the results would not be returned
- Fixed an ambiguous error message that could occur under `Connect-AutomateNOW` when a non-existent domain was specified
- Added the parameter `-Id` to `Read-AutomateNOWWorkflowTemplateItem`
- Added the parameter `-KeepSessionVariable` to `Disconnect-AutomateNOW`
- Removed the parameter `-All` from `Read-AutomateNOWCodeRepositoryItem` as it is now redundant with Patch 87
- Removed the parameter `-unsetRules` from `Set-AutomateNOWApproval`
- Optimized the parameter sets within `Get-AutomateNOWRuntimeAction`
- Optimized the parameter sets within `Get-AutomateNOWTask`
- Added more information to the "instance_info" object within the ANOW session variable (e.g. _apiReadDefaultMaxDataPageSize_)
- Added a custom class [ANOWReferrer] which formalizes the output of `Find-AutomateNOWObjectReferrer`

## 1.0.33
### Major updates
+ Dashboards are added and fully supported
+ Server Node Groups are added and fully supported
+ Runtime Actions are added and mostly supported (the 'Do Action' tab is missing)

### Minor updates
+ Anomalies can now be added to a Metric (i.e. to create a Resource Anomaly object)
+ All 5 types of Event Logs are fully supported (Agent, Domain, Node, Processing & Resource)
+ You can now pass any type of [ANOWProcessTemplate] object to the pipeline of its respective Get function
+ The last remaining object types (domain classes) have been added to Add/Remove Code Repository Item
+ The last remaining object types (domain classes) have been added to Edit Object Source Code
+ Unlocking user accounts is now supported
+ Bump compatibility to _ANOW version 3.3.1.86 HF3_

### Detailed Change Log
- Added new functions: `Add-AutomateNOWDashboardPortlet`, `Add-AutomateNOWResourceAnomaly`, `Add-AutomateNOWServerNodeGroupItem`, `Copy-AutomateNOWDashboard`, `Copy-AutomateNOWRuntimeAction`, `Copy-AutomateNOWServerNodeGroup`, `Export-AutomateNOWDashboard`, `Export-AutomateNOWRuntimeAction`, `Export-AutomateNOWServerNodeGroup`, `Get-AutomateNOWDashboard`, `Get-AutomateNOWInterface`, `Get-AutomateNOWRuntimeAction`, `Get-AutomateNOWServerNodeGroup`, `New-AutomateNOWDashboard`, `New-AutomateNOWRuntimeAction`, `New-AutomateNOWServerNodeGroup`, `Pop-AutomateNOWDashboard`, `Pop-AutomateNOWServerNodeGroupItem`, `Push-AutomateNOWDashboard`, `Push-AutomateNOWServerNodeGroupItem`, `Read-AutomateNOWDashboardPortlet`, `Read-AutomateNOWServerNodeGroupItem`, `Remove-AutomateNOWDashboard`, `Remove-AutomateNOWDashboardPortlet`, `Remove-AutomateNOWRuntimeAction`, `Remove-AutomateNOWServerNodeGroup`, `Remove-AutomateNOWServerNodeGroupItem`, `Rename-AutomateNOWDashboard`, `Rename-AutomateNOWServerNodeGroup`, `Set-AutomateNOWDashboard`, `Set-AutomateNOWRuntimeAction`, `Set-AutomateNOWServerNodeGroup`, `Unlock-AutomateNOWSecUser`
- Fixed an issue with `Get-AutomateNOWSchedule` by aligning the nullable properties within the [ANOWProcessing] class
- Fixed an issue with the GetCurrentTime() method in the [ANOWTimeZone] class. All calculations have been tested
- Fixed an issue with `Trace-AutomateNOWProcessing` that occurred if the Design Template's taskType was null
- Fixed an issue with `Get-AutomateNOWSecUser` that occurred if the accountValidUntil was null
- Fixed an issue with `Get-AutomateNOWWorkflow` where the -ProcessingStatus parameter could sometimes be ignored
- Added the parameter `-OverrideConnectionRequirement` to `Import-AutomateNOWLocalTimeZone`
- Renamed `Get-AutomateNOWProcessingEventLog` to `Read-AutomateNOWProcessingEventLog` and fixed some minor issues
- Renamed `Get-AutomateNOWTimeTrigger` to `Read-AutomateNOWTimeTrigger`
- Added the remaining object types to `Add-AutomateNOWCodeRepositoryItem`, `Get-AutomateNOWCodeRepositoryObjectSource` and `Remove-AutomateNOWCodeRepositoryItem`
- Added pipeline capability to `Protect-AutomateNOWEncryptedString` (unsecure strings only) and `Unprotect-AutomateNOWEncryptedString`
- Updated the Trace function for patch 86 where TRIGGER tasks no longer have a Task Type defined
- Optimized the Wait functions

## 1.0.32
### Major updates
+ A single command `Trace-AutomateNOWProcessing` will trace any Task, Workflow, Service Manager or Schedule (and optionally return back its Context Variables)
+ Security Roles, User Roles & Domain Roles are added and fully supported.
+ Security Access Tokens for API users are fully supported

### Minor updates
+ You can now easily convert returned context variables into a hash table (or json string) via `ConvertFrom-AutomateNOWContextVariable`
+ Tracing with the `-WaitForExecution` parameter now includes the 'WAITING' status along with 'EXECUTING'
+ You can now change the order of ServerNode Endpoint objects within a Node object
+ Bump compatibility to _ANOW version 3.3.1.85 HF1_

### Detailed Change Log
- Added new functions: `Add-AutomateNOWSecurityAccessToken`, `Add-AutomateNOWSecurityRoleDomain`, `Add-AutomateNOWSecurityRoleUser`, `ConvertFrom-AutomateNOWContextVariable`, `Copy-AutomateNOWAnomaly`, `Copy-AutomateNOWSecurityRole`, `Copy-AutomateNOWSecurityRoleDomain`, `Export-AutomateNOWAnomaly`, `Export-AutomateNOWResourceAnomaly`, `Export-AutomateNOWSecurityAccessToken`, `Export-AutomateNOWSecurityRole`, `Export-AutomateNOWSecurityRoleDomain`, `Export-AutomateNOWSecurityRoleUser`, `Export-AutomateNOWServerNodeEndpoint`, `Get-AutomateNOWAnomaly`, `Get-AutomateNOWSecurityRole`, `New-AutomateNOWAnomaly`, `New-AutomateNOWSecurityRole`, `Pop-AutomateNOWServerNodeEndpoint`, `Push-AutomateNOWServerNodeEndpoint`, `Read-AutomateNOWResourceAnomaly`, `Read-AutomateNOWSecurityAccessToken`, `Read-AutomateNOWSecurityRoleDomain`, `Read-AutomateNOWSecurityRoleUser`, `Remove-AutomateNOWAnomaly`, `Remove-AutomateNOWResourceAnomaly`, `Remove-AutomateNOWSecurityAccessToken`, `Remove-AutomateNOWSecurityRole`, `Remove-AutomateNOWSecurityRoleDomain`, `Remove-AutomateNOWSecurityRoleUser`, `Rename-AutomateNOWAnomaly`, `Rename-AutomateNOWSecurityRole`, `Set-AutomateNOWAnomaly`, `Set-AutomateNOWSecurityRole`, `Set-AutomateNOWSecurityRoleDomain`, `Set-AutomateNOWServerNodeEndpoint`, `Trace-AutomateNOWProcessing`, `Wait-AutomateNOWSchedule`
- Fixed another issue with `Get-AutomateNOWVariable` only returning preview values
- Fixed an issue with the parameter sets for `Set-AutomateNOWBusinessView`
- Corrected the usage of the `iconSet` enum in a number of places (some objects only accept two types of icons instead of three)
- Repaired some issues with `Read-AutomateNOWServiceManagerTemplateItem`
- Renamed all "User" functions to "SecUser" (e.g. `Export-AutomateNOWUser` is now `Export-AutomateNOWSecUser`)
- Renamed `Get-AutomateNOWCodeRepositoryItem` to `Read-AutomateNOWCodeRepositoryItem`
- Renamed the parameter `-InactiveUsers` to `-ActiveUsersOnly` for `Get-AutomateNOWSecUser`
- Renamed `Trace-AutomateNOWWorkflow` to `Trace-AutomateNOWProcessing` (aliases cover Schedules, Service Managers, Tasks & Workflows)
- Changed the default value of `-sortBy` from `id` to `dateCreated` within `Get-AutomateNOWSchedule`, `Get-AutomateNOWServiceManager`, `Get-AutomateNOWTask` & `Get-AutomateNOWWorkflow`
- Added the parameters `-IncludeAPIUsers` and `-APIUsersOnly` to `Get-AutomateNOWSecUser`
- Added the parameters `-startRow` and `-endRow` to `Get-AutomateNOWDomain`
- Added the parameters `-startRow` and `-endRow` to `Get-AutomateNOWFolder`
- Added the parameters `-startRow`, `-endRow` and `-AllDomains` to `Get-AutomateNOWTag`
- Added the parameter `-PreviewOnly` to `Get-AutomateNOWContextVariable`
- Added the parameter `-EventParameters` to `Start-AutomateNOWEvent`
- Added the parameter `-Folder` to `Get-AutomateNOWScheduleTemplate`, `Get-AutomateNOWServiceManagerTemplate` and `Get-AutomateWorkflowScheduleTemplate`
- Added new method `GetCurrentTime()` to [ANOWTimeZone]
- Optimzed and re-organized the **Classes.psm1** file significantly. All custom classes are clearly identified.
- Many tiny fixes and improvements to the in-line help

## 1.0.31
### Major update
+ You can now trace 🕵️‍♂️ Tasks, Workflows and ServiceManagers with `Trace-AutomateNOWWorkflow`
+ You can now include archived items 📦 with the Tasks, Workflows and Service Managers by including `-IncludeArchivedItems`
+ You can now wait ⌚ for a Task, Workflow or Service Manager by way of `Wait-AutomateNOWWorkflow`
+ You can chain together `Start-AutomateNOWWorkflow` with `Trace-AutomateNOWWorkflow` to wait for the context variables 🤯

### Minor updates
+ The CodeRepositoryOutOfSync functions have been renamed to CodeRepositoryConflict
+ Context Variables will now return the **full** value instead of the truncated "preview value"
+ Statistical duration ⌛ can now be configured (by milliseconds) for Task Templates, Schedule Templates, Service Manager Templates and Workflow Templates 🥳
+ Compatibility remains at _ANOW version 3.3.1.84_

### Detailed Change Log
- Added new functions: `Add-AutomateNOWServerNodeEndpoint`, `Add-AutomateNOWServiceManagerTemplateItem`, `Confirm-AutomateNOWServiceManagerTemplate`, `Copy-AutomateNOWServiceManagerTemplate`, `Copy-AutomateNOWUserReport`, `Edit-AutomateNOWDataSourceItem`, `Export-AutomateNOWServiceManager`, `Export-AutomateNOWServiceManagerTemplate`, `Export-AutomateNOWUserReport`, `Get-AutomateNOWServiceManager`, `Get-AutomateNOWServiceManagerTemplate`, `Get-AutomateNOWUserReport`, `New-AutomateNOWServiceManagerTemplate`, `Read-AutomateNOWServerNodeEndpoint`, `Read-AutomateNOWServiceManagerTemplateItem`, `Remove-AutomateNOWServerNodeEndpoint`, `Remove-AutomateNOWServiceManager`, `Remove-AutomateNOWServiceManagerTemplate`, `Remove-AutomateNOWServiceManagerTemplateItem`, `Remove-AutomateNOWUserReport`, `Rename-AutomateNOWServiceManagerTemplate`, `Rename-AutomateNOWUserReport`, `Resolve-AutomateNOWCodeRepository`, `Restart-AutomateNOWServiceManager`, `Resume-AutomateNOWServiceManager`, `Resume-AutomateNOWServiceManagerTemplate`, `Set-AutomateNOWServiceManagerTemplate`, `Set-AutomateNOWUserReport`, `Skip-AutomateNOWServiceManager`, `Skip-AutomateNOWServiceManagerTemplate`, `Start-AutomateNOWServiceManagerTemplate`, `Stop-AutomateNOWServiceManager`, `Suspend-AutomateNOWServiceManager`, `Suspend-AutomateNOWServiceManagerTemplate`, `Trace-AutomateNOWWorkFlow`, `Wait-AutomateNOWServiceManager`, `Wait-AutomateNOWTask`, `Wait-AutomateNOWWorkFlow`
- Renamed `Compare-AutomateNOWCodeRepositoryOutOfSyncItem` to `Compare-AutomateNOWCodeRepositoryConflictItem`
- Renamed `Get-AutomateNOWCodeRepositoryOutOfSyncItem` to `Get-AutomateNOWCodeRepositoryConflictItem`
- Renamed `Get-AutomateNOWDataSourceItem` to `Read-AutomateNOWDataSourceItem`
- Renamed `Merge-AutomateNOWCodeRepositoryOutOfSyncItem` to `Merge-AutomateNOWCodeRepositoryConflictItem`
- Renamed `Show-AutomateNOWCodeRepositoryOutOfSyncItemComparison` to `Show-AutomateNOWCodeRepositoryConflictItemComparison`
- Removed the `-Quiet` parameter from `Stop-AutomateNOWSchedule`, `Stop-AutomateNOWTask`, and `Stop-AutomateNOWWorkflow`
- Moved the 3 helper functions `Compare-ObjectProperty`, `ConvertTo-QueryString` and `New-WebkitBoundaryString` from public to private
- Added the parameters `-DelayedStartTime`, `-TimeZone` and `-VerboseMode` to `Start-AutomateNOWScheduleTemplate`, `Start-AutomateNOWServiceManagerTemplate`, `Start-AutomateNOWTaskTemplate`, `Start-AutomateNOWWorkflowTemplate`, `Set-AutomateNOWServiceManagerTemplate`, `Set-AutomateNOWTaskTemplate` and `Set-AutomateNOWWorkflowTemplate`
- Added the parameters `-DataType`, `-IsArray`, `-ErrorHandling` and `-Validity` to `Set-AutomateNOWDataSource`
- Added the parameter `-launchedById` to `Get-AutomateNOWWorkflow`
- Added the parameters `-IncludeArchived` and `-OnlyArchived` to `Get-AutomateNOWSchedule`, `Get-AutomateNOWTask` and `Get-AutomateNOWWorkflow`
- Added the parameter `-Id` to `Get-AutomateNOWContextVariable`
- Enforced case-sensitivity to all parameters that validate a set (mostly applies to `-sortBy`)
- Fixed an issue with `Connect-AutomateNOW` when using the `-SkipPreviousSessionCheck` parameter
- Fixed an issue with `Disconnect-AutomateNOW` (This function finally behaves the way it was intended to)
- Fixed an issue with the `-UseAutomaticName` parameter on `Start-AutomateNOWWorkflowTemplate`
- Cleaned up and updated the parameters for `New-AutomateNOWTaskTemplate`
- Clarified the error message that `Invoke-AutomateNOWAPI` will display when the ANOW API returns error for unexpected reason (e.g. unstable ANOW instance)

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

## 1.0.9
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

## 1.0.8
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

## 1.0.7
- Added new functions: `Get-AutomateNOWTask`, `Show-AutomateNOWTaskType`, `Start-AutomateNOWTask`
- Added support for transparent colors in `New-AutomateNOWTag`
- Added a requirement to use `Disconnect-AutomateNOW` before connecting to a different instance
- Added the _-Headers_ parameter to `Invoke-AutomateNOWAPI` for including additional headers (experimental)
- Incorporated `ConvertTo-QueryString` (see MSIdentityTools on the PowerShell Gallery)
- Fixed an issue with the token expiration date sometimes showing +1 hour ahead
- Fixed an issue with HTTP error hints not being shown
- Fixed an issue with the domain not being set in the header variable whenever the domain was specified with the _-Domain_ parameter of `Confirm-AutomateNOWSession`

## 1.0.6
- Added new functions: `Get-AutomateNOWWorkflow`, `Get-AutomateNOWFolder`, `New-AutomateNOWFolder`
- Added masked input to (and fixed some minor bugs with) `Connect-AutomateNOW`
- Improved guidance when http codes 401, 403 and 404 are encountered
- Fixed an issue with the usage of `Add-Type` (applies to Windows PowerShell only)
- Changed `Invoke-AutomateNOWAPI` will no longer recognize a GET request that accidentally included a body

## 1.0.5
- Fixed an issue with token updating

## 1.0.4
- Finished adding the help content with examples to each function

## 1.0.3
- Added new functions: `Import-AutomateNOWIcon`, `New-AutomateNOWTag`, `Remove-AutomateNOWTag` & `Update-AutomateNOWToken`
- Added the ability to refresh the token (See `Update-AutomateNOWToken`)
- Fixed an issue where the _-SkipCertificateCheck_ parameter was included in PowerShell 7 even when it was not needed

## 1.0.2
- Cosmetic fixes for PowerShell Gallery (again!)

## 1.0.1
- Cosmetic fixes for PowerShell Gallery

## 1.0.0
- Initial release (feedback requested)
- Compatibile with _ANOW version 3.2.1.69_
