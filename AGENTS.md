# AutomateNOW development guidance

This file contains the shared repository instructions for development tools.
Start with [README.md](README.md) for installation and
[docs/USAGE.md](docs/USAGE.md) for user workflows.

## Repository layout

- Keep the distributed runtime files together at the root: AutomateNOW.psd1,
  AutomateNOW.psm1, Classes.psm1, Icons.ps1 and timezones.json.
- Keep user guides, the FAQ and command catalogue in docs/, with screenshots
  in docs/images/. Keep release history in CHANGELOG.md.
- Read the manifest for the current version and exported commands. Generate
  docs/COMMANDS.md from FunctionsToExport and the exported functions' Alias
  attributes; keep syntax and examples in built-in help and the usage guide.

## Preserve the module contracts

- Preserve strict class and enum types, parameter sets, typed pipeline output,
  and documented compatibility with Windows PowerShell 5.1 and PowerShell 7.
- Preserve existing case-sensitive validation and exact vendor field and enum
  spellings, including vendor typos. Do not rename API values for readability.
- Keep comment-based help accurate for exported functions, including parameters,
  examples, output and effects. Follow the existing resource regions and naming.
- Preserve omitted settings, WhatIf/Confirm behavior and verification with Quiet
  where implemented. Check active signatures before changing examples.
- Keep meaningful, value-safe diagnostics through the existing error-handling
  helpers. Preserve uncertain results and stop before retrying a mutation.
- Use Write-Host for intentional human display; preserve structured success
  output for commands used in pipelines.
- Treat known-issue comments and missing vendor documentation as context to
  investigate. Establish evidence before changing behavior or calling it proved.

## Review and validation

- For documentation changes, check relative links, anchors, image paths and
  catalogue accuracy. Preserve working examples unless their behavior changes.
- For runtime changes, use the maintained development workflow to select
  relevant offline checks in both supported PowerShell hosts. Record exact
  versions and results; keep prior evidence tied to its original source.
- Live calls require the user's selected instance, exact domain, identity,
  operation and targets. Documentation work does not authorize connections,
  executions, mutations, cleanup or publication.
- Keep credentials, tokens and complete authentication responses local and out
  of source, documentation, diagnostics and commits. Preserve unrelated work.
