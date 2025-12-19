# AutomateNOW PowerShell Module - Code Review Guidelines
**Last Updated:** December 7, 2025  
**Module Version:** 1.0.42

## Overview
This PowerShell module aims to provide a comprehensive command-line interface for the AutomateNOW! automation platform. It contains 583+ functions across 104,000+ lines of code, enabling automation scripting, pipeline integration, and programmatic control of most platform resources.

---

## Intentional Design Decisions

### ✅ ValidateSet IgnoreCase = $false (Required Pattern)
**Status:** Intentional and Required  
**Instances:** 47 throughout the module  
**Reason:** The AutomateNOW! API is strictly case-sensitive on all endpoints. All `ValidateSet` attributes use `IgnoreCase = $false` to prevent case-mismatch errors when communicating with the API.

**Example:**
```powershell
[ValidateSet('ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE', IgnoreCase = $false)]
```

**Do Not:**
- Suggest removing `IgnoreCase = $false`
- Recommend case-insensitive validation
- Flag this as inconsistent or unnecessary

**Context:** Even seemingly user-friendly values (time zones, colors, status codes) must match the exact casing expected by the API. Any deviation causes API rejection.

---

### ✅ Region Markers (#region / #endregion)
**Status:** Standardized  
**Format:** Lowercase `#region` and `#endregion` used consistently  
**Reason:** Provides code organization for large function sets (583+ functions)

**API Category Labels:** Some regions include uppercase API category names in parentheses (e.g., `#region - Calendar (RESOURCE)`) to help correlate objects with their underlying API categories. For example, a Calendar is categorized as a RESOURCE within the AutomateNOW! API.

---

### ✅ Extensive Comment-Based Help
**Status:** Required for all exported functions  
**Reason:** Module is designed for public consumption; comprehensive documentation ensures usability

---

### ✅ Try/Catch Error Handling
**Status:** Required for all API calls  
**Reason:** Provides graceful error handling and meaningful error messages for API failures

---

## Code Quality Standards

### Required Patterns
- ✅ Comment-based help documentation (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`) for all exported functions
- ✅ Try/Catch blocks for all API calls and error-prone operations
- ✅ Comprehensive parameter validation (`[ValidateNotNullOrEmpty()]`, `[ValidateSet()]`, etc.)
- ✅ Consistent parameter naming across similar functions
- ✅ Proper use of `[CmdletBinding()]` with appropriate parameter sets

### Acceptable Patterns
- ✅ **Documented bugs:** Known issues documented with `# BUG:` or `# KNOWN ISSUE:` are acceptable when vendor-related or awaiting API fixes
- ✅ **Incomplete API Documentation:** Comments indicating `(MISSING DOCUMENTATION)` or similar are acceptable when:
  - The AutomateNOW! API Swagger definition is incomplete or unpublished for certain endpoints
  - The module implements functionality based on observed API behavior pending official documentation
  - Example: Migration-related enums may be marked as incomplete until vendor publishes full Swagger specification
  - These annotations help track areas requiring future updates when vendor documentation becomes available
- ✅ **Vendor API Typos:** The AutomateNOW! API contains typos that must be preserved for compatibility:
  - **Enum values:**
    - `GPRC` (should be `GRPC`) in `ANOWAgent_openTelemetryExporterType`
    - `GOOGLE_COULD_STORAGE_BUCKET` (should be `GOOGLE_CLOUD_STORAGE_BUCKET`) in `ANOWEndpoint_endpointType`
  - **Property/parameter names:**
    - `tenatId` (should be `tenantId`) - misspelling of "tenant" appears throughout API responses and must be used exactly as provided
  - These typos exist in the vendor's API and cannot be corrected in the module without breaking API compatibility
- ✅ **Write-Host for Visual-Only Output:** `Write-Host` is acceptable when:
  - The function's primary purpose is visual display for human consumption (not data processing)
  - Multi-color formatting on a single line requires `-NoNewline` parameter (unavailable in other cmdlets)
  - The output is explicitly designed for console viewing (e.g., `Show-AutomateNOWCodeRepositoryConflictItemComparison`)

---

## API Integration Context

### Error Handling Philosophy
- API errors should be caught and translated into meaningful PowerShell exceptions
- Network errors should be caught and provide troubleshooting guidance
- Authentication failures should provide clear next steps

---

## File Organization

### Structure
- **AutomateNOW.psm1:** Main module file (104,000+ lines, 583+ functions)
- **Classes.psm1:** Enum definitions and class structures
- **AutomateNOW.psd1:** Module manifest
- **Icons.ps1:** Icon code mappings for UI elements

### Region Organization
Functions are organized by function type (e.g., `#region - Authentication`, `#region - Objects`) followed by resource type (e.g., `#region - Agent`, `#region - Calendar (RESOURCE)`). Some regions include uppercase API category labels in parentheses to correlate objects with their underlying API categories.

---

## Testing Expectations

When reviewing or modifying this module:
1. ✅ Test error handling paths (network failures, authentication errors, API errors)
2. ✅ Confirm comment-based help is accurate and complete
3. ✅ Validate parameter sets work correctly and prevent invalid combinations

---

## Addressing Common Concerns

### "Why not use IgnoreCase = $true for better UX?"
**Answer:** The AutomateNOW! API rejects requests with incorrect casing. Case-insensitive validation would accept invalid values, causing runtime API errors instead of helpful parameter validation errors.

### "104,000 lines in one file is too large"
**Answer:** The current structure:
- Simplifies distribution (single .psm1 file)
- Maintains related functions together by resource type
- Has proven maintainable through region-based organization

### "Write-Host should never be used"
**Answer:** We minimize Write-Host usage to specific scenarios where it's appropriate:
- **Visual diff comparison functions** (`Show-AutomateNOWCodeRepositoryConflictItemComparison`) where multi-color formatting on single lines requires the `-NoNewline` parameter
- The function's explicit purpose is visual console output for human interpretation, not data processing
- Alternative approaches (ANSI escape sequences) would add complexity without meaningful benefit for this use case
- Usage is isolated to 13 Write-Host statements total (0.0125% of codebase) within a single specialized function
- Follows Microsoft guidance: *"Write-Host is acceptable when the sole purpose is to write colored text to the console for human viewing"*

---

## Feedback & Contributions
This document reflects API constraints and battle-tested design decisions. When proposing changes, 
please ensure they account for:
- AutomateNOW! API case-sensitivity requirements
- CLI use cases (scripting, automation, pipeline integration)
- Existing function behavior and backward compatibility

---
