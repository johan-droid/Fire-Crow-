# FireCrow Security Audit Report

## Identity

- Audit ID: scan-report-1
- Execution ID: exec-1
- Attempt: 1
- Repository: https://github.com/acme/widget
- Branch: main
- Snapshot: 0123456789abcdef0123456789abcdef01234567
- Files analyzed: 8
- Snapshot size (bytes): 4096
- Coverage state: FAILED
- Canonical schema version: 1
- Report schema version: 1

## Executive Summary

Coverage is incomplete: gitleaks (failed), osv (failed).

- Findings: 0
- Invalid findings: 0
- Duplicate groups: 0
- Security score: unavailable because scan coverage is incomplete. A partial scan cannot be scored; the missing value is not zero.

### Findings by severity

- (none)

### Findings by scanner

- (none)

## Coverage

- Status: partial
- Complete: no
- Successful scanners: semgrep
- Unsuccessful scanners: gitleaks (failed), osv (failed)

### Limitations

- scanner gitleaks did not analyze the repository (failed)
- scanner osv did not analyze the repository (failed)

## Findings (0)

No findings were reported.

## Notices

- This report presents a frozen canonical audit. Generating it ran no scanners, accessed no repository, and called no AI service.
- A missing or &quot;unknown&quot; value means the scanner did not report it; it is never inferred or defaulted here.
- Remediation text is guidance suggested by the scanner or platform; it is not a verified fact about the repository.

