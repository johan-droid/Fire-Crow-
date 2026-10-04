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

Coverage is incomplete: osv (failed).

- Findings: 1
- Invalid findings: 0
- Duplicate groups: 0
- Security score: unavailable because scan coverage is incomplete. A partial scan cannot be scored; the missing value is not zero.

### Findings by severity

- high: 1

### Findings by scanner

- gitleaks: 1

## Coverage

- Status: partial
- Complete: no
- Successful scanners: gitleaks, semgrep
- Unsuccessful scanners: osv (failed)

### Limitations

- scanner osv did not analyze the repository (failed)

## Findings (1)

### 1. aws-access-token detection [high]

Detected by gitleaks.

**Scanner:** gitleaks (1.0.0)

**Rule:** aws-access-token

**Location:** `config/aws.env:3`

**Confidence:** high (scanner_default)

**Evidence (secret)**:
```
AWS_ACCESS_KEY_ID=[REDACTED]
```

**Suggested remediation:** Apply the vendor guidance.

## Notices

- This report presents a frozen canonical audit. Generating it ran no scanners, accessed no repository, and called no AI service.
- A missing or &quot;unknown&quot; value means the scanner did not report it; it is never inferred or defaulted here.
- Remediation text is guidance suggested by the scanner or platform; it is not a verified fact about the repository.

