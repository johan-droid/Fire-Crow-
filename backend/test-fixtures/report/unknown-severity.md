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
- Coverage state: SUCCESS_FINDINGS
- Canonical schema version: 1
- Report schema version: 1

## Executive Summary

1 finding(s) reported across 3 scanner(s).

- Findings: 1
- Invalid findings: 0
- Duplicate groups: 0
- Security score: 8.5/10

### Findings by severity

- unknown: 1

### Findings by scanner

- osv: 1

## Coverage

- Status: complete
- Complete: yes
- Successful scanners: gitleaks, osv, semgrep
- Unsuccessful scanners: (none)

### Limitations

- (none)

## Findings (1)

### 1. GHSA-unknown detection [unknown]

Detected by osv.

**Scanner:** osv (1.0.0)

**Rule:** GHSA-unknown

**Location:** `package-lock.json:1`

**Confidence:** high (scanner)

**Evidence (dependency)**:
```
GHSA-unknown affects lodash@1.0.0
```

**Suggested remediation:** Apply the vendor guidance.

## Notices

- This report presents a frozen canonical audit. Generating it ran no scanners, accessed no repository, and called no AI service.
- A missing or &quot;unknown&quot; value means the scanner did not report it; it is never inferred or defaulted here.
- Remediation text is guidance suggested by the scanner or platform; it is not a verified fact about the repository.

