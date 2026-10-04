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

2 finding(s) reported across 3 scanner(s).

- Findings: 2
- Invalid findings: 0
- Duplicate groups: 0
- Security score: 7.0/10

### Findings by severity

- unknown: 2

### Findings by scanner

- osv: 2

## Coverage

- Status: complete
- Complete: yes
- Successful scanners: gitleaks, osv, semgrep
- Unsuccessful scanners: (none)

### Limitations

- (none)

## Findings (2)

### 1. GHSA-dep-1 detection [unknown]

Detected by osv.

**Scanner:** osv (1.0.0)

**Rule:** GHSA-dep-1

**Location:** `package-lock.json:1`

**Confidence:** high (scanner)

**Evidence (dependency)**:
```
GHSA-dep-1 affects lodash@1.0.0
```

**Suggested remediation:** Apply the vendor guidance.

### 2. GHSA-dep-2 detection [unknown]

Detected by osv.

**Scanner:** osv (1.0.0)

**Rule:** GHSA-dep-2

**Location:** `package-lock.json:1`

**Confidence:** high (scanner)

**Evidence (dependency)**:
```
GHSA-dep-2 affects lodash@1.0.0
```

**Suggested remediation:** Apply the vendor guidance.

## Notices

- This report presents a frozen canonical audit. Generating it ran no scanners, accessed no repository, and called no AI service.
- A missing or &quot;unknown&quot; value means the scanner did not report it; it is never inferred or defaulted here.
- Remediation text is guidance suggested by the scanner or platform; it is not a verified fact about the repository.

