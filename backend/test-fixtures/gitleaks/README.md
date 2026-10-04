# Gitleaks fixture (Phase 7)

Intentionally vulnerable. Scanned read-only by the ignored
`gitleaks_integration` end-to-end test, which expects exactly one finding:

- `leaked-secret.txt` line 2, rule `aws-access-token`.

The key in `leaked-secret.txt` is the documented dummy from the AWS docs
(an `AKIA…EXAMPLE` placeholder); it matches the detector pattern but can
never authenticate anything. Do not add real credentials here, and do not
quote the key in this file otherwise the fixture yields extra findings.
