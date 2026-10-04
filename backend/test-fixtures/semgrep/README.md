# Semgrep fixtures (Phase 9)

Scanned read-only by the ignored `semgrep_integration` end-to-end tests, using
the pinned ruleset in `backend/scanners/semgrep/firecrow-sast.yml`.

- `vulnerable/vuln.py` — one minimal trigger per rule family, on known lines.
  The live test asserts rule id, file, line range, severity, and the CWE /
  OWASP / confidence the rule itself supplies.
- `clean/safe.py` — the same operations written safely, to prove the ruleset
  discriminates rather than matching on the presence of an API.
- `empty/` — a tree with no analyzable files, used to prove that
  "scanned nothing" never reads as a clean scan.

## Known accepted false positive

`clean/safe.py` still reports one finding:
`ssrf-request-to-variable-url` on `urlopen(url)`.

The rule matches that call syntactically and cannot see that the host was
allowlisted two lines above. This is deliberate. Narrowing the rule to
"understand this guard" would mean missing the unguarded call, which is the
case that actually matters. The rule is therefore a **review signal**
(confidence MEDIUM), not a proof.

Consequently no test asserts "the clean fixture produces zero findings".
The live test instead asserts the **absence of the seven specific rules** the
fixture is written to exercise, which is what actually demonstrates the ruleset
discriminates. A blanket zero-finding assertion would be asserting something
the ruleset does not promise.
