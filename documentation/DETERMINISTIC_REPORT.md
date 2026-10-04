# Phase 13 — Deterministic Reporting

> A report is a **presentation** of a Canonical Audit v1. It is not another
> security-analysis engine, and it does no reasoning of its own.

The dependency direction is one-way:

```
Canonical Audit v1
        ↓
Deterministic Report Model
        ↓
   ┌────┼────┐
   ↓    ↓    ↓
 JSON  Markdown  HTML
```

Nothing downstream of the canonical audit may go back up. There is no path from
the reporter to a scanner, a repository, the network, or an AI service — so if
the AI layer is removed tomorrow, Fire Crow still produces a complete and
trustworthy report.

---

## 13.1 — Inventory of pre-existing reporting code

Phase 13 required an inventory *before* any change, so older code could not
silently become the new source of truth. This is that inventory, and what
became of each entry.

| Code | Consumed | Phase 13 disposition |
|---|---|---|
| `services/reporter.rs` | `Finding` (pre-Phase-13) | **Rewritten.** Now a pure function of `CanonicalAuditReport`. Accepts only a report model; no repository, no database, no findings query. |
| `orchestrator/mod.rs` report step | raw `ScannerResult` + aggregated findings | **Demoted.** It *produces* the canonical audit and hands it to `build_report`; it is no longer a report source. Its output is committed by `finalize_execution`, not written separately. |
| `api/routes_audit.rs` report routes | `audit_reports` table | **Kept, scoped.** Serves the persisted report; falls back to rebuilding from the execution's canonical document. Never queries findings independently. |
| `api/routes_audit.rs` email route | `SELECT * FROM audit_reports WHERE job_id=$1` | **Corrected.** It silently returned an arbitrary attempt once reports became per-execution; it now joins `audit_executions` and takes the highest `attempt_number`. |
| `services/attack_graph.rs` | `&[Finding]` | **Out of scope, unchanged.** Not the security report. Still reads findings directly. |
| `services/remediation_planner.rs` | `&[Finding]` | **Out of scope, unchanged.** Not the security report. |
| `services/llm.rs` | — | **Deliberately not wired in.** No call from any report path. |

Two entry points are therefore *not* report sources of truth and must not be
mistaken for them: the attack graph and the remediation planner. Both consume
`Finding` directly and are separate features.

---

## Report Contract

`schemas::report::CanonicalAuditReport`, version-tagged by
`REPORT_SCHEMA_VERSION` (currently `1`).

```jsonc
{
  "report_schema_version": 1,
  "identity": {
    "audit_id": "...", "execution_id": "...", "attempt_number": 2,
    "repository_url": "...", "repo_branch": "main",
    "repo_owner": "...", "repo_name": "...",
    "snapshot_commit": "…40-hex…",
    "snapshot_file_count": 12, "snapshot_total_size": 4096,
    "canonical_schema_version": 1,
    "report_schema_version": 1
  },
  "coverage": {
    "state": "SUCCESS_FINDINGS",
    "status": "complete",
    "complete": true,
    "scanner_runs": [ /* one per scanner, sorted by name */ ],
    "successful_scanners": ["gitleaks", "osv", "semgrep"],
    "unsuccessful_scanners": {},   // scanner -> status
    "limitations": []
  },
  "summary": {
    "headline": "1 finding(s) reported across 3 scanner(s).",  // facts only
    "finding_count": 1,
    "findings_by_severity": {"high": 1},
    "findings_by_scanner": {"gitleaks": 1},
    "invalid_finding_count": 0,
    "duplicate_group_count": 0,
    "security_score": 8.5           // null stays null
  },
  "findings": [ /* canonical findings, sorted by (severity, id) */ ],
  "correlations": [ /* only what the canonical audit already asserts */ ],
  "invalid_findings": [ /* quarantined, with the canonical reason */ ],
  "limitations": [],
  "disclaimers": [ /* fixed, auditable statements */ ]
}
```

### Source-of-Truth Boundary

`build_report(&CanonicalAudit, &ExecutionIdentity)` is the **only** entry point.
Its signature admits nothing else — there is no overload taking scanner output, a
repository path, an HTTP response, raw Gitleaks/OSV/Semgrep JSON, or
`AuditState`. `ExecutionIdentity` carries exactly two facts (execution id,
attempt number) and nothing more.

The renderer, `services::reporter::ReportGenerator`, is likewise a pure function
of the report model. Markdown, JSON, and HTML all derive from that one model;
none re-reads the database or re-inspects findings.
### Deterministic Rendering

Every ordering is explicit, never inherited from hash or input order:

| Output | Sort key |
|---|---|
| findings | severity rank (highest first, `unknown` last), then canonical id |
| scanner runs | scanner name |
| correlations | correlation id |
| invalid findings | id |
| limitations | sorted, then de-duplicated |
| summary maps | `BTreeMap`, so iteration is sorted by construction |

No timestamp is generated during rendering, and no UUID is minted. Rendering the
same model twice yields identical bytes; `tests/report.rs` asserts this directly,
including under deliberate input reordering.

JSON stability is asserted semantically (parsed values compared) rather than
byte-for-byte, because the serializer does not itself guarantee byte stability.

### Evidence and Remediation

Evidence is reproduced byte-for-byte as the canonical audit carries it — never
re-read from the repository, never expanded, never inferred. HTML escapes it;
Markdown does not, since escaping inside a code fence would corrupt it. A
triple-backtick run in evidence is neutralized so it cannot break out of the
fence.

Remediation is always labelled "Suggested remediation:". It is guidance, not a
verified fact, and the report's own disclaimers say so. Nothing is invented where
the canonical audit has none.

### Golden Fixtures

Ten frozen reports live in `test-fixtures/report/` (`.md` and `.json` per case):
clean, findings, partial coverage, failed scanner, dependency, SAST, secrets,
mixed all-scanners, duplicate/correlation, unknown severity. Changing any of them
is a deliberate contract change, not a cleanup.

---

## Persistence

A report is keyed by **execution**, not by job:

```
execution → canonical audit → report
```

`audit_reports.execution_id` is unique, so a retry writes its own row and can
never overwrite an earlier attempt's report. `audit_reports` is frozen once its
execution is terminal — the same guarantee Phase 12 gives findings and the
canonical document. Without that, the report was the one mutable surface left in
a finalized audit: everything else refused a post-terminal write while the
artifact a reader actually sees stayed editable.

If the report leg fails, `finalize_execution` commits the scanner findings and
the terminal status anyway. A rendering failure must never rewrite a successful
scanner execution as a scanner failure, and must never destroy evidence.

---

## API

| Route | Behaviour |
|---|---|
| `GET /api/v1/audit/job/:id/report` | Latest finalized attempt. `?format=markdown\|json\|html`. |
| `GET /api/v1/audit/job/:id/execution/:execution_id/report` | One explicit historical attempt. Unknown id is a 404, never silently resolved to the latest. |

A `running` execution is a `409`, and an execution with no canonical document is
a `409`. Neither is ever presented as a completed security report.

---

## Test Map

| File | Proves |
|---|---|
| `tests/report.rs` | The transformation is deterministic and total: coverage states, facts-only summaries, unknown/absent preserved, evidence pass-through, no raw scanner structures, byte-stable rendering, 10 goldens. No database required. |
| `tests/report_persistence.rs` | The storage half: reconstruction from PostgreSQL alone, retry isolation, terminal guards, report immutability, report-failure isolation, API surface. |
| `tests/atomic_audit_commit.rs` | Phase 12's single-commit invariant still holds with the report row included. |

---

## Remaining Risks

- **Report size.** HTML and Markdown are built in memory and stored whole. A
  repository with a very large finding count produces a large row, bounded today
  only by the canonical layer's own evidence and metadata limits.
- **Golden review is manual.** The fixtures are frozen by assertion, but the
  "reviewed by a human once" step is a process, not something the suite enforces.
- **Two non-report features still read `Finding` directly** (attack graph,
  remediation planner). They are out of Phase 13's scope and remain ungoverned by
  this contract; if either is ever presented as a security report it would need
  the same treatment.
- **Score semantics are inherited, not re-derived.** The reporter copies whatever
  was persisted. If the scoring algorithm changes, historical reports keep
  presenting the score that was true at the time — correct for auditability, but
  two reports of the same snapshot can legitimately differ.

### Coverage Handling

`CoverageState` is one of `SUCCESS_CLEAN`, `SUCCESS_FINDINGS`, `FAILED`,
`TIMEOUT`, `CANCELLED`, `NO_FILES_ANALYZED`, derived purely from the canonical
scanner runs. There is deliberately **no** conversion of a failure into a clean
result, and `NO_FILES_ANALYZED` is never rendered as clean — "the scanner looked
at nothing" is unknown coverage.

`derive_coverage_state` prefers `CANCELLED` over `TIMEOUT`, so a run that was both
cancelled and timed out is reported as the thing that actually decided it.