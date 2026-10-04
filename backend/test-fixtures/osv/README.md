# OSV fixtures (Phase 8)

Each directory is a minimal repository scanned read-only by the ignored
`osv_integration` end-to-end tests. All versions are frozen; advisories for
these versions are long-standing and stable.

- `npm-vuln`: lodash 4.17.20, direct. Expect ≥1 finding (GHSA-…/CVE-2020-8203 family).
- `npm-fixed`: lodash 4.17.21, direct. Expect the GHSA-29mw-wpgm-hmr9
  finding to be gone, but *not* zero findings: 4.17.21 carries later
  advisories of its own (verified against the live database). The test asserts
  the specific advisory drops out, which is the version/range behaviour worth
  proving; a blanket "no findings" assertion would be wrong.
- `npm-transitive`: only `parent-pkg` is direct; lodash 4.17.20 is nested
  under it. Expect a lodash finding with `direct = false`.
- `npm-clean`: no dependencies. Expect SUCCESS with 0 findings.
- `cargo-vuln`: regex 1.5.1, direct. Expect ≥1 finding (GHSA-m5pq-gvj9-9vr8 / RUSTSEC-2022-0013).

No real credentials anywhere; checksums in `Cargo.lock` are dummy values
(the scanner only reads name/version).
