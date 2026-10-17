# Native scanning (docker-free execution)

Fire Crow has two scanner execution backends. This document defines what each
one actually guarantees, how to enable native mode, and what is **not** verified.

## The two modes

| | `container` (default) | `native` (opt-in) |
|---|---|---|
| How scanners run | Pinned images via the Docker daemon | Pinned binaries as hardened subprocesses |
| Needs a Docker daemon | **Yes** | **No** |
| Filesystem boundary | Container FS, `--read-only`, `--cap-drop=ALL`, `--user=65534` | None — subprocess inherits the backend's uid (`10001`) |
| Network boundary | `--network=none` / filtered proxy, kernel-enforced | **Not kernel-enforced** — flags/proxy only |
| Resource ceilings | Container cgroups | `setrlimit` (AS/CPU/FSIZE/NPROC) + `PR_SET_NO_NEW_PRIVS` |
| Suitable for Render free tier | No (no Docker-in-Docker) | Yes |

Select it with `SCANNER_EXECUTION_MODE` (`native` or `container`). Any other
value **fails startup**; unset defaults to `container`, the strongest boundary.

## Why native mode is not a container substitute

All three scanners — **gitleaks, osv-scanner, semgrep** — *parse* content
(files, lockfiles, ASTs). They never execute repository code, build steps,
package hooks, or Git hooks, in either mode. The container's job is to bound the
blast radius **around the scanner process itself** (a parser memory-safety bug, a
file crafted against the parser) and to enforce network isolation at the kernel.

Native mode keeps the *process-level* hardening but **is not equivalent to a
container or VM boundary**. What it still enforces:

- argument arrays only — never a shell, so untrusted bytes cannot become syntax;
- a cleared environment — no ambient secret/token/proxy reaches a scanner unless
  explicitly declared;
- wall-clock timeout with reliable child termination (cancellation kills the real
  process, not just a database flag);
- bounded stderr and a bounded report file;
- `setrlimit` address-space/CPU/file-size/process ceilings and `no-new-privs`;
- a per-run scratch directory removed on every exit path;
- the already-unprivileged backend uid (`10001`).

What it does **not** enforce (residual risk, stated not hidden):

- no per-process filesystem namespace — a scanner subprocess can read any file
  the backend uid can;
- no kernel-enforced network isolation — gitleaks and semgrep are invoked with
  flags that make no network calls, and osv-scanner's egress routes through the
  validated filtering proxy (`OSV_EGRESS_PROXY`), but the OS does not block a
  determined process the way `--network=none` does.

Because of that gap, native mode is **opt-in** and the console shows a
**reduced-isolation warning** at scan time. Prefer trusted repositories when
running native mode. Do not describe native mode as a container replacement.

## Scanner availability (fail-closed)

`GET /api/v1/health/deep` reports the execution model and per-scanner
availability in the `scanner` block:

```json
{
  "docker": "not_required",
  "scanner": {
    "mode": "native",
    "isolation": "process",
    "gitleaks": "available",
    "osv": "available",
    "semgrep": "unavailable"
  }
}
```

- **A missing scanner is reported `unavailable`, never silently substituted.**
  If `GITLEAKS_BIN` (etc.) points at a non-executable path, that scanner is
  unavailable — it is *not* PATH-searched for a different binary.
- A scan that runs with a scanner missing is marked **partial /
  `engine_unavailable`** in the Canonical Audit. **It is never clean.**
- The frontend gates submission on the `scanner` block (not the HTTP status) so
  a broken scanner never masquerades as a working scan.

### Which scanners native mode supports

| Scanner | Native mode | Why |
|---|---|---|
| gitleaks 8.18.4 | **Installed** in the backend image | Single small Go binary |
| osv-scanner 2.2.4 | **Installed** in the backend image | Single small Go binary; needs egress to OSV (via `OSV_EGRESS_PROXY`) |
| semgrep 1.96.0 | **Not installed** | Large Python toolchain; runtime memory exceeds the 512 MB free tier. Reported `unavailable` (partial coverage, never clean). |

Container mode runs all three as pinned images when a daemon is reachable.

## Scanner installation & version verification

`backend/Dockerfile` downloads gitleaks and osv-scanner at **build time**, pinned
to the same versions as the container images, and verifies each against its
published **SHA-256** before installing:

```
GITLEAKS_SHA256=ba6dbb656933921c775ee5a2d1c13a91046e7952e9d919f9bac4cec61d628e7d
OSV_SCANNER_SHA256=7702cd1e5d9f5059dd9570f4ad967f27d3c5f5391b371ec937b384c238177f55
```

A swapped or corrupted download fails the build (`sha256sum -c`) rather than
shipping a tampered scanner. Binaries land in `/usr/local/bin` (on `PATH`).

Override locations with `GITLEAKS_BIN` / `OSV_SCANNER_BIN` / `SEMGREP_BIN`; when
unset, each is looked up on `PATH`.

## Durable storage (fail-closed)

Storage selection is explicit; a half-configured backend never silently falls
back to local disk:

- **All four** `R2_*` values set → durable R2/S3 is used.
- **None** set → local disk, **ephemeral** (lost on restart/redeploy), logged
  loudly at startup. Acceptable for development only.
- **Some but not all** set → **startup error.**

Render's local filesystem is not durable. Do not route production artifacts to
local disk when durable storage is required.

## Free-tier reality (Render free)

- 512 MB RAM, ephemeral filesystem, spin-down/cold starts (~30–60 s wake).
- **No Docker daemon / Docker-in-Docker** → container mode is unavailable there;
  native mode is the supported path.
- A long scan may not survive a spin-down or restart.
- **semgrep is not available in native mode** on this tier (memory). Expect
  partial coverage for SAST; secrets + dependency scanning run.

## Deployment checklist (no paid infra)

1. Set `SCANNER_EXECUTION_MODE=native` (Render) or leave `container` with a
   reachable `DOCKER_HOST`.
2. Confirm `GET /api/v1/health/deep` shows `scanner.mode` and each needed
   scanner `available`.
3. Set **all four** `R2_*` values for durable artifacts, or accept ephemeral
   local storage knowingly.
4. Set `OSV_EGRESS_PROXY` if dependency scanning should query OSV through the
   filtering proxy.
5. Verify `/health` (liveness) and `/health/ready` (DB readiness) are distinct.
6. Run a scan against a **locally controlled fixture repo** and confirm the
   report shows real scanner versions and statuses — never a fabricated clean
   result.

## What is and is not verified here

- **Verified:** native executor argv/env/timeout/limits logic, mode resolution,
  fail-closed binary resolution, storage selection, config validation, the
  account-deletion POST change, and the Canonical-Audit invariants — all by the
  executed backend test suites (see the implementation report).
- **Not verified:** the actual Render free-tier runtime (512 MB behavior, egress,
  spin-down survival) and a full `docker build` of the scanner-install stage in
  this environment. The download + SHA-256 commands were validated individually
  against the pinned release URLs, but the assembled image build was **not** run
  here. Treat the image build as **IMPLEMENTED, NOT VERIFIED** until it is built
  on Render or a Docker-capable host.
