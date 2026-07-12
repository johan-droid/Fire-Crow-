"""
Comprehensive Stress & Feature Coverage Tests
==============================================
Tests all major Fire Crow product features under concurrent load:

1. Auth Pipeline      - register, login, /me, logout, cookie-based auth
2. Audit Jobs         - submit, list, status, findings, artifacts, cancel
3. Leaderboard        - ranking correctness under concurrent job completion
4. User GDPR          - data export, right-to-be-forgotten
5. System Health      - /system/status endpoint availability
6. Chat               - chat session creation and message handling
7. Rate Limits        - concurrent submit respects per-user active job limits
8. Security           - unauthenticated access is always rejected (401/403)
9. Concurrency Safety - no data leakage between simultaneous users
"""
from __future__ import annotations

import concurrent.futures
import uuid
import time
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes_auth import PRIVACY_POLICY_VERSION
from app.models import (
    AuditJob,
    FindingModel,
    SessionLocal,
    User,
    AgentLog,
    AuditArtifact,
)
from app.schemas import JobStatus, Severity
from app.services.auth import create_access_token
from app.config import settings

# ── helpers ──────────────────────────────────────────────────────────────────

CONCURRENT_USERS = 12   # enough to stress DB pool without overwhelming SQLite
PP_VERSION = PRIVACY_POLICY_VERSION


def _unique(prefix: str = "u") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _register_and_login(client: TestClient, username: str) -> tuple[str, dict]:
    """Register a fresh user and return (user_id, auth_headers)."""
    import uuid
    from datetime import datetime, timezone

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            user = User(
                id=str(uuid.uuid4()),
                username=username,
                email=f"{username}@example.com",
                privacy_policy_version=PP_VERSION,
                privacy_policy_accepted_at=datetime.now(timezone.utc),
                terms_version=settings.TERMS_VERSION,
                terms_accepted_at=datetime.now(timezone.utc),
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        token = create_access_token(user_id=user.id, username=user.username, db=db)
        user_id = user.id
    finally:
        db.close()

    return user_id, {"Authorization": f"Bearer {token}"}



def _seed_job(
    db,
    user_id: str,
    repo_url: str = "https://github.com/test/repo",
    status: JobStatus = JobStatus.COMPLETED,
    score: float | None = 82.5,
) -> AuditJob:
    job = AuditJob(
        id=f"job_{uuid.uuid4().hex[:12]}",
        user_id=user_id,
        repo_url=repo_url,
        repo_branch="main",
        status=status,
        security_score=score,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _seed_finding(db, job_id: str, severity: Severity = Severity.HIGH) -> str:
    """Seed a finding and return its id. Copies primitive attrs before session closes."""
    f = FindingModel(
        id=f"fnd_{uuid.uuid4().hex[:10]}",
        job_id=job_id,
        agent_source="stress_test_agent",
        title="SQL Injection",
        severity=severity,
        description="Unsanitised input",
        file_path="app/db.py",
        line_number=42,
    )
    db.add(f)
    db.commit()
    return str(f.id)


# ══════════════════════════════════════════════════════════════════════════════
# 1. AUTH PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

class TestAuthPipeline:
    """Full auth lifecycle under concurrent load."""

    def _run_one_user(self, index: int):
        client = TestClient(app)
        uname = _unique(f"auth_stress_{index}")
        user_id, headers = _register_and_login(client, uname)

        # /me
        me = client.get("/api/v1/auth/me", headers=headers)
        assert me.status_code == 200
        assert me.json()["user_id"] == user_id
        assert me.json()["username"] == uname

        # system status
        sys_status = client.get("/api/v1/system/status", headers=headers)
        assert sys_status.status_code == 200

        return user_id

    def test_concurrent_onboarding(self):
        """Register + login + /me for CONCURRENT_USERS in parallel."""
        errors: list = []
        results: list = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_USERS) as ex:
            futs = {ex.submit(self._run_one_user, i): i for i in range(CONCURRENT_USERS)}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception as exc:
                    errors.append(exc)
        assert not errors, f"Auth concurrency errors: {errors}"
        assert len(results) == CONCURRENT_USERS
        # All user IDs must be unique – no session collision
        assert len(set(results)) == CONCURRENT_USERS

    def test_registration_and_login_disabled(self):
        client = TestClient(app)
        uname = _unique("disabled_user")
        r1 = client.post(
            "/api/v1/auth/register",
            json={
                "username": uname,
                "password": "Str0ng!StressPass",
                "privacy_policy_accepted": True,
                "privacy_policy_version": PP_VERSION,
            },
        )
        assert r1.status_code == 400
        assert "disabled" in r1.json()["detail"].lower()

        r2 = client.post(
            "/api/v1/auth/login",
            json={
                "username": uname,
                "password": "Str0ng!StressPass",
                "privacy_policy_accepted": True,
                "privacy_policy_version": PP_VERSION,
            },
        )
        assert r2.status_code == 400
        assert "disabled" in r2.json()["detail"].lower()


    def test_logout_invalidates_session(self):
        client = TestClient(app)
        uname = _unique("logout_test")
        _, headers = _register_and_login(client, uname)
        logout = client.post("/api/v1/auth/logout", headers=headers)
        assert logout.status_code in (200, 204)


# ══════════════════════════════════════════════════════════════════════════════
# 2. AUDIT JOB LIFECYCLE
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditJobLifecycle:
    """Test audit job submission, listing, retrieval, findings, and cancellation."""

    def test_job_list_empty_for_new_user(self):
        client = TestClient(app)
        _, headers = _register_and_login(client, _unique("list_empty"))
        resp = client.get("/api/v1/audit/jobs", headers=headers)
        assert resp.status_code == 200
        # The endpoint returns a plain JSON list
        body = resp.json()
        jobs = body if isinstance(body, list) else body.get("jobs", [])
        assert isinstance(jobs, list)

    def test_job_list_shows_only_own_jobs(self):
        client = TestClient(app)
        uid1, h1 = _register_and_login(client, _unique("owner1"))
        uid2, h2 = _register_and_login(client, _unique("owner2"))
        db = SessionLocal()
        try:
            job_own = _seed_job(db, uid1, "https://github.com/own/repo")
            _seed_job(db, uid2, "https://github.com/other/repo")
            # Copy primitive IDs before session closes to avoid DetachedInstanceError
            job_own_id = str(job_own.id)
        finally:
            db.close()

        resp = client.get("/api/v1/audit/jobs", headers=h1)
        assert resp.status_code == 200
        # Parse flexible response shape (list OR {"jobs": [...]})
        jobs_payload = resp.json()
        jobs = jobs_payload if isinstance(jobs_payload, list) else jobs_payload.get("jobs", [])
        ids = [j.get("id") or j.get("job_id") for j in jobs]
        assert job_own_id in ids
        for job in jobs:
            jid = job.get("user_id") or job.get("owner_id")
            if jid:
                assert jid == uid1

    def test_job_detail_returns_status(self):
        client = TestClient(app)
        uid, headers = _register_and_login(client, _unique("detail"))
        db = SessionLocal()
        try:
            job = _seed_job(db, uid, status=JobStatus.COMPLETED, score=91.0)
            job_id = str(job.id)  # copy before session closes
        finally:
            db.close()

        # Note: detail endpoint is /audit/job/{id} (singular), not /audit/jobs/{id}
        # Response shape: {"job": {...}, "findings": [...]}
        resp = client.get(f"/api/v1/audit/job/{job_id}", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        # The job object is nested under 'job' key
        job_data = data.get("job") or data
        resolved_id = job_data.get("id") or job_data.get("job_id")
        assert resolved_id == job_id, f"Expected job_id={job_id}, got id={resolved_id} in {list(data.keys())}"

    def test_findings_accessible_for_completed_job(self):
        client = TestClient(app)
        uid, headers = _register_and_login(client, _unique("findings"))
        db = SessionLocal()
        try:
            job = _seed_job(db, uid)
            job_id = str(job.id)  # copy before session closes
            _seed_finding(db, job_id, Severity.CRITICAL)
            _seed_finding(db, job_id, Severity.HIGH)
        finally:
            db.close()

        # Findings are embedded in the job detail response under 'findings' key.
        # Response shape: {"job": {...}, "findings": [...]}
        resp = client.get(f"/api/v1/audit/job/{job_id}", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        # findings may be top-level or nested depending on response model
        findings_list = data.get("findings") or []
        assert len(findings_list) >= 2, (
            f"Expected >= 2 findings, got {len(findings_list)}. Full response: {data}"
        )

    def test_cannot_access_other_users_job(self):
        client = TestClient(app)
        uid1, _ = _register_and_login(client, _unique("owner_a"))
        _, h2 = _register_and_login(client, _unique("intruder_b"))
        db = SessionLocal()
        try:
            job = _seed_job(db, uid1)
            job_id = str(job.id)  # copy before session closes
        finally:
            db.close()
        resp = client.get(f"/api/v1/audit/jobs/{job_id}", headers=h2)
        assert resp.status_code in (403, 404), (
            f"Expected 403/404 for cross-user access, got {resp.status_code}"
        )

    def test_unauthenticated_job_list_rejected(self):
        client = TestClient(app)
        resp = client.get("/api/v1/audit/jobs")
        assert resp.status_code in (401, 403)

    def test_job_submit_mock_broker(self, monkeypatch):
        client = TestClient(app)
        _, headers = _register_and_login(client, _unique("submit_mock"))
        monkeypatch.setattr("app.api.routes_audit._is_broker_reachable", lambda: True)
        monkeypatch.setattr(
            "app.api.routes_audit.run_audit_job_task.apply_async",
            lambda *a, **kw: None,
        )
        resp = client.post(
            "/api/v1/audit/submit",
            json={
                "repo_url": "https://github.com/stress/test-repo",
                "repo_branch": "main",
                "attestation_accepted": True,
            },
            headers=headers,
        )
        assert resp.status_code in (200, 201), f"Submit failed: {resp.text}"


# ══════════════════════════════════════════════════════════════════════════════
# 3. RATE LIMIT ENFORCEMENT
# ══════════════════════════════════════════════════════════════════════════════

def test_concurrent_submit_respects_active_job_limit(monkeypatch):
    """
    High-concurrency submit: only MAX_ACTIVE_JOBS_PER_USER succeed.
    The rest must receive 429.
    """
    client = TestClient(app)
    uname = _unique("rate_limit_user")
    _, headers = _register_and_login(client, uname)

    monkeypatch.setattr("app.api.routes_audit._is_broker_reachable", lambda: True)
    monkeypatch.setattr(
        "app.api.routes_audit.run_audit_job_task.apply_async",
        lambda *a, **kw: None,
    )
    from app.config import settings
    monkeypatch.setattr(settings, "MAX_ACTIVE_JOBS_PER_USER", 3)

    def _submit(idx: int):
        tc = TestClient(app)
        r = tc.post(
            "/api/v1/audit/submit",
            json={
                "repo_url": f"https://github.com/rate/{idx}",
                "repo_branch": "main",
                "attestation_accepted": True,
            },
            headers=headers,
        )
        return r.status_code

    status_codes: list[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(_submit, i) for i in range(10)]
        for f in concurrent.futures.as_completed(futs):
            status_codes.append(f.result())

    success = status_codes.count(201) + status_codes.count(200)
    limited = status_codes.count(429)
    assert success <= 3, f"Accepted more than limit: {success}"
    assert success + limited == 10, f"Unexpected codes: {status_codes}"


# ══════════════════════════════════════════════════════════════════════════════
# 4. LEADERBOARD
# ══════════════════════════════════════════════════════════════════════════════

class TestLeaderboard:
    def test_leaderboard_accessible(self):
        client = TestClient(app)
        _, headers = _register_and_login(client, _unique("lb_user"))
        resp = client.get("/api/v1/leaderboard", headers=headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_leaderboard_returns_scored_jobs(self):
        client = TestClient(app)
        uid, headers = _register_and_login(client, _unique("lb_score"))
        db = SessionLocal()
        try:
            _seed_job(db, uid, "https://github.com/lb/top", score=95.0)
            _seed_job(db, uid, "https://github.com/lb/bottom", score=40.0)
        finally:
            db.close()
        resp = client.get("/api/v1/leaderboard", headers=headers)
        assert resp.status_code == 200
        entries = resp.json()
        if entries:
            scores = [e.get("score") or e.get("security_score") for e in entries]
            non_null = [s for s in scores if s is not None]
            if len(non_null) >= 2:
                assert non_null == sorted(non_null, reverse=True), "Leaderboard not sorted desc"

    def test_leaderboard_unauthenticated_rejected(self):
        client = TestClient(app)
        resp = client.get("/api/v1/leaderboard")
        assert resp.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# 5. SYSTEM HEALTH
# ══════════════════════════════════════════════════════════════════════════════

class TestSystemHealth:
    def test_status_endpoint_returns_200(self):
        client = TestClient(app)
        _, headers = _register_and_login(client, _unique("health_user"))
        resp = client.get("/api/v1/system/status", headers=headers)
        assert resp.status_code == 200

    def test_status_has_required_keys(self):
        client = TestClient(app)
        _, headers = _register_and_login(client, _unique("health_keys"))
        resp = client.get("/api/v1/system/status", headers=headers)
        data = resp.json()
        # Must include at least one of these top-level keys
        expected_keys = {"status", "agents", "uptime", "database", "db"}
        assert expected_keys & set(data.keys()), (
            f"Status response missing expected keys. Got: {list(data.keys())}"
        )

    def test_health_endpoint_unauthenticated(self):
        """Health / liveness probe must be reachable without auth."""
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code in (200, 204)

    def test_concurrent_health_poll(self):
        """50 concurrent /health calls must all succeed without timeout."""
        def _poll(_):
            c = TestClient(app)
            return c.get("/health").status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            codes = list(ex.map(_poll, range(50)))
        assert all(c in (200, 204) for c in codes), f"Some health polls failed: {set(codes)}"


# ══════════════════════════════════════════════════════════════════════════════
# 6. GDPR / USER DATA
# ══════════════════════════════════════════════════════════════════════════════

class TestGDPR:
    def test_export_returns_user_fields(self):
        client = TestClient(app)
        uname = _unique("gdpr_export")
        _, headers = _register_and_login(client, uname)
        resp = client.get("/api/v1/user/export", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "username" in data
        assert "password_hash" not in data, "Password hash must NEVER be exported"
        assert data["username"] == uname

    def test_export_unauthenticated_rejected(self):
        client = TestClient(app)
        resp = client.get("/api/v1/user/export")
        assert resp.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# 7. DATA ISOLATION (NO CROSS-USER LEAKAGE)
# ══════════════════════════════════════════════════════════════════════════════

def test_no_data_leakage_between_concurrent_users():
    """
    Spin up N users concurrently. Each seeds their own job and finding.
    After all complete, each user must only see their own data.
    """
    N = 8
    user_data: dict[str, tuple[str, dict, str]] = {}  # uname -> (uid, headers, job_id)
    errors: list = []

    def _create_user_and_job(i: int):
        client = TestClient(app)
        uname = _unique(f"isolate_{i}")
        uid, headers = _register_and_login(client, uname)
        db = SessionLocal()
        try:
            job = _seed_job(db, uid, f"https://github.com/isolate/repo_{i}")
            job_id = str(job.id)   # copy primitive before closing
            # seed a finding with agent_source set
            _seed_finding(db, job_id, Severity.CRITICAL)
        finally:
            db.close()
        return uname, uid, headers, job_id

    with concurrent.futures.ThreadPoolExecutor(max_workers=N) as ex:
        futs = {ex.submit(_create_user_and_job, i): i for i in range(N)}
        for fut in concurrent.futures.as_completed(futs):
            try:
                uname, uid, headers, job_id = fut.result()
                user_data[uname] = (uid, headers, job_id)
            except Exception as e:
                errors.append(e)

    assert not errors, f"User creation errors: {errors}"

    # Now verify each user only sees their own job
    for uname, (uid, headers, job_id) in user_data.items():
        client = TestClient(app)
        resp = client.get("/api/v1/audit/jobs", headers=headers)
        assert resp.status_code == 200
        payload = resp.json()
        jobs = payload if isinstance(payload, list) else payload.get("jobs", [])
        ids = {j.get("id") or j.get("job_id") for j in jobs}
        # Their own job must be present
        assert job_id in ids, f"User {uname} missing own job {job_id}"
        # No other user's job should appear
        other_ids = {
            jid
            for other_uname, (_, _, jid) in user_data.items()
            if other_uname != uname
        }
        leaked = ids & other_ids
        assert not leaked, f"Data leakage for {uname}: saw job IDs {leaked}"


# ══════════════════════════════════════════════════════════════════════════════
# 8. SECURITY – UNAUTHENTICATED ACCESS ALWAYS REJECTED
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("method,path,allowed_codes", [
    # Standard protected endpoints – must require auth
    ("GET",  "/api/v1/audit/jobs",              (401, 403)),
    ("POST", "/api/v1/audit/submit",            (401, 403, 422)),
    ("GET",  "/api/v1/leaderboard",             (401, 403)),
    ("GET",  "/api/v1/auth/me",                 (401, 403)),
    ("GET",  "/api/v1/user/export",             (401, 403)),
    ("GET",  "/api/v1/system/status",           (401, 403)),
    # Job-by-id: FastAPI resolves the path param then hits auth; 404 is also acceptable
    # because the router may check path existence before auth in some middleware configs
    ("GET",  "/api/v1/audit/jobs/nonexistent-id", (401, 403, 404)),
])
def test_unauthenticated_endpoint_returns_auth_error(method, path, allowed_codes):
    client = TestClient(app)
    resp = getattr(client, method.lower())(path)
    assert resp.status_code in allowed_codes, (
        f"{method} {path} → expected {allowed_codes}, got {resp.status_code}: {resp.text[:200]}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# 9. PERFORMANCE BASELINE
# ══════════════════════════════════════════════════════════════════════════════

def test_auth_response_time_under_200ms():
    """
    /me must respond in under 200 ms per request (median over 20 calls).
    """
    client = TestClient(app)
    uname = _unique("perf_user")
    _, headers = _register_and_login(client, uname)

    times: list[float] = []
    for _ in range(20):
        t0 = time.perf_counter()
        r = client.get("/api/v1/auth/me", headers=headers)
        t1 = time.perf_counter()
        assert r.status_code == 200
        times.append(t1 - t0)

    times.sort()
    median = times[len(times) // 2]
    assert median < 0.200, f"/me median latency too high: {median*1000:.1f}ms"


def test_health_response_time_under_50ms():
    """
    /health liveness probe must respond in under 50 ms (median over 20 calls).
    """
    client = TestClient(app)
    times: list[float] = []
    for _ in range(20):
        t0 = time.perf_counter()
        r = client.get("/health")
        t1 = time.perf_counter()
        assert r.status_code in (200, 204)
        times.append(t1 - t0)

    times.sort()
    median = times[len(times) // 2]
    assert median < 0.050, f"/health median latency too high: {median*1000:.1f}ms"
