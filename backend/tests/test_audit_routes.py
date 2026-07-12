from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.api.routes_auth import PRIVACY_POLICY_VERSION
from app.models import AgentLog, AuditArtifact, AuditJob, FindingModel, SessionLocal, User, get_db
from app.models.role import Role
from app.schemas import JobStatus, Severity

client = TestClient(app)


def _auth_session(username: str = "auditor") -> tuple[dict[str, str], str]:
    import uuid
    from datetime import datetime, timezone
    from app.services.auth import create_access_token
    from app.config import settings

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            user = User(
                id=str(uuid.uuid4()),
                username=username,
                email=f"{username}@example.com",
                privacy_policy_version=PRIVACY_POLICY_VERSION,
                privacy_policy_accepted_at=datetime.now(timezone.utc),
                terms_version=settings.TERMS_VERSION,
                terms_accepted_at=datetime.now(timezone.utc),
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        token = create_access_token(user_id=user.id, username=user.username, db=db)
        return {"Authorization": f"Bearer {token}"}, user.id
    finally:
        db.close()


def _auth_headers(username: str = "auditor") -> dict[str, str]:
    return _auth_session(username)[0]


def test_list_jobs_returns_only_current_user_jobs():
    headers, user_id = _auth_session()
    db = SessionLocal()
    try:
        db.add_all(
            [
                AuditJob(id="job-1", user_id=user_id, repo_url="https://example.com/one", repo_branch="main"),
                AuditJob(id="job-2", user_id=user_id, repo_url="https://example.com/two", repo_branch="develop"),
                AuditJob(id="job-3", user_id="usr_other", repo_url="https://example.com/other", repo_branch="main"),
            ]
        )
        db.commit()
    finally:
        db.close()

    response = client.get("/api/v1/audit/jobs", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert {job["id"] for job in payload} == {"job-1", "job-2"}
    assert all(job["user_id"] == user_id for job in payload)
    assert all(isinstance(job["created_at"], str) and "T" in job["created_at"] for job in payload)


def test_get_job_detail_serializes_findings():
    headers, user_id = _auth_session()
    db = SessionLocal()
    try:
        db.add(
            AuditJob(
                id="job-detail",
                user_id=user_id,
                repo_url="https://example.com/repo",
                repo_branch="main",
                status=JobStatus.RUNNING,
            )
        )
        db.add(
            FindingModel(
                id="finding-1",
                job_id="job-detail",
                agent_source="SAST",
                title="SQL Injection",
                description="Unsanitized query builder",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                evidence="SELECT * FROM users",
                remediation="Use parameterized queries",
            )
        )
        db.commit()
    finally:
        db.close()

    response = client.get("/api/v1/audit/job/job-detail", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["job"]["id"] == "job-detail"
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["title"] == "SQL Injection"


def test_get_job_insight_returns_disabled_state(monkeypatch):
    headers, user_id = _auth_session("insight-disabled-user")
    db = SessionLocal()
    try:
        db.add(
            AuditJob(
                id="job-insight-disabled",
                user_id=user_id,
                repo_url="https://example.com/repo",
                repo_branch="main",
                status=JobStatus.COMPLETED,
            )
        )
        db.commit()
    finally:
        db.close()

    monkeypatch.setattr("app.api.routes_audit.is_llm_enabled", lambda feature: False)

    response = client.get("/api/v1/audit/job/job-insight-disabled/insight", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"insight": None, "enabled": False}


def test_get_job_insight_returns_safe_summary(monkeypatch):
    headers, user_id = _auth_session("insight-enabled-user")
    db = SessionLocal()
    try:
        db.add(
            AuditJob(
                id="job-insight-enabled",
                user_id=user_id,
                repo_url="https://example.com/repo",
                repo_branch="main",
                status=JobStatus.COMPLETED,
            )
        )
        db.add_all(
            [
                FindingModel(
                    id="finding-insight-critical",
                    job_id="job-insight-enabled",
                    agent_source="SAST",
                    title="Hardcoded secret",
                    description="A credential is committed to the repository.",
                    severity=Severity.CRITICAL,
                ),
                FindingModel(
                    id="finding-insight-high",
                    job_id="job-insight-enabled",
                    agent_source="SEMGREP",
                    title="SQL Injection",
                    description="Unsanitized query path.",
                    severity=Severity.HIGH,
                ),
            ]
        )
        db.commit()
    finally:
        db.close()

    monkeypatch.setattr("app.api.routes_audit.is_llm_enabled", lambda feature: True)
    monkeypatch.setattr("app.api.routes_audit.safe_llm_call", lambda *args, **kwargs: "Critical credential exposure and injection risk require immediate action.")

    response = client.get("/api/v1/audit/job/job-insight-enabled/insight", headers=headers)

    assert response.status_code == 200
    assert response.json() == {
        "insight": "Critical credential exposure and injection risk require immediate action.",
        "enabled": True,
    }


def test_submit_audit_dispatches_celery_task(monkeypatch):
    calls = []
    headers, user_id = _auth_session()

    def fake_apply_async(*, kwargs, task_id):
        calls.append({"kwargs": kwargs, "task_id": task_id})

    class MockRedis:
        def get(self, name):
            if name == "celery:heartbeat":
                return b"alive"
            return None

    monkeypatch.setattr("app.services.auth._get_redis_client", lambda: MockRedis())
    monkeypatch.setattr("app.api.routes_audit.run_audit_job_task.apply_async", fake_apply_async)

    response = client.post(
        "/api/v1/audit/submit",
        json={
            "repo_url": "https://github.com/example/repo",
            "repo_branch": "main",
            "attestation_accepted": True
        },
        headers=headers,
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["repo_url"] == "https://github.com/example/repo"
    assert payload["status"] == "queued"
    assert payload["cancel_requested"] is False
    assert payload["cancel_requested_at"] is None
    assert len(calls) == 1
    assert calls[0]["task_id"] == payload["id"]
    assert calls[0]["kwargs"]["user_id"] == user_id


def test_submit_audit_enforces_active_job_limit(monkeypatch):
    calls = []
    headers, user_id = _auth_session()

    def fake_apply_async(*, kwargs, task_id):
        calls.append({"kwargs": kwargs, "task_id": task_id})

    db = SessionLocal()
    try:
        for index in range(5):
            db.add(
                AuditJob(
                    id=f"job-active-{index}",
                    user_id=user_id,
                    repo_url=f"https://example.com/repo-{index}",
                    repo_branch="main",
                    status=JobStatus.RUNNING,
                )
            )
        db.commit()
    finally:
        db.close()

    monkeypatch.setattr("app.api.routes_audit._is_broker_reachable", lambda: True)
    monkeypatch.setattr("app.api.routes_audit.run_audit_job_task.apply_async", fake_apply_async)

    response = client.post(
        "/api/v1/audit/submit",
        json={
            "repo_url": "https://github.com/example/repo",
            "repo_branch": "main",
            "attestation_accepted": True
        },
        headers=headers,
    )

    assert response.status_code == 429
    assert calls == []


def test_cancel_job_sets_cancel_intent_without_forcing_terminal_state():
    headers, user_id = _auth_session()
    db = SessionLocal()
    try:
        db.add(
            AuditJob(
                id="job-cancel-route",
                user_id=user_id,
                repo_url="https://example.com/cancel",
                repo_branch="main",
                status=JobStatus.RUNNING,
            )
        )
        db.commit()
    finally:
        db.close()

    response = client.delete("/api/v1/audit/job/job-cancel-route", headers=headers)

    assert response.status_code == 200
    db = SessionLocal()
    try:
        job = db.query(AuditJob).filter(AuditJob.id == "job-cancel-route").first()
        assert job is not None
        assert job.status == JobStatus.RUNNING
        assert job.cancel_requested is True
        assert job.cancel_requested_at is not None
    finally:
        db.close()


def test_download_report_serves_local_report(monkeypatch, tmp_path):
    monkeypatch.setattr("app.api.routes_audit.REPORTS_DIR", tmp_path)
    headers, user_id = _auth_session()
    (tmp_path / "job-report.pdf").write_bytes(b"%PDF-1.4 test report")

    db = SessionLocal()
    try:
        db.add(
            AuditJob(
                id="job-report",
                user_id=user_id,
                repo_url="https://example.com/report",
                repo_branch="main",
                status=JobStatus.COMPLETED,
                report_pdf_url="/reports/job-report.pdf",
            )
        )
        db.commit()
    finally:
        db.close()

    response = client.get("/api/v1/audit/job/job-report/report", headers=headers)

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-1.4")


def test_download_report_falls_back_to_persisted_html_when_local_artifact_is_missing():
    headers, user_id = _auth_session("report-html-fallback")

    db = SessionLocal()
    try:
        db.add(
            AuditJob(
                id="job-report-html-fallback",
                user_id=user_id,
                repo_url="https://example.com/report",
                repo_branch="main",
                status=JobStatus.COMPLETED,
                report_pdf_url="artifact://artifact-missing-report",
            )
        )
        db.add(
            AuditArtifact(
                id="artifact-missing-report",
                job_id="job-report-html-fallback",
                artifact_type="report_pdf",
                name="job-report.pdf",
            )
        )
        db.add(
            AuditArtifact(
                id="artifact-html-snapshot",
                job_id="job-report-html-fallback",
                artifact_type="report_html",
                name="job-report.html",
                data_text="<html><body><h1>Persisted report</h1></body></html>",
            )
        )
        db.commit()
    finally:
        db.close()

    response = client.get("/api/v1/audit/job/job-report-html-fallback/report", headers=headers)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Persisted report" in response.text


@pytest.mark.parametrize("report_url", ["/reports/../secret.pdf", "file:///tmp/report.pdf", "https://evil.example/report.pdf"])
def test_download_report_rejects_unsafe_report_locations(report_url: str):
    headers, user_id = _auth_session()
    db = SessionLocal()
    try:
        db.add(
            AuditJob(
                id="job-unsafe-report",
                user_id=user_id,
                repo_url="https://example.com/report",
                repo_branch="main",
                status=JobStatus.COMPLETED,
                report_pdf_url=report_url,
            )
        )
        db.commit()
    finally:
        db.close()

    response = client.get("/api/v1/audit/job/job-unsafe-report/report", headers=headers)

    assert response.status_code == 400


def test_system_status_requires_auth_and_scopes_stats_to_current_user():
    headers, user_id = _auth_session()
    db = SessionLocal()
    try:
        db.add_all(
            [
                AuditJob(id="job-system-user", user_id=user_id, repo_url="https://example.com/user", repo_branch="main"),
                AuditJob(id="job-system-other", user_id="usr_other", repo_url="https://example.com/other", repo_branch="main"),
            ]
        )
        db.add_all(
            [
                FindingModel(
                    job_id="job-system-user",
                    agent_source="SAST",
                    title="User finding",
                    description="Current tenant finding",
                    severity=Severity.HIGH,
                ),
                FindingModel(
                    job_id="job-system-other",
                    agent_source="SAST",
                    title="Other finding",
                    description="Another tenant finding",
                    severity=Severity.CRITICAL,
                ),
            ]
        )
        db.commit()
    finally:
        db.close()

    unauthenticated_client = TestClient(app)
    unauthenticated = unauthenticated_client.get("/api/v1/system/status")
    response = client.get("/api/v1/system/status", headers=headers)

    assert unauthenticated.status_code == 401
    assert response.status_code == 200
    assert response.json()["stats"] == {"jobs": 1, "findings": 1}
    assert "debug" not in response.json()
    assert "integrations" not in response.json()


def test_system_status_admin_gets_operational_details():
    headers, user_id = _auth_session("admin-auditor")
    db = SessionLocal()
    try:
        role = db.query(Role).filter(Role.name == "admin").first()
        if not role:
            role = Role(name="admin", description="Admin", can_start_scans=True, can_view_reports=True)
            db.add(role)
            db.flush()
        user = db.query(User).filter(User.id == user_id).first()
        assert user is not None
        user.role_id = role.id
        db.commit()
    finally:
        db.close()

    response = client.get("/api/v1/system/status", headers=headers)

    assert response.status_code == 200
    assert "integrations" in response.json()
    assert "debug" in response.json()


@pytest.mark.parametrize("status_value", ["completed", "failed", "cancelled", "partial"])
def test_sse_stream_emits_terminal_event_for_terminal_statuses(status_value: str):
    status = JobStatus(status_value)
    headers, user_id = _auth_session()
    db = SessionLocal()
    try:
        db.add(
            AuditJob(
                id=f"job-sse-{status_value}",
                user_id=user_id,
                repo_url="https://example.com/repo",
                repo_branch="main",
                status=status,
                report_pdf_url="file:///tmp/report.pdf" if status in {JobStatus.COMPLETED, JobStatus.PARTIAL} else None,
                error_message="boom" if status in {JobStatus.FAILED, JobStatus.PARTIAL} else None,
            )
        )
        db.add(
            AgentLog(
                job_id=f"job-sse-{status_value}",
                agent_name="MAESTRO",
                log_level="INFO",
                message="terminal log",
            )
        )
        db.commit()
    finally:
        db.close()

    response = client.get(f"/api/v1/audit/job-sse-{status_value}/stream", headers=headers)

    assert response.status_code == 200
    assert "event: complete" in response.text
    assert f"\"status\": \"{status_value}\"" in response.text


def test_sse_stream_rechecks_tenant_scope():
    headers, user_id = _auth_session("sse-owner")
    db = SessionLocal()
    try:
        db.add(
            AuditJob(
                id="job-sse-ownership",
                user_id=user_id,
                repo_url="https://example.com/repo",
                repo_branch="main",
                status=JobStatus.RUNNING,
            )
        )
        db.commit()
        job = db.query(AuditJob).filter(AuditJob.id == "job-sse-ownership").first()
        assert job is not None
        job.user_id = "usr_other"
        db.commit()
    finally:
        db.close()

    response = client.get("/api/v1/audit/job-sse-ownership/stream", headers=headers)

    assert response.status_code == 404


def test_global_exception_handler_does_not_leak_exception_message():
    def broken_db():
        raise RuntimeError("database password leaked in exception")

    app.dependency_overrides[get_db] = broken_db
    safe_client = TestClient(app, raise_server_exceptions=False)
    try:
        response = safe_client.get("/health")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 500
    assert response.json()["detail"] == "Internal Server Error"
    assert "request_id" in response.json()
    assert "error_id" not in response.json()
    assert "password leaked" not in response.text


def test_health_does_not_leak_database_exception():
    class BrokenDb:
        def execute(self, *_args, **_kwargs):
            raise RuntimeError("postgres://user:secret@db.internal/firecrow")

    def broken_db():
        yield BrokenDb()

    app.dependency_overrides[get_db] = broken_db
    try:
        response = client.get("/health")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == {"status": "degraded", "database": "unavailable"}
    assert "secret" not in response.text


def test_email_report_endpoint(monkeypatch, tmp_path):
    headers, user_id = _auth_session("email-test-user")
    (tmp_path / "job-email-report.pdf").write_bytes(b"%PDF-1.4 test report")

    db = SessionLocal()
    try:
        # Create a user in db and set email
        user = db.query(User).filter(User.id == user_id).first()
        assert user is not None
        user.email = "test-github-email@example.com"
        db.commit()

        db.add(
            AuditJob(
                id="job-email-test",
                user_id=user_id,
                repo_url="https://example.com/report",
                repo_branch="main",
                status=JobStatus.COMPLETED,
                report_pdf_url="/reports/job-email-report.pdf",
            )
        )
        db.commit()
    finally:
        db.close()

    monkeypatch.setattr("app.api.routes_audit.REPORTS_DIR", tmp_path)
    
    # Mock send_email_report
    calls = []
    def fake_send_email_report(self, to_email, report_url, job_id, counts, repo_url="", pdf_path=None):
        calls.append({
            "to_email": to_email,
            "report_url": report_url,
            "job_id": job_id,
            "counts": counts,
            "repo_url": repo_url,
            "pdf_path": pdf_path
        })
        return True
    
    from app.services.reporter import ReportGenerator
    monkeypatch.setattr(ReportGenerator, "send_email_report", fake_send_email_report)

    # 1. Test sending to custom email
    response = client.post(
        "/api/v1/audit/job/job-email-test/email",
        json={"email": "custom-email@example.com"},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["recipient"] == "custom-email@example.com"
    assert len(calls) == 1
    assert calls[0]["to_email"] == "custom-email@example.com"
    assert calls[0]["job_id"] == "job-email-test"
    import os
    assert os.path.exists(calls[0]["pdf_path"])

    # 2. Test fallback to GitHub OAuth email
    response = client.post(
        "/api/v1/audit/job/job-email-test/email",
        json={},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["recipient"] == "test-github-email@example.com"
    assert len(calls) == 2
    assert calls[1]["to_email"] == "test-github-email@example.com"
