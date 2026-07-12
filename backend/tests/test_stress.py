import concurrent.futures
import pytest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from app.main import app
from app.api.routes_auth import PRIVACY_POLICY_VERSION
from app.models import SessionLocal, AuditJob, User, get_db
from app.schemas import JobStatus
from app.config import settings
from app.services.auth import create_access_token


# Concurrently spawn 15 users to stress authentication, DB connection pooling, and endpoint security
CONCURRENT_USERS = 15

def run_register_and_login(username_prefix: str, index: int):
    username = f"{username_prefix}_{index}"
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
        user_id = user.id
    finally:
        db.close()

    # Thread-safe TestClient instance to prevent session/cookie crossover
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    
    # 3. Retrieve me endpoint
    me_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["user_id"] == user_id
    assert me_res.json()["username"] == username
    
    # 4. Fetch system status
    status_res = client.get("/api/v1/system/status", headers=headers)
    assert status_res.status_code == 200
    
    return user_id

def test_concurrent_user_onboarding(monkeypatch):
    """
    Stress test concurrent user registration, login, session validation,
    and system status queries using a high thread count.
    """
    results = []
    errors = []
    
    from app.services.auth import create_access_token
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_USERS) as executor:
        futures = {
            executor.submit(run_register_and_login, "stress_user", i): i
            for i in range(CONCURRENT_USERS)
        }
        for future in concurrent.futures.as_completed(futures):
            idx = futures[future]
            try:
                user_id = future.result()
                results.append(user_id)
            except Exception as e:
                errors.append((idx, e))
                
    assert len(errors) == 0, f"Encountered concurrency errors: {errors}"
    assert len(results) == CONCURRENT_USERS

def test_concurrent_job_submission_limit_enforcement(monkeypatch):
    """
    Test that submitting jobs concurrently respects user active limits correctly
    and handles rate limits under high parallel load.
    """
    from app.services.auth import create_access_token
    
    username = "stress_submit_user"
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
    finally:
        db.close()
        
    headers = {"Authorization": f"Bearer {token}"}
    
    # Mock broker status & Celery task dispatch
    class MockRedis:
        def get(self, name):
            if name == "celery:heartbeat":
                return b"alive"
            return None

    monkeypatch.setattr("app.services.auth._get_redis_client", lambda: MockRedis())
    monkeypatch.setattr("app.api.routes_audit._is_broker_reachable", lambda: True)
    monkeypatch.setattr("app.api.routes_audit.run_audit_job_task.apply_async", lambda *args, **kwargs: None)
    monkeypatch.setattr(settings, "MAX_ACTIVE_JOBS_PER_USER", 3)
    
    # Concurrently submit 10 scan requests.
    # The active limit is 3, so some should succeed (up to 3) and the rest should get 429.
    def submit_job(idx: int):
        t_client = TestClient(app)
        res = t_client.post(
            "/api/v1/audit/submit",
            json={
                "repo_url": f"https://github.com/stress/repo-{idx}",
                "repo_branch": "main",
                "attestation_accepted": True
            },
            headers=headers
        )
        return res.status_code, res.json()
        
    status_codes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(submit_job, i) for i in range(10)]
        for future in concurrent.futures.as_completed(futures):
            code, payload = future.result()
            status_codes.append(code)
            
    # Under high concurrency, we should see 201 (success) for the first 3 active jobs,
    # and 429 (Too Many Requests / Active Job Limit Reached) for the rest.
    success_count = status_codes.count(201)
    limit_count = status_codes.count(429)
    
    assert success_count <= 3, f"Allowed more than 3 active jobs: {success_count}"
    assert success_count + limit_count == 10, f"Unexpected response codes: {status_codes}"
