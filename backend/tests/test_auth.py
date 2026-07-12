import json
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.api.routes_auth import PRIVACY_POLICY_VERSION
from app.main import app
from app.models import AuthExchangeCode, SecurityLog, SessionLocal, User, UserActivityEvent
from app.services.auth import (
    AUTH_COOKIE_NAME,
    create_access_token,
    create_exchange_code,
    verify_access_token,
)
from app.config import settings

client = TestClient(app)


def _register_payload(username: str, password: str = "supersecretpassword") -> dict:
    return {
        "username": username,
        "password": password,
        "privacy_policy_accepted": True,
        "privacy_policy_version": PRIVACY_POLICY_VERSION,
    }


def _create_test_user_and_token(username: str, email: str = None) -> tuple[str, str]:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            user = User(
                id=str(uuid.uuid4()),
                username=username,
                email=email or f"{username}@example.com",
                privacy_policy_version=PRIVACY_POLICY_VERSION,
                privacy_policy_accepted_at=datetime.now(timezone.utc),
                terms_version=settings.TERMS_VERSION,
                terms_accepted_at=datetime.now(timezone.utc),
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        token = create_access_token(user_id=user.id, username=user.username, db=db)
        return token, user.id
    finally:
        db.close()


def test_jwt_generation_and_verification():
    user_id = str(uuid.uuid4())
    token = create_access_token(user_id=user_id, username="tester")

    assert token is not None
    assert isinstance(token, str)

    payload = verify_access_token(token)
    assert payload is not None
    assert payload["sub"] == user_id
    assert payload["username"] == "tester"
    assert payload["iss"] == "firecrow-api"
    assert payload["aud"] == "firecrow-web"
    assert payload["jti"]


def test_auth_me_unauthorized():
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


def test_auth_me_authorized():
    token, user_id = _create_test_user_and_token("supertester")

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["user_id"] == user_id
    uuid.UUID(user_id)
    assert response.json()["role"] == "security_engineer"
    assert response.json()["privacy_policy_version"] == PRIVACY_POLICY_VERSION


def test_auth_session_accepts_cookie():
    token, _ = _create_test_user_and_token("cookietester")

    response = client.get(
        "/api/v1/auth/session",
        cookies={AUTH_COOKIE_NAME: token},
    )

    assert response.status_code == 200
    assert response.json()["username"] == "cookietester"
    assert response.json()["providers"]["github"]["connected"] is False


def test_logout_revokes_token():
    token, _ = _create_test_user_and_token("revoketester")

    logout_response = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_response.status_code == 200

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_logout_revokes_token_with_redis_configured(monkeypatch):
    class FakeRedis:
        def __init__(self):
            self.revoked: dict[str, tuple[int, str]] = {}

        def exists(self, key: str) -> int:
            return int(key in self.revoked)

        def setex(self, key: str, ttl: int, value: str) -> None:
            self.revoked[key] = (ttl, value)

    fake_redis = FakeRedis()
    monkeypatch.setattr("app.services.auth._get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(settings, "DEBUG", False)
    monkeypatch.setattr(settings, "REDIS_URL", "redis://cache.firecrow.test:6379/0")

    token, _ = _create_test_user_and_token("redisrevoker")

    logout_response = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_response.status_code == 200
    assert fake_redis.revoked

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_registration_and_login_flow_are_disabled():
    reg_response = client.post(
        "/api/v1/auth/register",
        json={
            **_register_payload("newuser"),
            "email": "newuser@example.com",
        },
    )
    assert reg_response.status_code == 400
    assert "disabled" in reg_response.json()["detail"].lower()

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            **_register_payload("newuser"),
            "password": "supersecretpassword",
        },
    )
    assert login_response.status_code == 400
    assert "disabled" in login_response.json()["detail"].lower()


def test_google_auth_is_disabled():
    response = client.get("/api/v1/auth/google")
    assert response.status_code == 400
    assert "disabled" in response.json()["detail"].lower()

    callback_response = client.get("/api/v1/auth/google/callback")
    assert callback_response.status_code == 400
    assert "disabled" in callback_response.json()["detail"].lower()


def test_policy_context_reports_password_auth_disabled():
    response = client.get("/api/v1/auth/policy-context")
    assert response.status_code == 200
    assert response.json()["providers"].get("password") is False
    assert response.json()["providers"].get("google") is False


def test_policy_context_hides_unconfigured_oauth_providers(monkeypatch):
    monkeypatch.setattr(settings, "DEBUG", True)
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "")

    response = client.get("/api/v1/auth/policy-context")

    assert response.status_code == 200
    providers = response.json()["providers"]
    assert providers["github"] is False
    assert providers.get("google") is False
    assert providers.get("password") is False


def test_policy_context_sets_local_csrf_cookie_without_secure_flag_in_debug(monkeypatch):
    monkeypatch.setattr(settings, "CSRF_ENABLED", True)
    monkeypatch.setattr(settings, "DEBUG", True)
    monkeypatch.setattr(settings, "FRONTEND_URL", "http://localhost:3000")
    monkeypatch.setattr(settings, "AUTH_COOKIE_SECURE", True)
    with TestClient(app) as local_client:
        response = local_client.get("/api/v1/auth/policy-context")

    assert response.status_code == 200
    set_cookie = response.headers.get("set-cookie", "")
    assert "fc_csrf_token=" in set_cookie
    assert "Secure" not in set_cookie


def test_oauth_redirects_fail_when_provider_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "DEBUG", False)
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "")
    github_response = client.get(
        "/api/v1/auth/github",
        params={
            "privacy_policy_accepted": "true",
            "privacy_policy_version": PRIVACY_POLICY_VERSION,
        },
    )
    assert github_response.status_code == 503
    assert "not configured" in github_response.json()["detail"]


def test_github_oauth_requests_private_repo_pr_scopes(monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "github-client")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "github-secret")

    response = client.get(
        "/api/v1/auth/github",
        params={
            "privacy_policy_accepted": "true",
            "privacy_policy_version": PRIVACY_POLICY_VERSION,
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 307}
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["scope"] == ["repo,workflow,read:org,user:email"]


def test_github_oauth_callback_sets_cookie_without_token_url(monkeypatch):
    class FakeResponse:
        def __init__(self, payload: Any, status_code: int = 200, headers: dict[str, str] | None = None):
            self._payload = payload
            self.status_code = status_code
            self.headers = headers or {}

        def json(self):
            return self._payload

    class FakeAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse({"access_token": "github-oauth-token", "scope": "repo,workflow,read:org,user:email"})

        async def get(self, url, *args, **kwargs):
            if url.endswith("/user"):
                return FakeResponse(
                    {"id": 123, "login": "octo", "email": "Octo@Example.com"},
                    headers={"X-OAuth-Scopes": "repo,workflow,read:org,user:email"},
                )
            return FakeResponse([])

    monkeypatch.setattr("app.api.routes_auth.httpx.AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "github-client")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "github-secret")
    monkeypatch.setattr(settings, "FRONTEND_URL", "https://app.firecrow.test")
    monkeypatch.setattr(settings, "DEBUG", False)

    state = client.get(
        "/api/v1/auth/github",
        params={
            "privacy_policy_accepted": "true",
            "privacy_policy_version": PRIVACY_POLICY_VERSION,
        },
        follow_redirects=False,
    ).headers["location"].split("state=", 1)[1].split("&", 1)[0]

    response = client.get(
        "/api/v1/auth/github/callback",
        params={"code": "oauth-code", "state": state},
        follow_redirects=False,
    )

    assert response.headers["location"].startswith("https://app.firecrow.test/signin?code=")
    assert "token=" not in response.headers["location"]
    set_cookie = response.headers["set-cookie"]
    assert f"{AUTH_COOKIE_NAME}=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert "SameSite=strict" in set_cookie

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "octo").first()
        assert user is not None
        assert user.github_access_token is not None
        assert user.github_access_token.startswith("ENC[")
        assert user.github_token_scopes == "read:org,repo,user:email,workflow"
    finally:
        db.close()


def test_github_oauth_callback_uses_request_origin_when_frontend_url_missing(monkeypatch):
    class FakeResponse:
        def __init__(self, payload: Any, status_code: int = 200, headers: dict[str, str] | None = None):
            self._payload = payload
            self.status_code = status_code
            self.headers = headers or {}

        def json(self):
            return self._payload

    class FakeAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse({"access_token": "github-oauth-token", "scope": "repo,workflow,read:org,user:email"})

        async def get(self, url, *args, **kwargs):
            if url.endswith("/user"):
                return FakeResponse(
                    {"id": 456, "login": "originfallback", "email": "originfallback@example.com"},
                    headers={"X-OAuth-Scopes": "repo,workflow,read:org,user:email"},
                )
            return FakeResponse([])

    monkeypatch.setattr("app.api.routes_auth.httpx.AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "github-client")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "github-secret")
    monkeypatch.setattr(settings, "FRONTEND_URL", "")
    monkeypatch.setattr(settings, "DEBUG", True)

    state = client.get(
        "/api/v1/auth/github",
        params={
            "privacy_policy_accepted": "true",
            "privacy_policy_version": PRIVACY_POLICY_VERSION,
        },
        follow_redirects=False,
    ).headers["location"].split("state=", 1)[1].split("&", 1)[0]

    response = client.get(
        "/api/v1/auth/github/callback",
        params={"code": "oauth-code", "state": state},
        follow_redirects=False,
    )

    assert response.headers["location"].startswith("http://testserver/signin?code=")
    assert "localhost" not in response.headers["location"]


def test_policy_event_logging_records_security_log():
    response = client.post(
        "/api/v1/auth/policy-events",
        json={
            "policy": "privacy_policy",
            "event_type": "page_view",
            "policy_version": PRIVACY_POLICY_VERSION,
            "source": "pytest",
            "href": "/privacy-policy",
            "page_path": "/privacy-policy",
            "referrer_path": "/signin",
        },
    )
    assert response.status_code == 202

    db = SessionLocal()
    try:
        log = db.query(SecurityLog).filter(SecurityLog.action == "policy.privacy_policy.page_view").first()
        assert log is not None
        assert log.details is not None
        assert '"page_path":"/privacy-policy"' in log.details
        assert '"policy_version_matches_current":true' in log.details
        assert '"source":"pytest"' in log.details
    finally:
        db.close()


def test_policy_event_logging_redacts_sensitive_details():
    response = client.post(
        "/api/v1/auth/policy-events",
        json={
            "policy": "privacy_policy",
            "event_type": "link_click",
            "policy_version": PRIVACY_POLICY_VERSION,
            "source": "pytest",
            "href": "https://app.example/path?token=secret-token-value",
            "page_path": "/signin",
            "referrer_path": "https://app.example/start?access_token=secret",
        },
    )
    assert response.status_code == 202

    db = SessionLocal()
    try:
        log = db.query(SecurityLog).filter(SecurityLog.action == "policy.privacy_policy.link_click").first()
        assert log is not None
        serialized_details = str(log.details or "{}")
        details = json.loads(serialized_details)
        assert details["href"] == "https://app.example/path"
        assert details["referrer_path"] == "https://app.example/start"
        assert "secret-token-value" not in serialized_details
    finally:
        db.close()


def test_oauth_code_exchange():
    original_frontend_url = settings.FRONTEND_URL
    original_debug = settings.DEBUG
    settings.FRONTEND_URL = "https://app.firecrow.test"
    settings.DEBUG = False

    db = SessionLocal()
    try:
        token = create_access_token(user_id="usr_test_oauth", username="oauth_tester", db=db)
        code = create_exchange_code(user_id="usr_test_oauth", username="oauth_tester", token=token, db=db)

        stored_code = db.query(AuthExchangeCode).filter(AuthExchangeCode.code == code).first()
        assert stored_code is not None

        response = client.post("/api/v1/auth/exchange", json={"code": code})
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == token
        assert data["username"] == "oauth_tester"
        assert data["user_id"] == "usr_test_oauth"
        set_cookie = response.headers["set-cookie"]
        assert f"{AUTH_COOKIE_NAME}=" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "Secure" in set_cookie
        assert "SameSite=strict" in set_cookie

        db.expire_all()
        consumed_code = db.query(AuthExchangeCode).filter(AuthExchangeCode.code == code).first()
        assert consumed_code is None

        response_retry = client.post("/api/v1/auth/exchange", json={"code": code})
        assert response_retry.status_code == 400
    finally:
        db.close()
        settings.FRONTEND_URL = original_frontend_url
        settings.DEBUG = original_debug


def test_user_activity_logging():
    username = f"logtester_{uuid.uuid4().hex[:6]}"

    def fetch_activity_rows(db_session, target_user_id: str) -> list[UserActivityEvent]:
        return (
            db_session.query(UserActivityEvent)
            .filter(UserActivityEvent.user_id == target_user_id)
            .order_by(UserActivityEvent.created_at.desc())
            .all()
        )

    token, user_id = _create_test_user_and_token(username)

    db = SessionLocal()
    try:
        from app.api.routes_auth import _add_user_activity, TERMS_VERSION
        user = db.query(User).filter(User.id == user_id).first()
        assert user is not None
        user.terms_version = TERMS_VERSION
        user.terms_accepted_at = datetime.now(timezone.utc)
        user.first_login_at = datetime.now(timezone.utc)
        user.last_login_at = datetime.now(timezone.utc)
        
        _add_user_activity(db, user_id=user.id, action="register", details={"email": user.email})
        _add_user_activity(db, user_id=user.id, action="login", details={"provider": "github"})
        db.commit()

        activity_history = fetch_activity_rows(db, user_id)
        activity_actions = [entry.action for entry in activity_history]
        assert "login" in activity_actions
        assert "register" in activity_actions
    finally:
        db.close()

    policy_response = client.post(
        "/api/v1/auth/policy-events",
        json={
            "policy": "privacy_policy",
            "policy_version": PRIVACY_POLICY_VERSION,
            "event_type": "link_click",
            "source": "footer",
            "href": "https://app.example/path",
            "page_path": "/dashboard",
            "referrer_path": "/home"
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert policy_response.status_code == 202

    db = SessionLocal()
    try:
        activity_history = fetch_activity_rows(db, user_id)
        assert len(activity_history) >= 3
        assert activity_history[0].action == "policy_privacy_policy_link_click"
    finally:
        db.close()

    logout_response = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout_response.status_code == 200

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        assert user is not None
        assert user.last_logout_at is not None
        activity_history = fetch_activity_rows(db, user_id)
        assert len(activity_history) >= 4
        assert activity_history[0].action == "logout"
    finally:
        db.close()


def test_redis_miss_falls_back_to_db(monkeypatch):
    class FakeRedis:
        def exists(self, key: str) -> int:
            return 0

        def setex(self, key: str, ttl: int, value: str) -> None:
            pass

    fake_redis = FakeRedis()
    monkeypatch.setattr("app.services.auth._get_redis_client", lambda: fake_redis)

    token, _ = _create_test_user_and_token("redis_miss")

    logout_response = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_response.status_code == 200

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_redis_outage_falls_back_to_db(monkeypatch):
    class CrashingRedis:
        def exists(self, key: str) -> int:
            raise Exception("Connection timeout")

        def setex(self, key: str, ttl: int, value: str) -> None:
            raise Exception("Connection timeout")

    crashing_redis = CrashingRedis()
    monkeypatch.setattr("app.services.auth._get_redis_client", lambda: crashing_redis)

    token, _ = _create_test_user_and_token("redis_outage")

    client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_auth_me_bearer_no_cookies():
    token, user_id = _create_test_user_and_token("cleanclient")

    clean_client = TestClient(app)
    response = clean_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["user_id"] == user_id
    assert response.json()["username"] == "cleanclient"


def test_github_mock_oauth_flow(monkeypatch):
    monkeypatch.setattr(settings, "DEBUG", True)
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "mock_github_client_id")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "mock_github_client_secret")

    login_response = client.get(
        "/api/v1/auth/github",
        params={
            "privacy_policy_accepted": "true",
            "privacy_policy_version": PRIVACY_POLICY_VERSION,
        },
        follow_redirects=False,
    )
    assert login_response.status_code in {302, 307}
    location = login_response.headers["location"]

    parsed = urlparse(location)
    query_params = parse_qs(parsed.query)
    assert "code" in query_params
    assert "state" in query_params

    code = query_params["code"][0]
    state = query_params["state"][0]
    assert code == "mock_github_code"

    callback_response = client.get(
        "/api/v1/auth/github/callback",
        params={
            "code": code,
            "state": state,
        },
        follow_redirects=False,
    )
    assert callback_response.status_code in {302, 307}
    callback_location = callback_response.headers["location"]
    assert "code=" in callback_location
