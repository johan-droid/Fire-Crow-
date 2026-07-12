from datetime import datetime, timezone
from typing import Literal, Optional
import urllib.parse
import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import func, inspect as sa_inspect
from sqlalchemy.orm import Session

from app.config import settings
from app.models.database import get_db
from app.models.user import User, GithubCredential
from app.services.auth import (
    ACCESS_TOKEN_EXPIRE_SECONDS,
    REFRESH_TOKEN_EXPIRE_SECONDS,
    REFRESH_COOKIE_NAME,
    create_access_token,
    create_exchange_code,
    create_oauth_state,
    create_refresh_token,
    encrypt_provider_token,
    get_current_token_payload,
    get_current_user,
    get_optional_current_user,
    hash_password,
    password_needs_rehash,
    revoke_access_token,
    revoke_token_family,
    verify_and_consume_exchange_code,
    verify_oauth_state,
    verify_password,
    verify_refresh_token,
    check_login_lockout,
    record_login_failure,
    clear_login_failures,
)
from app.services.security_log import record_security_event
from app.services.limiter import limiter
from app.services.user_activity import append_user_activity, list_user_activities

router = APIRouter(prefix="/auth", tags=["Authentication"])

PRIVACY_POLICY_VERSION = settings.PRIVACY_POLICY_VERSION
TERMS_VERSION = settings.TERMS_VERSION
GITHUB_OAUTH_SCOPES = tuple(settings.GITHUB_OAUTH_SCOPES)
COMMON_PASSWORDS = {
    "password",
    "password123",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty123",
    "letmein123",
    "admin123",
    "welcome123",
}



class LoginRequest(BaseModel):
    username: str
    password: str
    privacy_policy_accepted: bool
    privacy_policy_version: str
    timezone: Optional[str] = None
    region: Optional[str] = None


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    privacy_policy_accepted: bool
    privacy_policy_version: str
    timezone: Optional[str] = None
    region: Optional[str] = None


class PolicyEventRequest(BaseModel):
    policy: Literal["terms", "privacy_policy"]
    event_type: Literal["link_click", "page_view"]
    policy_version: str
    source: Optional[str] = None
    href: Optional[str] = None
    page_path: Optional[str] = None
    referrer_path: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    user_id: str


def _normalize_username(username: str) -> str:
    return username.strip()


def _normalize_email(email: Optional[str]) -> Optional[str]:
    normalized = email.strip().lower() if email else None
    return normalized or None


def _user_id_for(username: str) -> str:
    safe = "".join(char.lower() if char.isalnum() else "_" for char in username).strip("_")
    return f"usr_{safe or 'workspace'}"


def _new_user_id() -> str:
    return str(uuid.uuid4())


def _validate_privacy_consent(accepted: bool, version: str) -> None:
    if not accepted:
        raise HTTPException(status_code=400, detail="Privacy Policy consent is required.")
    if version != PRIVACY_POLICY_VERSION:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported Privacy Policy version. Expected {PRIVACY_POLICY_VERSION}.",
        )


def _validate_password_strength(password: str, username: str, email: Optional[str] = None) -> None:
    if len(password) < settings.MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters.",
        )

    normalized_password = password.strip().lower()
    if normalized_password in COMMON_PASSWORDS:
        raise HTTPException(status_code=400, detail="Password is too common. Choose a less guessable password.")

    identifiers = {username.strip().lower()}
    if email and "@" in email:
        identifiers.add(email.split("@", 1)[0].strip().lower())
    if any(identifier and len(identifier) >= 4 and identifier in normalized_password for identifier in identifiers):
        raise HTTPException(
            status_code=400,
            detail="Password must not contain your username or email name.",
        )

def _add_user_activity(
    db: Session,
    *,
    user_id: str,
    action: str,
    details: Optional[dict] = None,
) -> None:
    append_user_activity(db, user_id=user_id, action=action, details=details)


def _apply_consents(db: Session, user: User, privacy_version: str) -> None:
    now = datetime.now(timezone.utc)
    user.privacy_policy_version = privacy_version
    user.privacy_policy_accepted_at = now
    
    # Automatically accept terms as well since frontend terms and privacy are accepted in a single checkbox
    if not user.terms_accepted_at:
        user.terms_accepted_at = now
        user.terms_version = TERMS_VERSION
        _add_user_activity(
            db,
            user_id=user.id,
            action="terms_accepted",
            details={"version": TERMS_VERSION, "info": "first_time_accept"},
        )


def _current_policy_version(policy: Literal["terms", "privacy_policy"]) -> str:
    if policy == "terms":
        return TERMS_VERSION
    return PRIVACY_POLICY_VERSION


def _ensure_unique_username(db: Session, username: str) -> str:
    candidate = username
    suffix = 1
    while db.query(User).filter(User.username == candidate).first():
        candidate = f"{username}{suffix}"
        suffix += 1
    return candidate


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def _login_rate_key(request: Request, username: str) -> str:
    return f"{_client_ip(request)}:{username.strip().lower()}"


def _enforce_login_attempt_limit(request: Request, username: str, db: Session) -> None:
    ip = _client_ip(request)
    if check_login_lockout(db, ip, username):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please wait before trying again.",
        )


def _record_login_failure(request: Request, username: str, db: Session) -> None:
    ip = _client_ip(request)
    record_login_failure(db, ip, username)


def _clear_login_failures(request: Request, username: str, db: Session) -> None:
    ip = _client_ip(request)
    clear_login_failures(db, ip, username)


def _find_unique_user_by_normalized_email(
    db: Session,
    email: Optional[str],
    *,
    provider: str,
    request: Request,
) -> Optional[User]:
    normalized_email = _normalize_email(email)
    if not normalized_email:
        return None

    users = db.query(User).filter(func.lower(User.email) == normalized_email).all()
    if len(users) > 1:
        record_security_event(
            db,
            action=f"auth.oauth.{provider}.duplicate_email_blocked",
            request=request,
            details={"email": normalized_email, "matches": len(users)},
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This email is linked to multiple workspaces. Sign in with workspace credentials or contact support.",
        )
    return users[0] if users else None


def _cookie_secure() -> bool:
    return (not settings.DEBUG) or settings.FRONTEND_URL.startswith("https://")


def _set_session_cookie(response: Response, token: str) -> None:
    cookie_secure = settings.AUTH_COOKIE_SECURE
    if settings.DEBUG:
        cookie_secure = _cookie_secure()
    response.set_cookie(
        key=settings.AUTH_COOKIE_NAME,
        value=token,
        max_age=ACCESS_TOKEN_EXPIRE_SECONDS,
        httponly=settings.AUTH_COOKIE_HTTPONLY,
        secure=cookie_secure,
        samesite=settings.AUTH_COOKIE_SAMESITE,  # type: ignore
        path="/",
    )


def _set_refresh_cookie(response: Response, token: str) -> None:
    cookie_secure = settings.AUTH_COOKIE_SECURE
    if settings.DEBUG:
        cookie_secure = _cookie_secure()
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=token,
        max_age=REFRESH_TOKEN_EXPIRE_SECONDS,
        httponly=settings.AUTH_COOKIE_HTTPONLY,
        secure=cookie_secure,
        samesite=settings.AUTH_COOKIE_SAMESITE,  # type: ignore
        path="/",
    )


def _request_origin(request: Request) -> str:
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    forwarded_host = request.headers.get("x-forwarded-host", "")
    scheme = forwarded_proto.split(",", 1)[0].strip() or request.url.scheme
    host = forwarded_host.split(",", 1)[0].strip() or request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}".rstrip("/")


def _frontend_signin_url(request: Request | None = None) -> str:
    if settings.DEBUG and request:
        origin = _request_origin(request)
        if "localhost" in origin or "127.0.0.1" in origin:
            import urllib.parse
            parsed = urllib.parse.urlparse(origin)
            netloc = parsed.netloc
            if ":" in netloc:
                host_part = netloc.split(":")[0]
                netloc = f"{host_part}:3000"
            else:
                netloc = f"{netloc}:3000"
            return f"{parsed.scheme}://{netloc}/"
    frontend_base_url = settings.FRONTEND_URL.rstrip("/")
    if frontend_base_url:
        return f"{frontend_base_url}/"
    if request:
        return f"{_request_origin(request)}/"
    return "/"


def _parse_scope_string(scope_string: Optional[str]) -> list[str]:
    if not scope_string:
        return []
    return sorted({scope.strip() for scope in scope_string.split(",") if scope.strip()})


def _github_provider_payload(user: User) -> dict:
    scopes = _parse_scope_string(user.github_token_scopes)
    return {
        "connected": bool(user.github_id and user.github_access_token),
        "private_repo_access": "repo" in scopes,
        "pr_write_access": "repo" in scopes,
        "workflow_write_access": "workflow" in scopes,
        "org_read_access": "read:org" in scopes,
        "scopes": scopes,
        "required_scopes": list(GITHUB_OAUTH_SCOPES),
        "token_persisted": bool(user.github_access_token),
    }


def _user_session_payload(user: User) -> dict:
    return {
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "role": "security_engineer",
        "privacy_policy_version": user.privacy_policy_version,
        "privacy_policy_accepted_at": user.privacy_policy_accepted_at.isoformat()
        if user.privacy_policy_accepted_at
        else None,
        "providers": {
            "github": _github_provider_payload(user),
            "google": {"connected": bool(user.google_id)},
        },
    }


def _oauth_redirect_url(request: Request, route_name: str) -> str:
    # If BACKEND_BASE_URL is set, use it as the base for the redirect URI.
    if settings.BACKEND_BASE_URL:
        from urllib.parse import urljoin
        # url_for generates a path like '/api/v1/auth/github/callback'
        path = request.url_for(route_name)
        # Ensure the base URL ends with a slash for urljoin to work correctly.
        base = settings.BACKEND_BASE_URL.rstrip("/") + "/"
        return urljoin(base, path.lstrip("/"))
    # Fallback to original behavior: use the request's scheme and host, possibly overridden by headers.
    url = request.url_for(route_name)
    proto = request.headers.get("x-forwarded-proto")
    if proto:
        proto = proto.split(",")[0].strip()
        url = url.replace(scheme=proto)
    elif not settings.DEBUG or settings.FRONTEND_URL.startswith("https://"):
        url = url.replace(scheme="https")
    return str(url)


class ExchangePayload(BaseModel):
    code: str


@router.post("/exchange")
@limiter.limit("20/minute")
async def exchange_token(
    payload: ExchangePayload,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    data = verify_and_consume_exchange_code(payload.code, db=db)
    if not data:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired exchange code"
        )
    _set_session_cookie(response, data["access_token"])
    refresh_token = create_refresh_token(user_id=data["user_id"], username=data["username"], db=db)
    _set_refresh_cookie(response, refresh_token)
    return TokenResponse(
        access_token=data["access_token"],
        token_type="bearer",
        username=data["username"],
        user_id=data["user_id"],
    )


class RefreshPayload(BaseModel):
    refresh_token: Optional[str] = None


@router.post("/refresh")
@limiter.limit("10/minute")
async def refresh_token(
    request: Request,
    response: Response,
    payload: RefreshPayload | None = None,
    db: Session = Depends(get_db),
):
    refresh_token_val = request.cookies.get(REFRESH_COOKIE_NAME)
    if payload and payload.refresh_token:
        refresh_token_val = payload.refresh_token

    if not refresh_token_val:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not provided",
        )

    from app.services.auth import verify_refresh_token_with_rotation
    rotation_result = verify_refresh_token_with_rotation(
        refresh_token_val,
        db=db,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    if not rotation_result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked refresh token. Please sign in again.",
        )

    old_payload = rotation_result["old_payload"]
    access_token = rotation_result["new_access_token"]
    new_refresh_token = rotation_result["new_refresh_token"]

    user_id = old_payload.get("sub")
    raw_username = old_payload.get("username")
    username: str = raw_username if isinstance(raw_username, str) and raw_username else (user_id or "")

    _set_session_cookie(response, access_token)
    _set_refresh_cookie(response, new_refresh_token)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        username=username,
        user_id=user_id,
    )


@router.get("/policy-context")
@limiter.limit("30/minute")
async def policy_context(request: Request):
    return {
        "privacy_policy_version": PRIVACY_POLICY_VERSION,
        "terms_version": TERMS_VERSION,
        "providers": {
            "github": bool(settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET),
            "google": False,
            "password": True,
        },
    }


@router.post("/policy-events", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("30/minute")
async def create_policy_event(
    payload: PolicyEventRequest,
    request: Request,
    user_id: Optional[str] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    current_version = _current_policy_version(payload.policy)
    
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            _add_user_activity(
                db,
                user_id=user.id,
                action=f"policy_{payload.policy}_{payload.event_type}",
                details={"version": payload.policy_version},
            )
            db.commit()

    record_security_event(
        db,
        action=f"policy.{payload.policy}.{payload.event_type}",
        request=request,
        user_id=user_id,
        details={
            "policy": payload.policy,
            "policy_version": payload.policy_version,
            "current_policy_version": current_version,
            "policy_version_matches_current": payload.policy_version == current_version,
            "source": payload.source,
            "href": payload.href,
            "page_path": payload.page_path,
            "referrer_path": payload.referrer_path,
            "api_path": request.url.path,
        },
    )
    return {"status": "recorded"}


@router.post("/register")
async def register(
    request: Request,
    response: Response,
    payload: RegisterRequest,
    db: Session = Depends(get_db),
):
    _validate_privacy_consent(payload.privacy_policy_accepted, payload.privacy_policy_version)
    _validate_password_strength(payload.password, payload.username, payload.email)

    username = _normalize_username(payload.username)
    email = _normalize_email(payload.email)

    if settings.DATABASE_BACKEND == "neo4j":
        # Neo4j backend
        from app.graph.store import GraphStore
        graph_store = GraphStore()
        if graph_store.username_exists(username):
            raise HTTPException(status_code=400, detail="Username already taken")
        if email and graph_store.email_exists(email):
            raise HTTPException(status_code=400, detail="Email already registered")
        user_id = _new_user_id()
        hashed_password = hash_password(payload.password)
        from app.graph.store import GraphUser
        user = GraphUser(
            id=user_id,
            username=username,
            email=email,
            password_hash=hashed_password,
            credit_balance=10.0,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        # Apply consents
        now = datetime.now(timezone.utc)
        user.privacy_policy_version = payload.privacy_policy_version
        user.privacy_policy_accepted_at = now
        if not user.terms_accepted_at:
            user.terms_accepted_at = now
            user.terms_version = TERMS_VERSION
        graph_store.persist_user(user)
        # Record activity
        graph_store.create_user_activity(user_id, "register", {"privacy_policy_version": payload.privacy_policy_version})
        # Create tokens (db=None signals auth service to use graph store for sessions)
        access_token = create_access_token(
            user_id=user.id,
            username=user.username,
            db=None,
            ip=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        refresh_token = create_refresh_token(user_id=user.id, username=user.username, db=None)
        _set_session_cookie(response, access_token)
        _set_refresh_cookie(response, refresh_token)
        record_security_event(
            db,  # db is None, but the record_security_event function can handle None? Let's check.
            action="auth.register.success",
            request=request,
            user_id=user.id,
            details={
                "username": user.username,
                "privacy_policy_version": payload.privacy_policy_version,
            },
        )
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            username=user.username,
            user_id=user.id,
        )
    else:
        # SQL backend
        # Ensure username is unique
        username = _ensure_unique_username(db, username)

        # Create new user
        user_id = _new_user_id()
        hashed_password = hash_password(payload.password)
        user = User(
            id=user_id,
            username=username,
            email=email,
            password_hash=hashed_password,
        )
        db.add(user)
        db.flush()

        # Apply consents (privacy policy and terms)
        _apply_consents(db, user, payload.privacy_policy_version)

        # Update first and last login times
        now = datetime.now(timezone.utc)
        user.first_login_at = now
        user.last_login_at = now

        _add_user_activity(
            db,
            user_id=user.id,
            action="register",
            details={"privacy_policy_version": payload.privacy_policy_version},
        )

        # Create access and refresh tokens
        access_token = create_access_token(
            user_id=user.id,
            username=user.username,
            db=db,
            ip=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        refresh_token = create_refresh_token(user_id=user.id, username=user.username, db=db)

        _set_session_cookie(response, access_token)
        _set_refresh_cookie(response, refresh_token)

        record_security_event(
            db,
            action="auth.register.success",
            request=request,
            user_id=user.id,
            details={
                "username": user.username,
                "privacy_policy_version": payload.privacy_policy_version,
            },
        )

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            username=user.username,
            user_id=user.id,
        )


@router.post("/login")
async def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    db: Session = Depends(get_db),
):
    _validate_privacy_consent(payload.privacy_policy_accepted, payload.privacy_policy_version)

    username = _normalize_username(payload.username)
    # Normalize email? Not needed for login, but we can keep it for consistency if we want to allow email as username?
    # Currently, we only support username for login. If we want to support email, we would need to adjust.

    # Find user by username
    user = db.query(User).filter(User.username == username).first()
    if not user:
        # Instead of revealing that the user doesn't exist, we can still check the password to avoid user enumeration.
        # But for simplicity, we'll just raise an invalid credentials error.
        # However, to prevent user enumeration, we should always compute the hash and compare.
        # We'll use a dummy hash to compare if the user doesn't exist.
        hash_password("dummy")  # This is to prevent timing attacks by always computing a hash.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check password
    if not verify_password(payload.password, user.password_hash):
        # Record login failure
        _record_login_failure(request, username, db)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Clear any login failures on successful login
    _clear_login_failures(request, username, db)

    # Update last login time
    user.last_login_at = datetime.now(timezone.utc)
    db.add(user)
    db.commit()

    _add_user_activity(
        db,
        user_id=user.id,
        action="login",
        details={"privacy_policy_version": payload.privacy_policy_version},
    )

    # Create access and refresh tokens
    access_token = create_access_token(
        user_id=user.id,
        username=user.username,
        db=db,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    refresh_token = create_refresh_token(user_id=user.id, username=user.username, db=db)

    _set_session_cookie(response, access_token)
    _set_refresh_cookie(response, refresh_token)

    record_security_event(
        db,
        action="auth.login.success",
        request=request,
        user_id=user.id,
        details={
            "username": user.username,
            "privacy_policy_version": payload.privacy_policy_version,
        },
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        username=user.username,
        user_id=user.id,
    )


@router.post("/logout")
@limiter.limit("20/minute")
async def logout(
    request: Request,
    response: Response,
    token_payload: dict = Depends(get_current_token_payload),
    db: Session = Depends(get_db),
):
    user_id = str(token_payload.get("sub", ""))
    # Revoke the specific access token and, if possible, the entire token family.
    token_family = token_payload.get("token_family")
    revoked = revoke_access_token(token_payload, db=db)
    if token_family:
        revoked = revoke_token_family(token_family, db=db) or revoked
    if not revoked:
        raise HTTPException(status_code=503, detail="Logout could not revoke the active session.")

    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.last_logout_at = datetime.now(timezone.utc)
        _add_user_activity(db, user_id=user.id, action="logout")
        db.commit()

    record_security_event(
        db,
        action="auth.logout",
        request=request,
        user_id=user_id,
        details={"source": "frontend"},
    )
    response.delete_cookie(settings.AUTH_COOKIE_NAME, path="/", secure=settings.AUTH_COOKIE_SECURE, httponly=settings.AUTH_COOKIE_HTTPONLY, samesite=settings.AUTH_COOKIE_SAMESITE)
    response.delete_cookie(REFRESH_COOKIE_NAME, path="/", secure=settings.AUTH_COOKIE_SECURE, httponly=settings.AUTH_COOKIE_HTTPONLY, samesite=settings.AUTH_COOKIE_SAMESITE)
    return {"status": "logged_out"}


@router.get("/me")
@limiter.limit("60/minute")
async def get_me(request: Request, user_id: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User session could not be resolved.")

    return _user_session_payload(user)


@router.get("/session")
@limiter.limit("60/minute")
async def get_session(request: Request, user_id: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User session could not be resolved.")
    return _user_session_payload(user)


@router.get("/activities")
@limiter.limit("30/minute")
async def get_user_activities(request: Request, user_id: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return list_user_activities(db, user_id=user_id)


@router.get("/github")
@limiter.limit("10/minute")
async def github_login(
    request: Request,
    privacy_policy_accepted: bool,
    privacy_policy_version: str,
    timezone: Optional[str] = None,
    region: Optional[str] = None,
    db: Session = Depends(get_db),
):
    if not settings.GITHUB_CLIENT_ID or not settings.GITHUB_CLIENT_SECRET:
        raise HTTPException(status_code=503, detail="GitHub OAuth is not configured.")

    if settings.DEBUG and settings.GITHUB_CLIENT_ID == "mock_github_client_id":
        _validate_privacy_consent(privacy_policy_accepted, privacy_policy_version)
        oauth_state = create_oauth_state(
            "github",
            privacy_policy_version,
            timezone_name=timezone,
            region=region,
        )
        callback_url = _oauth_redirect_url(request, "github_callback")
        redirect_url = f"{callback_url}?code=mock_github_code&state={oauth_state}"
        return RedirectResponse(redirect_url)

    _validate_privacy_consent(privacy_policy_accepted, privacy_policy_version)
    oauth_state = create_oauth_state(
        "github",
        privacy_policy_version,
        timezone_name=timezone,
        region=region,
    )

    record_security_event(
        db,
        action="auth.oauth.github.initiated",
        request=request,
        details={
            "policy_version": privacy_policy_version,
            "timezone": timezone,
            "region": region,
        },
    )

    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": _oauth_redirect_url(request, "github_callback"),
        "scope": ",".join(GITHUB_OAUTH_SCOPES),
        "state": oauth_state,
    }
    url = f"https://github.com/login/oauth/authorize?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url)


@router.get("/github/callback")
@limiter.limit("20/minute")
async def github_callback(
    request: Request,
    code: str,
    state: str,
    db: Session = Depends(get_db),
):
    if not settings.GITHUB_CLIENT_ID or not settings.GITHUB_CLIENT_SECRET:
        raise HTTPException(status_code=503, detail="GitHub OAuth is not configured.")

    oauth_state = verify_oauth_state(state)
    if not oauth_state or oauth_state.get("provider") != "github":
        raise HTTPException(status_code=400, detail="Invalid or expired GitHub OAuth state.")

    if settings.DEBUG and code == "mock_github_code":
        github_id = "999999"
        username = "mock_github_user"
        email = "mock_github_user@example.com"
        granted_scope_string = "repo,workflow,read:org,user:email"
        access_token = "mock_github_access_token"
    else:
        async with httpx.AsyncClient() as client:
            token_res = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": settings.GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": _oauth_redirect_url(request, "github_callback"),
                },
            )
            if token_res.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to retrieve access token from GitHub.")

            token_data = token_res.json()
            access_token = token_data.get("access_token")
            if not access_token:
                raise HTTPException(
                    status_code=400,
                    detail=f"GitHub OAuth error: {token_data.get('error_description', 'No access token')}",
                )
            granted_scope_string = str(token_data.get("scope") or "")

            user_res = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {access_token}"},
            )
            if user_res.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to retrieve user profile from GitHub.")
            if not granted_scope_string:
                granted_scope_string = str(getattr(user_res, "headers", {}).get("X-OAuth-Scopes", ""))

            profile = user_res.json()
            github_id = str(profile.get("id"))
            username = profile.get("login") or f"github_{github_id}"
            email = _normalize_email(profile.get("email"))

            if not email:
                emails_res = await client.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"token {access_token}"},
                )
                if emails_res.status_code == 200:
                    for email_obj in emails_res.json():
                        if email_obj.get("primary"):
                            email = _normalize_email(email_obj.get("email"))
                            break

    user = db.query(User).filter(User.github_id == github_id).first()
    if not user and email:
        user = _find_unique_user_by_normalized_email(db, email, provider="github", request=request)
        if user:
            user.github_id = github_id

    if not user:
        username = _ensure_unique_username(db, username)
        user = User(
            id=_new_user_id(),
            username=username,
            email=email,
            github_id=github_id,
        )
        db.add(user)

    user_state = sa_inspect(user)
    if user_state.transient:
        db.add(user)
    if not user_state.persistent:
        db.flush()
    _apply_consents(db, user, oauth_state["privacy_policy_version"])
    now = datetime.now(timezone.utc)
    if not user.first_login_at:
        user.first_login_at = now
    user.last_login_at = now
    user.github_access_token = encrypt_provider_token(access_token)
    user.github_token_scopes = ",".join(_parse_scope_string(granted_scope_string))
    user.github_token_updated_at = now
    
    tz_name = oauth_state.get("timezone")
    reg_name = oauth_state.get("region")
    user.region = reg_name
    user.timezone = tz_name
    
    _add_user_activity(
        db,
        user_id=user.id,
        action="login",
        details={
            "provider": "github",
            "timezone": tz_name,
            "region": reg_name,
        },
    )

    # Store/update OAuth credentials in the github_credentials table
    cred = db.query(GithubCredential).filter(GithubCredential.github_id == github_id).first()
    if not cred:
        cred = GithubCredential(
            user_id=user.id,
            github_id=github_id,
            access_token=encrypt_provider_token(access_token),
            scopes=",".join(_parse_scope_string(granted_scope_string)),
        )
        db.add(cred)
    else:
        cred.access_token = encrypt_provider_token(access_token)
        cred.scopes = ",".join(_parse_scope_string(granted_scope_string))

    db.commit()
    db.refresh(user)

    token = create_access_token(
        user_id=user.id,
        username=user.username,
        db=db,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    refresh_token = create_refresh_token(user_id=user.id, username=user.username, db=db)

    record_security_event(
        db,
        action="auth.oauth.github.success",
        request=request,
        user_id=user.id,
        details={
            "username": user.username,
            "timezone": tz_name,
            "region": reg_name,
            "github_scopes": _parse_scope_string(granted_scope_string),
        },
    )
    record_security_event(
        db,
        action="policy.privacy_policy.accepted",
        request=request,
        user_id=user.id,
        details={
            "policy_version": oauth_state["privacy_policy_version"],
            "source": "github_oauth",
            "timezone": tz_name,
            "region": reg_name,
        },
    )

    code = create_exchange_code(user_id=user.id, username=user.username, token=token, db=db)
    response = RedirectResponse(f"{_frontend_signin_url(request)}signin?code={code}")
    _set_session_cookie(response, token)
    _set_refresh_cookie(response, refresh_token)
    return response


@router.get("/google")
async def google_login():
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Google authentication is disabled. Only GitHub OAuth authentication is supported."
    )


@router.get("/google/callback")
async def google_callback():
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Google authentication is disabled. Only GitHub OAuth authentication is supported."
    )
