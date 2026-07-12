from __future__ import annotations

import hashlib
import hmac
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.models.database import get_db

from app.config import settings
from app.services.crypto import crypto_manager

logger = logging.getLogger("firecrow.services.auth")

security = HTTPBearer(auto_error=False)

ALGORITHM = "HS256"
JWT_ISSUER = "firecrow-api"
JWT_AUDIENCE = "firecrow-web"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
ACCESS_TOKEN_EXPIRE_SECONDS = ACCESS_TOKEN_EXPIRE_MINUTES * 60
REFRESH_TOKEN_EXPIRE_DAYS = 30
REFRESH_TOKEN_EXPIRE_SECONDS = REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
OAUTH_STATE_EXPIRE_MINUTES = 15
AUTH_COOKIE_NAME = "fc_access_token"
REFRESH_COOKIE_NAME = "fc_refresh_token"

_password_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

_redis_client = None
_redis_checked = False


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> int:
    return int(value.timestamp())


def _coerce_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _get_redis_client():
    global _redis_checked, _redis_client
    if _redis_checked:
        return _redis_client

    _redis_checked = True
    if not settings.REDIS_URL:
        return None

    try:
        import redis

        client = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.25, socket_timeout=0.25)
        client.ping()
        _redis_client = client
    except Exception:
        logger.critical("Redis unavailable. Token revocation checks will deny all tokens for safety (fail-closed). Set REDIS_URL or expect degraded auth.")
        _redis_client = None

    return _redis_client


def _denylist_key(jti: str) -> str:
    return f"firecrow:revoked_jti:{jti}"





def _claims(expires_delta: timedelta) -> tuple[datetime, datetime, datetime, str]:
    now = _utc_now()
    not_before = now - timedelta(seconds=5)
    expire = now + expires_delta
    return now, not_before, expire, str(uuid.uuid4())


def create_access_token(
    user_id: str,
    username: Optional[str] = None,
    *,
    db: Optional[Session] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    token_family: Optional[str] = None,
) -> str:
    expire_minutes = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    now, not_before, expire, jti = _claims(timedelta(minutes=expire_minutes))
    family = token_family or str(uuid.uuid4())
    to_encode = {
        "sub": user_id,
        "username": username,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": _timestamp(now),
        "nbf": _timestamp(not_before),
        "exp": _timestamp(expire),
        "jti": jti,
        "token_family": family,
    }
    token = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)

    if settings.DATABASE_BACKEND == "neo4j":
        from app.graph.store import graph_store
        graph_store.create_user_session(
            session_id=jti,
            user_id=user_id,
            token_family=family,
            ip_hash=hashlib.sha256((ip or "unknown").encode("utf-8")).hexdigest(),
            user_agent_hash=hashlib.sha256((user_agent or "unknown").encode("utf-8")).hexdigest(),
            expires_at=expire,
        )
    elif db is not None:
        from app.models.user import UserSession
        ip_str = ip or "unknown"
        ua_str = user_agent or "unknown"
        ip_h = hashlib.sha256(ip_str.encode("utf-8")).hexdigest()
        ua_h = hashlib.sha256(ua_str.encode("utf-8")).hexdigest()

        session_obj = UserSession(
            id=jti,
            user_id=user_id,
            token_family=family,
            ip_hash=ip_h,
            user_agent_hash=ua_h,
            created_at=now,
            expires_at=expire,
            is_revoked=False,
        )
        db.add(session_obj)
        db.commit()

    return token


def create_refresh_token(
    user_id: str,
    username: Optional[str] = None,
    *,
    db: Optional[Session] = None,
    token_family: Optional[str] = None,
) -> str:
    """Create a long-lived refresh token for session renewal."""
    now, not_before, expire, jti = _claims(timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    family = token_family or str(uuid.uuid4())
    to_encode = {
        "sub": user_id,
        "username": username,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": _timestamp(now),
        "nbf": _timestamp(not_before),
        "exp": _timestamp(expire),
        "jti": jti,
        "token_family": family,
        "type": "refresh",
    }
    token = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)

    if settings.DATABASE_BACKEND == "neo4j":
        from app.graph.store import graph_store
        graph_store.create_user_session(
            session_id=jti,
            user_id=user_id,
            token_family=family,
            ip_hash="refresh",
            user_agent_hash="refresh",
            expires_at=expire,
        )
    elif db is not None:
        from app.models.user import UserSession
        session_obj = UserSession(
            id=jti,
            user_id=user_id,
            token_family=family,
            ip_hash="refresh",
            user_agent_hash="refresh",
            created_at=now,
            expires_at=expire,
            is_revoked=False,
        )
        db.add(session_obj)
        db.commit()

    return token


def verify_refresh_token(token: str, *, db: Optional[Session] = None) -> Optional[dict]:
    """Verify a refresh token and return its payload if valid."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            leeway=5,
        )
    except jwt.PyJWTError:
        return None

    if payload.get("type") != "refresh":
        return None

    if is_token_revoked(payload, db=db):
        return None

    return payload


def create_oauth_state(
    provider: str,
    privacy_policy_version: str,
    timezone_name: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    now, not_before, expire, jti = _claims(timedelta(minutes=OAUTH_STATE_EXPIRE_MINUTES))
    to_encode = {
        "type": "oauth_state",
        "provider": provider,
        "privacy_policy_version": privacy_policy_version,
        "timezone": timezone_name,
        "region": region,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": _timestamp(now),
        "nbf": _timestamp(not_before),
        "exp": _timestamp(expire),
        "jti": jti,
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)


def is_token_revoked(payload: dict, db: Optional[Session] = None) -> bool:
    jti = payload.get("jti")
    if not jti:
        return True

    # Fast path: check database session table/graph directly
    if settings.DATABASE_BACKEND == "neo4j":
        sess = graph_store.get_user_session(str(jti))
        if sess:
            # Check database session expiration
            now = _utc_now()
            if sess.expires_at and _coerce_utc(sess.expires_at) < now:
                return True
            return bool(sess.is_revoked)
        else:
            return True  # Fail-closed: missing session is revoked
    elif db is not None:
        from app.models.user import UserSession
        sess = db.query(UserSession).filter(UserSession.id == jti).first()
        if sess:
            # Check database session expiration
            now = _utc_now()
            if sess.expires_at and _coerce_utc(sess.expires_at) < now:
                return True
            return bool(sess.is_revoked)
        else:
            return True  # Fail-closed: missing session is revoked

    # Fallback to Redis if DB session is missing or DB is not provided
    client = _get_redis_client()
    if client is not None:
        try:
            return bool(client.exists(_denylist_key(str(jti))))
        except Exception:
            logger.error("Redis denylist lookup failed for jti=%s.", jti)
            # Fail closed on Redis errors - deny the token
            return True

    if settings.DATABASE_BACKEND == "neo4j":
        return True

    if db is not None:
        return True

    # Fail closed when no revocation store is available
    # This prevents token reuse if the revocation system is down
    logger.warning("No revocation store available (DB/Redis). Denying token jti=%s for security.", jti)
    return True


def revoke_token_family(token_family: str, db: Optional[Session] = None) -> bool:
    """Revoke all token sessions that belong to the same ``token_family``.
    This is used during logout (or password change) to ensure that a stolen
    refresh token cannot be used after the user has logged out.
    Returns ``True`` if at least one session was revoked.
    """
    if not token_family:
        return False

    if settings.DATABASE_BACKEND == "neo4j":
        from app.graph.store import graph_store
        count = graph_store.revoke_token_family(token_family, reason="family_revoked")
        return count > 0

    revoked_any = False
    sessions: list = []
    now = _utc_now()
    if db is not None:
        from app.models.user import UserSession
        sessions = (
            db.query(UserSession)
            .filter(UserSession.token_family == token_family, UserSession.is_revoked == False)
            .all()
        )
        for sess in sessions:
            sess.is_revoked = True
            sess.revocation_reason = "family_revoked"
        if sessions:
            db.commit()
            revoked_any = True

    client = _get_redis_client()
    if client is not None and sessions:
        for sess in sessions:
            try:
                ttl = max(int((sess.expires_at - now).total_seconds()), 1)
                client.setex(_denylist_key(str(sess.id)), ttl, "1")
            except Exception:
                logger.error("Failed to write family revocation for jti=%s to Redis", sess.id)
    return revoked_any


def revoke_access_token(payload: dict, db: Optional[Session] = None, reason: Optional[str] = None) -> bool:
    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return False

    try:
        expires_at = datetime.fromtimestamp(int(exp), tz=timezone.utc)
    except (TypeError, ValueError):
        return False

    revoked = False
    if settings.DATABASE_BACKEND == "neo4j":
        from app.graph.store import graph_store
        # In neo4j, we set the session as revoked
        revoked = graph_store.set_session_revoked(str(jti), reason or "logout")
    elif db is not None:
        from app.models.user import UserSession
        sess = db.query(UserSession).filter(UserSession.id == jti).first()
        if sess:
            sess.is_revoked = True
            sess.revocation_reason = reason or "logout"
            db.commit()
            revoked = True

    # Optionally write to Redis for cross-instance cache if available
    client = _get_redis_client()
    if client is not None:
        try:
            ttl = max(int((expires_at - _utc_now()).total_seconds()), 1)
            client.setex(_denylist_key(str(jti)), ttl, "1")
        except Exception:
            logger.error("Failed to write token jti=%s to Redis denylist.", jti)

    return revoked or (client is not None)


def verify_access_token(token: str, *, check_revocation: bool = False, db: Optional[Session] = None) -> Optional[dict]:
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            leeway=5,
        )
    except jwt.PyJWTError:
        return None

    if check_revocation and is_token_revoked(payload, db=db):
        return None
    return payload


def verify_oauth_state(token: str) -> Optional[dict]:
    payload = verify_access_token(token, check_revocation=False)
    if not payload or payload.get("type") != "oauth_state":
        return None
    return payload


def _extract_bearer_or_cookie_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials],
) -> Optional[str]:
    if credentials and credentials.scheme.lower() == "bearer" and credentials.credentials:
        return credentials.credentials
    return request.cookies.get(settings.AUTH_COOKIE_NAME)


def get_current_token_payload(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> dict:
    token = _extract_bearer_or_cookie_token(request, credentials)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_access_token(token, check_revocation=True, db=db)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


def get_current_user(payload: dict = Depends(get_current_token_payload)) -> str:
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return str(user_id)


def get_optional_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> Optional[str]:
    token = _extract_bearer_or_cookie_token(request, credentials)
    if not token:
        return None
    payload = verify_access_token(token, check_revocation=True, db=db)
    if not payload:
        return None
    subject = payload.get("sub")
    return str(subject) if subject else None


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def _is_legacy_pbkdf2_hash(hashed_password: str) -> bool:
    parts = hashed_password.split(":")
    if len(parts) != 2:
        return False
    salt_hex, hash_hex = parts
    try:
        bytes.fromhex(salt_hex)
        bytes.fromhex(hash_hex)
    except ValueError:
        return False
    return bool(salt_hex and hash_hex)


def _verify_legacy_password(password: str, hashed_password: str) -> bool:
    try:
        salt_hex, hash_hex = hashed_password.split(":")
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
        pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(pw_hash, expected_hash)
    except Exception:
        return False


def verify_password(password: str, hashed_password: str) -> bool:
    if _is_legacy_pbkdf2_hash(hashed_password):
        return _verify_legacy_password(password, hashed_password)

    try:
        return _password_hasher.verify(hashed_password, password)
    except (InvalidHashError, VerifyMismatchError, VerificationError):
        return False


def password_needs_rehash(hashed_password: str) -> bool:
    if _is_legacy_pbkdf2_hash(hashed_password):
        return True
    try:
        return _password_hasher.check_needs_rehash(hashed_password)
    except (InvalidHashError, VerificationError):
        return True


def legacy_hash_password_for_tests(password: str) -> str:
    salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return f"{salt.hex()}:{pw_hash.hex()}"


def encrypt_provider_token(token: str) -> str:
    return crypto_manager.encrypt_secret(token)


def decrypt_provider_token(token: str | None) -> str:
    if not token:
        return ""
    decrypted = crypto_manager.decrypt_secret(token)
    return "" if decrypted == "ERROR_DECRYPTING" else decrypted


def create_exchange_code(user_id: str, username: str, token: str, *, db: Session) -> str:
    import secrets

    from app.models.user import AuthExchangeCode

    now = _utc_now()
    expires_at = now + timedelta(seconds=60)
    db.query(AuthExchangeCode).filter(AuthExchangeCode.expires_at <= now).delete(synchronize_session=False)

    for _ in range(3):
        code = secrets.token_urlsafe(32)
        try:
            db.add(
                AuthExchangeCode(
                    code=code,
                    user_id=user_id,
                    username=username,
                    access_token=token,
                    created_at=now,
                    expires_at=expires_at,
                )
            )
            db.commit()
            return code
        except IntegrityError:
            db.rollback()

    raise RuntimeError("Could not generate a unique exchange code.")


def verify_and_consume_exchange_code(code: str, *, db: Session) -> Optional[dict]:
    from app.models.user import AuthExchangeCode

    now = _utc_now()
    try:
        db.query(AuthExchangeCode).filter(AuthExchangeCode.expires_at <= now).delete(synchronize_session=False)
        exchange_code = db.query(AuthExchangeCode).filter(AuthExchangeCode.code == code).first()
        if exchange_code is None:
            db.commit()
            return None
        expires_at = _coerce_utc(exchange_code.expires_at)
        if expires_at <= now:
            db.delete(exchange_code)
            db.commit()
            return None

        payload = {
            "user_id": exchange_code.user_id,
            "username": exchange_code.username,
            "access_token": exchange_code.access_token,
        }
        db.delete(exchange_code)
        db.commit()
        return payload
    except Exception:
        db.rollback()
        raise


def hash_login_key(ip: str, username: str) -> str:
    data = f"{settings.SECRET_KEY}:{ip}:{username.strip().lower()}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def record_login_failure(db: Session, ip: str, username: str) -> None:
    key_hash = hash_login_key(ip, username)
    now = datetime.now(timezone.utc)

    client = _get_redis_client()
    if client is not None:
        try:
            redis_key = f"firecrow:login_failures:{key_hash}"
            client.rpush(redis_key, now.isoformat())
            client.expire(redis_key, settings.LOGIN_FAILURE_WINDOW_MINUTES * 60)
            client.ltrim(redis_key, -settings.LOGIN_FAILURE_LIMIT, -1)
            return
        except Exception:
            logger.error("Failed to write login failure key=%s to Redis.", key_hash)

    from app.models.user import LoginFailure
    db.add(LoginFailure(id=str(uuid.uuid4()), key_hash=key_hash, attempted_at=now))
    db.commit()


def check_login_lockout(db: Session, ip: str, username: str) -> bool:
    key_hash = hash_login_key(ip, username)
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=settings.LOGIN_FAILURE_WINDOW_MINUTES)

    client = _get_redis_client()
    if client is not None:
        try:
            redis_key = f"firecrow:login_failures:{key_hash}"
            timestamps = client.lrange(redis_key, 0, -1)
            recent_attempts = []
            for ts_val in timestamps:
                ts_str = ts_val.decode("utf-8") if isinstance(ts_val, bytes) else ts_val
                dt = datetime.fromisoformat(ts_str)
                if dt >= window_start:
                    recent_attempts.append(dt)
            if len(recent_attempts) >= settings.LOGIN_FAILURE_LIMIT:
                return True
            return False
        except Exception:
            logger.error("Failed to read login failures key=%s from Redis.", key_hash)

    from app.models.user import LoginFailure
    db.query(LoginFailure).filter(LoginFailure.attempted_at < window_start).delete()
    db.commit()

    recent_count = db.query(LoginFailure).filter(
        LoginFailure.key_hash == key_hash,
        LoginFailure.attempted_at >= window_start
    ).count()

    return recent_count >= settings.LOGIN_FAILURE_LIMIT


def clear_login_failures(db: Session, ip: str, username: str) -> None:
    key_hash = hash_login_key(ip, username)

    client = _get_redis_client()
    if client is not None:
        try:
            redis_key = f"firecrow:login_failures:{key_hash}"
            client.delete(redis_key)
            return
        except Exception:
            logger.error("Failed to clear login failures key=%s in Redis.", key_hash)

    from app.models.user import LoginFailure
    db.query(LoginFailure).filter(LoginFailure.key_hash == key_hash).delete()
    db.commit()


def revoke_session_family(db: Session, token_family: str, reason: str = "family_revocation") -> None:
    from app.models.user import UserSession
    sessions = db.query(UserSession).filter(
        UserSession.token_family == token_family,
        UserSession.is_revoked == False
    ).all()
    for sess in sessions:
        sess.is_revoked = True
        sess.revocation_reason = reason
        client = _get_redis_client()
        if client is not None:
            try:
                ttl = max(int((sess.expires_at - datetime.now(timezone.utc)).total_seconds()), 1)
                client.setex(_denylist_key(sess.id), ttl, "1")
            except Exception:
                pass
    db.commit()


def verify_refresh_token_with_rotation(
    old_token: str,
    *,
    db: Session,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Optional[dict]:
    """Verify a refresh token, revoke it (rotation), and return its payload.

    If the token was ALREADY revoked (reuse detected), revokes the entire
    token family as a theft response and returns ``None``.

    On success, returns a dict with ``old_payload``, ``new_access_token``,
    and ``new_refresh_token`` so the caller can issue new credentials.
    """
    old_payload = verify_refresh_token(old_token, db=db)
    if not old_payload:
        return None

    token_family = old_payload.get("token_family")
    user_id = old_payload.get("sub")
    username = old_payload.get("username") or user_id

    if not user_id or not token_family:
        return None

    now = _utc_now()

    old_jti = old_payload.get("jti")
    if settings.DATABASE_BACKEND == "neo4j":
        old_session = graph_store.get_user_session(str(old_jti))
    else:
        from app.models.user import UserSession
        old_session = db.query(UserSession).filter(UserSession.id == old_jti).first()

    if not old_session:
        logger.warning("Refresh token session not found for jti=%s. Denying rotation.", old_jti)
        return None

    if old_session.is_revoked:
        # Token reuse detected — revoke entire family
        logger.warning("Refresh token reuse detected for user=%s family=%s. Revoking all sessions.", user_id, token_family)
        revoke_token_family(token_family, db=db)
        record_security_event_raw(
            db, user_id=user_id,
            action="auth.refresh_token_reuse_detected",
            details={"token_family": token_family, "revoked_jti": old_jti},
        )
        return None

    # Revoke old refresh token (rotation)
    if settings.DATABASE_BACKEND == "neo4j":
        graph_store.set_session_revoked(str(old_jti), "rotated")
    else:
        old_session.is_revoked = True
        old_session.revocation_reason = "rotated"
    
    client = _get_redis_client()
    if client is not None:
        try:
            ttl = max(int((old_session.expires_at - now).total_seconds()), 1)
            client.setex(_denylist_key(str(old_jti)), ttl, "1")
        except Exception:
            pass
            
    if settings.DATABASE_BACKEND != "neo4j":
        db.commit()

    new_access_token = create_access_token(
        user_id=user_id, username=username,
        db=db, ip=ip, user_agent=user_agent,
        token_family=token_family,
    )
    new_refresh_token = create_refresh_token(
        user_id=user_id, username=username,
        db=db, token_family=token_family,
    )

    return {
        "old_payload": old_payload,
        "new_access_token": new_access_token,
        "new_refresh_token": new_refresh_token,
    }


def record_security_event_raw(
    db: Session,
    user_id: str,
    action: str,
    details: Optional[dict] = None,
) -> None:
    import json
    from app.models.security_log import SecurityLog
    db.add(SecurityLog(
        user_id=user_id,
        action=action,
        ip_address=None,
        details=json.dumps(details) if details else None,
    ))
    db.commit()
