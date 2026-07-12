import logging

from fastapi import Request
from slowapi import Limiter
from slowapi.extension import StrOrCallableStr
from slowapi.util import get_remote_address

from app.config import settings

logger = logging.getLogger("firecrow.services.limiter")


def _extract_access_token(request: Request) -> str | None:
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        if token:
            return token
    return request.cookies.get(settings.AUTH_COOKIE_NAME)


def _get_rate_limit_key(request: Request) -> str:
    """Composite rate-limit key: authenticated user_id if available, else IP.

    This prevents abuse behind shared proxies/CDNs where many users share
    the same IP address, and ensures per-user fairness.
    """
    token = _extract_access_token(request)
    if token:
        try:
            import jwt
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"],
                audience="firecrow-web",
                issuer="firecrow-api",
                options={"verify_exp": False},  # Don't reject expired for rate-limit keying
            )
            user_id = payload.get("sub")
            if user_id:
                return f"user:{user_id}"
        except Exception:
            pass  # Fall through to IP-based key

    return get_remote_address(request)


default_limits: list[StrOrCallableStr] = [] if settings.DEBUG else [settings.DEFAULT_RATE_LIMIT]
limiter = Limiter(key_func=_get_rate_limit_key, default_limits=default_limits)
