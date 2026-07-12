from __future__ import annotations

import secrets
import logging
from typing import Optional

from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings

logger = logging.getLogger("firecrow.csrf")

CSRF_COOKIE_NAME = "fc_csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_TOKEN_LENGTH = 32

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(CSRF_TOKEN_LENGTH)


def _cookie_secure() -> bool:
    return (not settings.DEBUG) or settings.FRONTEND_URL.startswith("https://")


def get_csrf_token_from_request(request: Request) -> Optional[str]:
    return request.headers.get(CSRF_HEADER_NAME)


def verify_csrf_token(request: Request, token: str) -> bool:
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    if not cookie_token:
        return False
    return secrets.compare_digest(cookie_token, token)


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Allow disabling CSRF in test environments
        if not settings.CSRF_ENABLED:
            return await call_next(request)

        # Safe methods (GET/HEAD/OPTIONS/TRACE) do not require CSRF validation.
        # Also skip CSRF for public auth endpoints (register, login) because they are
        # unauthenticated and we rely on SameSite=strict for the session cookies we set.
        # OAuth callback routes are also exempted as they use state parameter for CSRF protection.
        csrf_exempt_paths = {
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/github/callback",
            "/api/v1/auth/google/callback",
        }
        if request.method in SAFE_METHODS or request.url.path in csrf_exempt_paths:
            response = await call_next(request)
            self._set_csrf_cookie_if_missing(request, response)
            return response

        # Every state‑changing request must present a valid CSRF token.
        # The CSRF token can be provided either via the dedicated header or via the cookie itself
        # (double‑submit cookie pattern). This matches the behaviour of many modern frameworks.
        token = get_csrf_token_from_request(request)
        if not token or not verify_csrf_token(request, token):
            logger.warning("CSRF validation failed for %s %s", request.method, request.url.path)
            return Response(
                content='{"detail":"CSRF token missing or invalid"}',
                status_code=status.HTTP_403_FORBIDDEN,
                media_type="application/json",
            )

        response = await call_next(request)
        self._set_csrf_cookie_if_missing(request, response)
        return response

    def _set_csrf_cookie_if_missing(self, request: Request, response: Response):
        if CSRF_COOKIE_NAME not in request.cookies:
            token = generate_csrf_token()
            cookie_secure = settings.AUTH_COOKIE_SECURE
            if settings.DEBUG:
                cookie_secure = _cookie_secure()
            # The CSRF cookie must be readable by client‑side JavaScript so that the token can be
            # placed into the X‑CSRF‑Token header for protected requests. Therefore ``httponly`` is set
            # to ``False``. All other security flags remain in place.
            response.set_cookie(
                key=CSRF_COOKIE_NAME,
                value=token,
                httponly=False,
                secure=cookie_secure,
                samesite=settings.AUTH_COOKIE_SAMESITE,
                path="/",
                max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            )


def get_csrf_token(request: Request) -> str:
    token = request.cookies.get(CSRF_COOKIE_NAME)
    if not token:
        token = generate_csrf_token()
    return token
