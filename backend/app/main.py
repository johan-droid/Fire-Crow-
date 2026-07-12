import os
import logging
import signal
import asyncio
from contextlib import asynccontextmanager, suppress

try:
    from pythonjsonlogger.json import JsonFormatter
    _JSON_LOGGING_AVAILABLE = True
except ImportError:
    _JSON_LOGGING_AVAILABLE = False

import uuid
import argparse
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from pathlib import Path
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from app.services.limiter import limiter
from app.middleware.telemetry import TelemetryMiddleware
from app.middleware.mfa_enforcement import MFAEnforcementMiddleware
from app.middleware.tenant import TenantMiddleware
from app.services.csrf import CSRFMiddleware
from app.utils.circuit_breaker import get_circuit_breaker

from app.config import settings, WORKSPACE_DIR
from app.models.database import Base, engine, ensure_database_compatibility, get_db
from app.graph.database import close_neo4j_driver, verify_neo4j_connectivity
from app.api import auth_router, audit_router, sse_router, system_router, storage_router, chat_router, leaderboard_router, push_router, user_router, mfa_router, sso_router, pam_router, iam_router, tenant_router, verify_router

_shutting_down = False

logger = logging.getLogger("firecrow.main")
# Structured JSON logging (production) – includes request_id when available.
# Falls back to standard formatter when python-json-logger is not installed.
if _JSON_LOGGING_AVAILABLE:
    _log_handler = logging.StreamHandler()
    _json_formatter = JsonFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s %(request_id)s"
    )
    _log_handler.setFormatter(_json_formatter)
    logger.addHandler(_log_handler)
else:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
logger.setLevel(logging.INFO if not settings.DEBUG else logging.DEBUG)


class RequestBodyTooLargeError(Exception):
    pass



def _cors_origins() -> list[str]:
    origins: set[str] = set()
    if settings.FRONTEND_URL:
        origins.add(settings.FRONTEND_URL.rstrip("/"))
    if settings.CORS_ORIGINS:
        origins.update(origin.strip().rstrip("/") for origin in settings.CORS_ORIGINS.split(",") if origin.strip())
    if settings.DEBUG:
        origins.update(
            {
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://localhost:3001",
                "http://127.0.0.1:3001",
                "http://localhost:5173",
                "http://127.0.0.1:5173",
            }
        )
    return sorted(origin for origin in origins if origin and origin != "*")


@asynccontextmanager
async def lifespan(app: FastAPI):
    housekeeping_task: asyncio.Task | None = None

    if settings.DATABASE_BACKEND == "neo4j":
        logger.info("Running with Neo4j backend mode.")
        verify_neo4j_connectivity()
    elif settings.DEBUG:
        logger.info("Running in DEBUG mode. Checking for pending migrations before auto-DDL.")
        try:
            from app.models.database import check_pending_migrations
            if check_pending_migrations():
                logger.warning(
                    "Pending database migrations detected. "
                    "Please run 'alembic upgrade head' to apply proper migrations. "
                    "Falling back to auto-DDL for development convenience."
                )
            Base.metadata.create_all(bind=engine)
            ensure_database_compatibility()
        except Exception as e:
            logger.error("Error during database initialization in DEBUG mode: %s", str(e))
    else:
        logger.info("Running in production mode; enforcing Alembic migration checks.")
        try:
            from app.models.database import check_pending_migrations
            if check_pending_migrations():
                logger.error(
                    "SECURITY CRITICAL: Pending database migrations detected. "
                    "Startup blocked. Run 'alembic upgrade head' first."
                )
                raise RuntimeError("Pending database migrations on production startup.")
            logger.info("Database migration check passed. Database is up-to-date.")
        except Exception as e:
            if isinstance(e, RuntimeError):
                raise e
            logger.error("Error running database migration startup check: %s", str(e))

    # Ensure workspace directories exist
    for dir_name in ["workspace/reports", "workspace/temp", "workspace/storage", "workspace/scans"]:
        (WORKSPACE_DIR / dir_name).mkdir(parents=True, exist_ok=True)

    # Run database storage housekeeping
    if settings.DATABASE_BACKEND != "neo4j":
        try:
            from app.models.database import SessionLocal
            from app.services.housekeeping import run_housekeeping
            from app.models.audit_job import AuditJob
            from app.schemas.audit_state import JobStatus
            db = SessionLocal()
            try:
                # Mark any running/queued jobs from previous session as failed
                stuck_jobs = db.query(AuditJob).filter(
                    AuditJob.status.in_([JobStatus.QUEUED, JobStatus.RUNNING])
                ).all()
                for job in stuck_jobs:
                    job.status = JobStatus.FAILED
                    job.error_message = "Job interrupted by system restart"
                if stuck_jobs:
                    db.commit()
                    logger.info(f"Cleaned up {len(stuck_jobs)} stuck jobs from previous session.")

                run_housekeeping(db)
            finally:
                db.close()
        except Exception as e:
            logger.error("Error running database housekeeping on startup: %s", str(e))

    if settings.DATABASE_BACKEND != "neo4j" and settings.HOUSEKEEPING_INTERVAL_SECONDS > 0:
        async def _periodic_housekeeping() -> None:
            from app.models.database import SessionLocal
            from app.services.housekeeping import run_housekeeping

            while True:
                await asyncio.sleep(settings.HOUSEKEEPING_INTERVAL_SECONDS)
                db = SessionLocal()
                try:
                    counts = run_housekeeping(db)
                    logger.info("Periodic housekeeping completed: %s", counts)
                except Exception as exc:
                    logger.error("Periodic housekeeping failed: %s", str(exc))
                finally:
                    db.close()

        housekeeping_task = asyncio.create_task(_periodic_housekeeping(), name="firecrow-housekeeping")

    try:
        yield
    finally:
        if housekeeping_task is not None:
            housekeeping_task.cancel()
            with suppress(asyncio.CancelledError):
                await housekeeping_task
        if settings.DATABASE_BACKEND == "neo4j":
            close_neo4j_driver()


app = FastAPI(
    title="Fire Crow API",
    description="Agentic Security Intelligence Platform Backend",
    version="1.0.0",
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore
app.add_middleware(SlowAPIMiddleware)  # type: ignore
app.add_middleware(TelemetryMiddleware)
app.add_middleware(TenantMiddleware)
app.add_middleware(CSRFMiddleware)
app.add_middleware(MFAEnforcementMiddleware)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Let FastAPI's default handler process HTTPException (400, 401, 404, etc.)
    from fastapi.exceptions import HTTPException as FastAPIHTTPException
    from starlette.exceptions import HTTPException as StarletteHTTPException
    if isinstance(exc, (FastAPIHTTPException, StarletteHTTPException)):
        raise exc

    error_id = str(uuid.uuid4())
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.exception(
        "Unhandled request error error_id=%s request_id=%s method=%s path=%s",
        error_id,
        request_id,
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal Server Error",
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id},
    )

# CORS configurations
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-CSRF-Token"],
)

@app.middleware("http")
async def limit_request_body_size(request: Request, call_next):
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    body_limit = settings.MAX_JSON_BODY_BYTES if content_type in {"application/json", "application/ld+json"} or content_type.endswith("+json") else settings.MAX_REQUEST_BODY_BYTES
    content_length_header = request.headers.get("content-length")
    if content_length_header:
        try:
            content_length = int(content_length_header)
            if content_length > body_limit:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Payload Too Large"},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length header"},
            )

    original_receive = request._receive
    received_bytes = 0

    async def limited_receive():
        nonlocal received_bytes
        message = await original_receive()
        if message["type"] == "http.request":
            received_bytes += len(message.get("body", b""))
            if received_bytes > body_limit:
                raise RequestBodyTooLargeError
        return message

    request._receive = limited_receive

    try:
        return await call_next(request)
    except RequestBodyTooLargeError:
        return JSONResponse(
            status_code=413,
            content={"detail": "Payload Too Large"},
        )


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"

    img_src_domains = "https://avatars.githubusercontent.com https://*.googleusercontent.com"
    if settings.R2_ENDPOINT_URL:
        r2_domain = settings.R2_ENDPOINT_URL
        if "://" in r2_domain:
            r2_domain = r2_domain.split("://")[1]
        img_src_domains += f" https://{r2_domain}"

    if settings.DEBUG:
        img_src_domains += " https://*"

    if settings.DEBUG:
        script_src = "'self' 'unsafe-inline' 'unsafe-eval'"
        style_src = "'self' 'unsafe-inline'"
        connect_src = "'self' ws: wss: http: https:"
    else:
        script_src = "'self'"
        style_src = "'self'"
        connect_src = "'self'"

    csp_header = (
        "default-src 'self'; "
        f"script-src {script_src}; "
        f"style-src {style_src}; "
        f"font-src 'self' data: https://fonts.gstatic.com https://fonts.googleapis.com; "
        f"img-src 'self' data: {img_src_domains}; "
        f"connect-src {connect_src}; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers["Content-Security-Policy"] = csp_header
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Register API Routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")
app.include_router(sse_router, prefix="/api/v1")
app.include_router(system_router, prefix="/api/v1")
app.include_router(storage_router, prefix="/api/v1")
app.include_router(chat_router, prefix="/api/v1")
app.include_router(leaderboard_router, prefix="/api/v1")
app.include_router(push_router, prefix="/api/v1")
app.include_router(user_router, prefix="/api/v1")
app.include_router(mfa_router, prefix="/api/v1")
app.include_router(sso_router, prefix="/api/v1")
app.include_router(pam_router, prefix="/api/v1")
app.include_router(iam_router, prefix="/api/v1")
app.include_router(tenant_router, prefix="/api/v1")
app.include_router(verify_router, prefix="/api/v1")


# Graceful shutdown handler
@app.middleware("http")
async def graceful_shutdown(request: Request, call_next):
    global _shutting_down
    if _shutting_down:
        return JSONResponse(
            status_code=503,
            content={"detail": "Server is shutting down. Please retry."},
        )
    return await call_next(request)


def _database_probe() -> bool:
    if settings.DATABASE_BACKEND == "neo4j":
        try:
            verify_neo4j_connectivity()
            return True
        except Exception:
            return False

    if engine is None:
        return False

    try:
        from sqlalchemy import text
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


# Enhanced deep health check with circuit breaker status
@app.get("/health/deep")
@limiter.limit("10/minute")
async def health_deep(request: Request, db: Session | None = Depends(get_db)):
    db_ok = _database_probe() if db is None else True
    if db is not None:
        try:
            from sqlalchemy import text
            db.execute(text("SELECT 1"))
        except Exception:
            db_ok = False

    storage_ok = True
    try:
        test_file = Path(WORKSPACE_DIR) / "workspace" / f".health_probe_{uuid.uuid4()}"
        test_file.write_text("health_ok")
        test_file.unlink()
    except Exception:
        storage_ok = False

    s3_ok = True
    from app.services.storage import storage_service
    if storage_service.s3_client is not None:
        try:
            storage_service.s3_client.list_buckets()
        except Exception:
            s3_ok = False

    # Circuit breaker status
    from app.utils.circuit_breaker import _circuit_breakers
    cb_status = {name: cb.stats() for name, cb in _circuit_breakers.items()}

    status_code = 200 if (db_ok and storage_ok and s3_ok) else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "healthy" if status_code == 200 else "unhealthy",
            "database": "ok" if db_ok else "failed",
            "local_storage": "ok" if storage_ok else "failed",
            "object_storage": "ok" if s3_ok else ("failed" if storage_service.is_s3_active() else "disabled"),
            "circuit_breakers": cb_status,
            "shutting_down": _shutting_down,
        }
    )


# Additionally, make /health/ready more comprehensive
@app.get("/health/ready")
@limiter.limit("10/minute")
async def health_ready(request: Request, db: Session | None = Depends(get_db)):
    db_ok = _database_probe() if db is None else True
    if db is not None:
        try:
            from sqlalchemy import text
            db.execute(text("SELECT 1"))
        except Exception:
            db_ok = False
    if not db_ok:
        logger.error("Readiness check database probe failed", exc_info=True)

    redis_ok = True
    try:
        from app.services.auth import _get_redis_client
        client = _get_redis_client()
        if client is not None:
            client.ping()
    except Exception:
        redis_ok = False
        logger.error("Readiness check Redis probe failed", exc_info=True)

    if not db_ok or not redis_ok:
        return JSONResponse(
            status_code=503,
            content={
                "status": "degraded",
                "database": "connected" if db_ok else "unavailable",
                "cache": "connected" if redis_ok else "unavailable"
            }
        )
    return {"status": "ready"}


# Ensure reports directory exists for authenticated downloads
reports_dir = os.path.join(WORKSPACE_DIR, "workspace", "reports")
os.makedirs(reports_dir, exist_ok=True)


@app.get("/health")
@limiter.limit("30/minute")
async def health_check(request: Request, db: Session | None = Depends(get_db)):
    db_ok = _database_probe() if db is None else True
    if db is not None:
        try:
            from sqlalchemy import text
            db.execute(text("SELECT 1"))
        except Exception:
            db_ok = False
    if not db_ok:
        logger.warning("Health check database probe failed.", exc_info=True)

    return {
        "status": "up" if db_ok else "degraded",
        "database": "connected" if db_ok else "unavailable"
    }


@app.get("/health/live")
@limiter.limit("30/minute")
async def health_live(request: Request):
    return {"status": "live"}


def _write_openapi(stream) -> None:
    import yaml

    yaml.safe_dump(app.openapi(), stream, sort_keys=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fire Crow API utilities")
    parser.add_argument("--generate-openapi", action="store_true", help="Write the OpenAPI schema as YAML to stdout.")
    args = parser.parse_args()

    if args.generate_openapi:
        _write_openapi(sys.stdout)
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
