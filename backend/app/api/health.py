from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.models.database import get_db
from app.services.limiter import limiter

router = APIRouter(prefix="/health", tags=["Health"])

@router.get("/live")
async def health_live() -> JSONResponse:
    """Liveness probe – the process is up and responding to HTTP."""
    return JSONResponse(status_code=200, content={"status": "live"})

@router.get("/ready")
@limiter.limit(settings.HEALTH_CHECK_RATE_LIMIT)
async def health_ready(request: Request, db: Session = Depends(get_db)) -> JSONResponse:
    """Readiness probe – checks that critical dependencies (DB, Redis) are reachable.
    Returns 200 when the service is ready to accept traffic.
    """
    # Simple DB ping – try a lightweight query
    try:
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Database unreachable") from exc

    # Check Redis if configured
    if settings.REDIS_URL:
        from app.services.auth import _get_redis_client
        client = _get_redis_client()
        if client is None:
            raise HTTPException(status_code=503, detail="Redis unreachable")
        try:
            client.ping()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Redis ping failed") from exc

    return JSONResponse(status_code=200, content={"status": "ready"})
