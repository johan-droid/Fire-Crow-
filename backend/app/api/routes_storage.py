from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.models import get_db
from app.services.auth import get_current_user
from app.services.limiter import limiter
from app.services.storage import storage_service

router = APIRouter(prefix="/storage", tags=["Storage"])


@router.get("/artifacts/{artifact_id}/download")
@limiter.limit(settings.STORAGE_UPLOAD_RATE_LIMIT)
async def download_artifact(
    artifact_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
):
    """
    Downloads an artifact from storage. Validates tenant access first.
    """
    try:
        file_path, filename, media_type = storage_service.download_artifact_local(db, artifact_id, user_id)
    finally:
        db.close()
    return FileResponse(path=file_path, filename=filename, media_type=media_type)


@router.post("/artifacts/{artifact_id}/legal-hold")
@limiter.limit(settings.STORAGE_DOWNLOAD_RATE_LIMIT)
async def set_legal_hold(
    artifact_id: str,
    request: Request,
    hold: bool,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
):
    """
    Toggles legal hold for an artifact (Admin/scoped).
    """
    artifact = storage_service.set_legal_hold(db, artifact_id, hold, user_id)  # type: ignore
    return {
        "message": f"Legal hold set to {hold} successfully",
        "artifact_id": artifact.id,
        "legal_hold": artifact.legal_hold,
    }
