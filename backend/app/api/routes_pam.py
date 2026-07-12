from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.models.database import get_db
from app.models.user import User
from app.services.auth import get_current_user
from app.services.limiter import limiter
from app.services.security_log import record_security_event
from app.services.pam_service import (  # type: ignore
    create_privilege_request, approve_privilege_request, deny_privilege_request,
    cancel_privilege_request, get_active_grants, revoke_grant,
    expire_stale_grants, get_pending_requests, request_to_dict, grant_to_dict,
    check_active_grant,
)
from app.services.mfa_service import enforce_mfa_for_admin

router = APIRouter(prefix="/pam", tags=["Privileged Access Management"])


class PrivilegeRequestCreate(BaseModel):
    role_name: str
    permission: str
    reason: str = Field(..., min_length=10)
    requested_duration_minutes: int = Field(..., ge=1, le=480)
    ticket_ref: Optional[str] = None


class PrivilegeApproveRequest(BaseModel):
    duration_minutes: Optional[int] = None


class PrivilegeDenyRequest(BaseModel):
    reason: Optional[str] = None


class RevokeRequest(BaseModel):
    grant_id: str


@router.post("/requests")
@limiter.limit(settings.PAM_REQUEST_RATE_LIMIT)
async def create_request(
    payload: PrivilegeRequestCreate,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    req = create_privilege_request(
        user_id=user_id,
        role_name=payload.role_name,
        permission=payload.permission,
        reason=payload.reason,
        requested_duration_minutes=payload.requested_duration_minutes,
        db=db,
        ticket_ref=payload.ticket_ref,
    )
    record_security_event(
        db, action="pam.request.created", request=request, user_id=user_id,
        details={
            "request_id": req.id,
            "role": payload.role_name,
            "permission": payload.permission,
            "duration_minutes": payload.requested_duration_minutes,
        },
    )
    return request_to_dict(req)


@router.get("/requests")
@limiter.limit(settings.PAM_LIST_RATE_LIMIT)
async def list_requests(
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if user and user.is_admin:
        pending = get_pending_requests(db)
    else:
        pending = get_pending_requests(db, user_id=user_id)
    return {"requests": [request_to_dict(r) for r in pending]}


@router.get("/requests/pending")
@limiter.limit(settings.PAM_APPROVE_RATE_LIMIT)
async def pending_requests(
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")

    pending = get_pending_requests(db)
    return {"requests": [request_to_dict(r) for r in pending]}


@router.post("/requests/{request_id}/approve")
@limiter.limit(settings.PAM_REJECT_RATE_LIMIT)
async def approve_request(
    request_id: str,
    payload: PrivilegeApproveRequest,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    grant = approve_privilege_request(request_id, user_id, db, duration_minutes=payload.duration_minutes)
    record_security_event(
        db, action="pam.request.approved", request=request, user_id=user_id,
        details={
            "request_id": request_id,
            "grant_id": grant.id,
            "duration_minutes": payload.duration_minutes,
        },
    )
    return grant_to_dict(grant)


@router.post("/requests/{request_id}/deny")
@limiter.limit(settings.PAM_CANCEL_RATE_LIMIT)
async def deny_request(
    request_id: str,
    payload: PrivilegeDenyRequest,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")

    result = deny_privilege_request(request_id, user_id, db, reason=payload.reason)
    record_security_event(
        db, action="pam.request.denied", request=request, user_id=user_id,
        details={"request_id": request_id, "reason": payload.reason},
    )
    return request_to_dict(result)


@router.post("/requests/{request_id}/cancel")
@limiter.limit(settings.PAM_REVOKE_RATE_LIMIT)
async def cancel_request(
    request_id: str,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = cancel_privilege_request(request_id, user_id, db)
    record_security_event(
        db, action="pam.request.cancelled", request=request, user_id=user_id,
        details={"request_id": request_id},
    )
    return request_to_dict(result)


@router.get("/grants")
@limiter.limit(settings.PAM_SESSIONS_RATE_LIMIT)
async def list_grants(
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if user and user.is_admin:
        from app.models.pam import PrivilegedAccessGrant
        now = datetime.now(timezone.utc)
        grants = db.query(PrivilegedAccessGrant).filter(
            PrivilegedAccessGrant.is_active == True,
            PrivilegedAccessGrant.expires_at > now,
        ).all()
    else:
        grants = get_active_grants(user_id, db)

    return {"grants": [grant_to_dict(g) for g in grants]}


@router.post("/grants/revoke")
@limiter.limit(settings.PAM_ACTIVITY_RATE_LIMIT)
async def revoke_grant_endpoint(
    payload: RevokeRequest,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    revoke_grant(payload.grant_id, user_id, db)
    record_security_event(
        db, action="pam.grant.revoked", request=request, user_id=user_id,
        details={"grant_id": payload.grant_id},
    )
    return {"status": "revoked"}


@router.post("/cleanup")
@limiter.limit(settings.PAM_POLICY_RATE_LIMIT)
async def cleanup_expired(
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")

    count = expire_stale_grants(db)
    if count:
        record_security_event(
            db, action="pam.cleanup.expired_grants", request=request, user_id=user_id,
            details={"expired_count": count},
        )
    return {"expired_grants_cleaned": count}


@router.get("/check/{permission}")
@limiter.limit(settings.PAM_CONFIG_RATE_LIMIT)
async def check_access(
    permission: str,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    has_access = check_active_grant(user_id, permission, db)
    return {"permission": permission, "granted": has_access}
