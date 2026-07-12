from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.models.database import get_db
from app.models.user import User
from app.services.auth import get_current_user
from app.services.limiter import limiter
from app.services.tenant_service import (
    create_tenant, get_tenant, get_tenant_by_slug, list_tenants,
    update_tenant, deactivate_tenant, get_tenant_stats,
    tenant_to_dict, resolve_tenant_from_request,
)
from app.services.security_log import record_security_event
from app.services.mfa_service import enforce_mfa_for_admin

router = APIRouter(prefix="/tenants", tags=["Multi-Tenancy"])


class TenantCreate(BaseModel):
    name: str
    slug: str
    domain: Optional[str] = None
    plan: str = "free"
    max_users: Optional[int] = None
    max_storage_gb: Optional[int] = None


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    plan: Optional[str] = None
    max_users: Optional[int] = None
    max_storage_gb: Optional[int] = None


@router.get("/")
@limiter.limit(settings.TENANT_LIST_RATE_LIMIT)
async def list_all_tenants(
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")

    tenants = list_tenants(db)
    return {"tenants": [tenant_to_dict(t) for t in tenants]}


@router.post("/")
@limiter.limit(settings.TENANT_CREATE_RATE_LIMIT)
async def create_new_tenant(
    payload: TenantCreate,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    tenant = create_tenant(db, name=payload.name, slug=payload.slug, domain=payload.domain,
                            plan=payload.plan, max_users=payload.max_users, max_storage_gb=payload.max_storage_gb)
    record_security_event(db, action="tenant.created", request=request, user_id=user_id,
                           details={"tenant_name": payload.name, "tenant_slug": payload.slug})
    return tenant_to_dict(tenant)


@router.get("/me")
@limiter.limit(settings.TENANT_GET_RATE_LIMIT)
async def current_tenant(
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    tenant = resolve_tenant_from_request(request, db)
    if not tenant:
        user = db.query(User).filter(User.id == user_id).first()
        if user and user.tenant_id:
            tenant = get_tenant(user.tenant_id, db)
        else:
            raise HTTPException(status_code=404, detail="No tenant assigned.")
    return tenant_to_dict(tenant)


@router.get("/{tenant_id}")
@limiter.limit(settings.TENANT_UPDATE_RATE_LIMIT)
async def get_tenant_by_id(
    tenant_id: str,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")

    tenant = get_tenant(tenant_id, db)
    return tenant_to_dict(tenant)


@router.get("/slug/{slug}")
@limiter.limit(settings.TENANT_DELETE_RATE_LIMIT)
async def get_tenant_by_slug_endpoint(
    slug: str,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")

    tenant = get_tenant_by_slug(slug, db)
    return tenant_to_dict(tenant)


@router.put("/{tenant_id}")
@limiter.limit(settings.TENANT_MEMBERS_RATE_LIMIT)
async def update_tenant_by_id(
    tenant_id: str,
    payload: TenantUpdate,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    tenant = update_tenant(tenant_id, db, **payload.model_dump(exclude_none=True))
    record_security_event(db, action="tenant.updated", request=request, user_id=user_id,
                           details={"tenant_id": tenant_id})
    return tenant_to_dict(tenant)


@router.delete("/{tenant_id}")
@limiter.limit(settings.TENANT_INVITE_RATE_LIMIT)
async def deactivate_tenant_by_id(
    tenant_id: str,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    tenant = deactivate_tenant(tenant_id, db)
    record_security_event(db, action="tenant.deactivated", request=request, user_id=user_id,
                           details={"tenant_id": tenant_id})
    return {"status": "deactivated"}


@router.get("/{tenant_id}/stats")
@limiter.limit(settings.TENANT_REVOKE_INVITE_RATE_LIMIT)
async def tenant_statistics(
    tenant_id: str,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")

    return get_tenant_stats(tenant_id, db)
