from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.models.database import get_db
from app.models.user import User
from app.services.auth import get_current_user
from app.services.limiter import limiter
from app.services.security_log import record_security_event
from app.services.iam_service import (  # type: ignore
    create_iam_policy, delete_iam_policy, get_all_iam_policies,
    assign_role_permission, remove_role_permission, get_role_permissions,
    deactivate_user, reactivate_user, delete_user_permanently,
    find_dormant_users, detect_shared_accounts, run_account_cleanup,
    create_service_account, revoke_service_account,
    policy_to_dict, role_permission_to_dict, enforce_least_privilege,
    check_permission,
)
from app.services.mfa_service import enforce_mfa_for_admin

router = APIRouter(prefix="/iam", tags=["Identity & Access Management"])


class PolicyCreate(BaseModel):
    name: str
    effect: str = "allow"
    actions: list[str]
    resources: list[str] = ["*"]
    description: Optional[str] = None
    conditions: Optional[str] = None
    priority: int = 0


class RolePermissionAssign(BaseModel):
    role_id: str
    permission: str
    resource_pattern: str = "*"


class UserActionRequest(BaseModel):
    user_id: str
    reason: Optional[str] = None


class ServiceAccountCreate(BaseModel):
    name: str
    permissions: list[str]
    description: Optional[str] = None
    expires_in_days: Optional[int] = None


@router.get("/policies")
@limiter.limit(settings.IAM_IDENTITIES_RATE_LIMIT)
async def list_policies(
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")

    policies = get_all_iam_policies(db)
    return {"policies": [policy_to_dict(p) for p in policies]}


@router.post("/policies")
@limiter.limit(settings.IAM_CREDENTIALS_RATE_LIMIT)
async def create_policy(
    payload: PolicyCreate,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    policy = create_iam_policy(
        db, name=payload.name, effect=payload.effect,
        actions=payload.actions, resources=payload.resources,
        description=payload.description, conditions=payload.conditions,
        priority=payload.priority,
    )
    record_security_event(
        db, action="iam.policy.created", request=request, user_id=user_id,
        details={"policy_name": payload.name},
    )
    return policy_to_dict(policy)


@router.delete("/policies/{policy_id}")
@limiter.limit(settings.IAM_CREDENTIALS_RATE_LIMIT)
async def delete_policy(
    policy_id: str,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    record_security_event(
        db, action="iam.policy.deleted", request=request, user_id=user_id,
        details={"policy_id": policy_id},
    )
    delete_iam_policy(policy_id, db)
    return {"status": "deleted"}


@router.get("/role-permissions/{role_id}")
@limiter.limit(settings.IAM_IDENTITIES_RATE_LIMIT)
async def list_role_permissions(
    role_id: str,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")

    permissions = get_role_permissions(role_id, db)
    return {"role_id": role_id, "permissions": [role_permission_to_dict(p) for p in permissions]}


@router.post("/role-permissions")
@limiter.limit(settings.IAM_CREDENTIALS_RATE_LIMIT)
async def assign_permission(
    payload: RolePermissionAssign,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    rp = assign_role_permission(db, payload.role_id, payload.permission, payload.resource_pattern)
    record_security_event(
        db, action="iam.role_permission.created", request=request, user_id=user_id,
        details={"role_id": payload.role_id, "permission": payload.permission},
    )
    return role_permission_to_dict(rp)


@router.delete("/role-permissions/{permission_id}")
@limiter.limit(settings.IAM_CREDENTIALS_RATE_LIMIT)
async def remove_permission(
    permission_id: str,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    remove_role_permission(permission_id, db)
    record_security_event(
        db, action="iam.role_permission.deleted", request=request, user_id=user_id,
        details={"permission_id": permission_id},
    )
    return {"status": "deleted"}


@router.post("/users/deactivate")
@limiter.limit(settings.IAM_CREDENTIALS_RATE_LIMIT)
async def deactivate_user_endpoint(
    payload: UserActionRequest,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    deactivate_user(payload.user_id, db, triggered_by=user_id, reason=payload.reason)
    record_security_event(
        db, action="iam.user.deactivated", request=request, user_id=user_id,
        details={"target_user_id": payload.user_id, "reason": payload.reason},
    )
    return {"status": "deactivated"}


@router.post("/users/reactivate")
@limiter.limit(settings.IAM_CREDENTIALS_RATE_LIMIT)
async def reactivate_user_endpoint(
    payload: UserActionRequest,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    reactivate_user(payload.user_id, db, triggered_by=user_id)
    record_security_event(
        db, action="iam.user.reactivated", request=request, user_id=user_id,
        details={"target_user_id": payload.user_id},
    )
    return {"status": "reactivated"}


@router.delete("/users/{target_user_id}")
@limiter.limit(settings.IAM_DEACTIVATE_ROLE_RATE_LIMIT)
async def delete_user_endpoint(
    target_user_id: str,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    record_security_event(
        db, action="iam.user.permanently_deleted", request=request, user_id=user_id,
        details={"target_user_id": target_user_id},
    )
    delete_user_permanently(target_user_id, db, triggered_by=user_id)
    return {"status": "permanently_deleted"}


@router.get("/audit/dormant")
@limiter.limit(settings.IAM_CREDENTIALS_RATE_LIMIT)
async def dormant_users(
    request: Request,
    days: int = 90,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")

    results = find_dormant_users(db, days_threshold=days)
    return {"dormant_users": results, "threshold_days": days}


@router.get("/audit/shared-accounts")
@limiter.limit(settings.IAM_CREDENTIALS_RATE_LIMIT)
async def shared_accounts(
    request: Request,
    threshold_ips: int = 5,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")

    results = detect_shared_accounts(db, threshold_ips=threshold_ips)
    return {"suspected_shared_accounts": results, "threshold_ips": threshold_ips}


@router.post("/cleanup")
@limiter.limit(settings.IAM_DEACTIVATE_ROLE_RATE_LIMIT)
async def cleanup_accounts(
    request: Request,
    dormant_days: int = 90,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    stats = run_account_cleanup(db, dormant_days=dormant_days)
    record_security_event(
        db, action="iam.cleanup.run", request=request, user_id=user_id,
        details=stats,
    )
    return {"cleanup_stats": stats}


@router.post("/service-accounts")
@limiter.limit(settings.IAM_CREDENTIALS_RATE_LIMIT)
async def create_svc_account(
    payload: ServiceAccountCreate,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    enforce_mfa_for_admin(user_id, db)

    result = create_service_account(
        db, name=payload.name, owner_id=user_id,
        permissions=payload.permissions, description=payload.description,
        expires_in_days=payload.expires_in_days,
    )
    record_security_event(
        db, action="iam.service_account.created", request=request, user_id=user_id,
        details={"name": payload.name, "permissions": payload.permissions},
    )
    return result


@router.post("/service-accounts/{account_id}/revoke")
@limiter.limit(settings.IAM_CREDENTIALS_RATE_LIMIT)
async def revoke_svc_account(
    account_id: str,
    request: Request,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")

    revoke_service_account(account_id, db)
    record_security_event(
        db, action="iam.service_account.revoked", request=request, user_id=user_id,
        details={"account_id": account_id},
    )
    return {"status": "revoked"}


@router.get("/check/{permission}")
@limiter.limit(settings.IAM_IDENTITIES_RATE_LIMIT)
async def check_permission_endpoint(
    permission: str,
    request: Request,
    resource: str = "*",
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    granted = check_permission(user, permission, resource, db)
    return {"permission": permission, "resource": resource, "granted": granted}
