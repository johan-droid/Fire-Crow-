import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.models.database import get_db
from app.models.user import User
from app.models.domain_verification import DomainVerification
from app.schemas.domain_verify import (
    DomainVerifyRequest,
    DomainVerifyResponse,
    DomainCheckRequest,
    DomainCheckResponse,
)
from app.services.auth import get_current_user
from app.services.domain_verify import DomainVerificationService
from app.services.limiter import limiter
from app.services.security_log import record_security_event

logger = logging.getLogger("firecrow.api.verify")

router = APIRouter(prefix="/verify", tags=["Domain Verification"])


def _build_response_details(record: DomainVerification) -> DomainVerifyResponse:
    return DomainVerifyResponse(
        id=record.id,
        domain=record.domain,
        verification_token=record.verification_token,
        verified=record.verified,
        verified_at=record.verified_at.isoformat() if record.verified_at else None,
        created_at=record.created_at.isoformat(),
        dns_txt_name=f"_firecrow-challenge.{record.domain}",
        dns_txt_value=record.verification_token,
        html_meta_name="firecrow-verification",
        html_meta_content=record.verification_token,
        well_known_path=f"/.well-known/firecrow.txt",
        well_known_content=record.verification_token,
    )


@router.get("/domains", response_model=List[DomainVerifyResponse])
@limiter.limit(settings.VERIFY_CHALLENGSE_RATE_LIMIT)
async def list_domains(
    request: Request,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
):
    """List all registered and verified domains for the current user."""
    records = db.query(DomainVerification).filter(DomainVerification.user_id == user_id).all()
    return [_build_response_details(r) for r in records]


@router.post("/domain", response_model=DomainVerifyResponse)
@limiter.limit(settings.VERIFY_STATUS_RATE_LIMIT)
async def initiate_verification(
    request: Request,
    payload: DomainVerifyRequest,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
):
    """Initiate ownership verification for a domain."""
    user = db.query(User).filter(User.id == user_id).first()
    tenant_id = user.tenant_id if user else None

    record = DomainVerificationService.get_verification_details(
        db, domain=payload.domain, user_id=user_id, tenant_id=tenant_id
    )

    record_security_event(
        db,
        action="domain.verify.initiate",
        request=request,
        user_id=user_id,
        details={"domain": payload.domain, "id": record.id},
    )

    return _build_response_details(record)


@router.post("/domain/check", response_model=DomainCheckResponse)
@limiter.limit(settings.VERIFY_STATUS_RATE_LIMIT)
async def check_verification(
    request: Request,
    payload: DomainCheckRequest,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
):
    """Run verification check for a domain using the specified method."""
    record = db.query(DomainVerification).filter(
        DomainVerification.domain == payload.domain,
        DomainVerification.user_id == user_id
    ).first()

    if not record:
        raise HTTPException(status_code=404, detail="Domain verification not initiated.")

    if record.verified:
        return DomainCheckResponse(verified=True, message="Domain is already verified.")

    verified = False
    method_name = payload.method.lower()

    if method_name == "dns":
        verified = await DomainVerificationService.verify_dns(record.domain, record.verification_token)
    elif method_name == "html":
        verified = await DomainVerificationService.verify_html(record.domain, record.verification_token)
    elif method_name == "file":
        verified = await DomainVerificationService.verify_file(record.domain, record.verification_token)

    if verified:
        record.verified = True
        record.verified_at = datetime.now(timezone.utc)
        record.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(record)

        record_security_event(
            db,
            action="domain.verify.success",
            request=request,
            user_id=user_id,
            details={"domain": record.domain, "method": method_name},
        )
        return DomainCheckResponse(verified=True, message=f"Domain verified successfully using {method_name.upper()}.")
    else:
        return DomainCheckResponse(verified=False, message=f"Verification via {method_name.upper()} failed. Please ensure the record/tag/file is correctly configured.")


@router.delete("/domain/{id}")
@limiter.limit(settings.VERIFY_STATUS_RATE_LIMIT)
async def delete_domain(
    id: str,
    request: Request,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
):
    """Remove a domain verification record."""
    record = db.query(DomainVerification).filter(
        DomainVerification.id == id,
        DomainVerification.user_id == user_id
    ).first()

    if not record:
        raise HTTPException(status_code=404, detail="Domain verification record not found.")

    db.delete(record)
    db.commit()

    record_security_event(
        db,
        action="domain.verify.delete",
        request=request,
        user_id=user_id,
        details={"domain": record.domain, "id": id},
    )

    return {"status": "success", "message": "Domain verification record removed."}
