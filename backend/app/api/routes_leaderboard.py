from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models import get_db, AuditJob, FindingModel
from app.schemas.audit_state import Severity
from app.services.auth import get_current_user
from app.services.limiter import limiter

router = APIRouter(prefix="/leaderboard", tags=["Leaderboard"])

@router.get("")
@router.get("/")
@limiter.limit(settings.LEADERBOARD_RATE_LIMIT)
async def get_leaderboard(
    request: Request,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    from sqlalchemy import or_
    from app.models import User, Membership

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return []

    # Get all organization IDs from memberships
    memberships = db.query(Membership).filter(Membership.user_id == user_id).all()
    org_ids = [m.organization_id for m in memberships]
    if user.tenant_id:
        org_ids.append(user.tenant_id)

    scope_filter = or_(
        AuditJob.user_id == user_id,
        AuditJob.tenant_id.in_(org_ids)
    ) if org_ids else (AuditJob.user_id == user_id)

    subquery = db.query(
        AuditJob.repo_url,
        func.max(AuditJob.security_score).label("max_score"),
    ).filter(
        AuditJob.security_score.isnot(None),
        scope_filter
    ).group_by(AuditJob.repo_url).subquery()

    critical_counts = (
        db.query(
            FindingModel.job_id.label("job_id"),
            func.count(FindingModel.id).label("critical_count"),
        )
        .filter(FindingModel.severity == Severity.CRITICAL)
        .group_by(FindingModel.job_id)
        .subquery()
    )

    leaderboard_jobs = db.query(
        AuditJob.id,
        AuditJob.repo_url,
        AuditJob.security_score,
        AuditJob.finished_at,
    ).filter(
        scope_filter
    ).join(
        subquery,
        (AuditJob.repo_url == subquery.c.repo_url) & (AuditJob.security_score == subquery.c.max_score),
    ).outerjoin(
        critical_counts,
        critical_counts.c.job_id == AuditJob.id,
    ).add_columns(
        critical_counts.c.critical_count,
    ).order_by(AuditJob.security_score.desc()).limit(10).all()

    results = []
    for job in leaderboard_jobs:
        results.append({
            "repo_url": job.repo_url,
            "score": job.security_score,
            "security_score": job.security_score,
            "completed_at": job.finished_at.isoformat() if job.finished_at else None,
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "critical_count": int(job.critical_count or 0),
        })

    return results
