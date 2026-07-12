from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
import logging

from app.models import get_db, PushSubscription
from app.services.auth import get_current_user
from app.services.limiter import limiter
from app.services.push_notify import load_or_generate_vapid_keys

logger = logging.getLogger("firecrow.api.push")
router = APIRouter(prefix="/push", tags=["Push Notifications"])

class SubscribeRequest(BaseModel):
    endpoint: str
    p256dh: str
    auth: str

@router.get("/vapid-public-key")
@limiter.limit(settings.PUSH_REGISTER_RATE_LIMIT)
async def get_vapid_public_key(request: Request):
    _, pub_key = load_or_generate_vapid_keys()
    if not pub_key:
        raise HTTPException(status_code=500, detail="VAPID keys not generated.")
    return {"public_key": pub_key}

@router.post("/subscribe")
@limiter.limit(settings.PUSH_UNREGISTER_RATE_LIMIT)
async def subscribe_user(
    payload: SubscribeRequest,
    request: Request,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    existing = db.query(PushSubscription).filter(PushSubscription.endpoint == payload.endpoint).first()
    if existing:
        existing.user_id = user_id
        existing.p256dh = payload.p256dh
        existing.auth = payload.auth
    else:
        new_sub = PushSubscription(
            user_id=user_id,
            endpoint=payload.endpoint,
            p256dh=payload.p256dh,
            auth=payload.auth
        )
        db.add(new_sub)
    db.commit()
    return {"status": "subscribed"}
