import uuid
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.core.auth import require_admin
from backend.core.config import settings
from backend.core.database import get_db
from backend.core.security import generate_invite_token, hash_invite_token
from backend.models.schemas import InviteCreateRequest, InviteResponse
from backend.models.user import Invitation, User

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/invites", response_model=InviteResponse)
def create_invite(
    payload: InviteCreateRequest,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    raw_token = generate_invite_token()
    token_hash = hash_invite_token(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.invite_token_expire_days)

    invite = Invitation(
        email=payload.email.lower().strip(),
        invite_token_hash=token_hash,
        invited_by_user_id=admin_user.id,
        expires_at=expires_at,
    )
    db.add(invite)
    db.commit()

    invite_url = f"/accept-invite?token={raw_token}"
    return InviteResponse(
        email=invite.email,
        invite_url=invite_url,
        expires_at=expires_at.isoformat(),
    )


@router.post("/users/{user_id}/revoke")
def revoke_user(
    user_id: str,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID.")

    user = db.query(User).filter(User.id == user_uuid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.status = "revoked"
    user.token_version += 1
    db.commit()

    return {"status": "revoked", "user_id": str(user.id)}
