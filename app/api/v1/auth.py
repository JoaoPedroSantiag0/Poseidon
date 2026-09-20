"""Authentication Endpoints (Login, Profile, Logout)."""
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.audit import record_audit_event
from app.core.config import settings
from app.core.security import create_access_token, verify_password
from app.models.user import User
from app.schemas.auth import LoginRequest, Token, UserResponse

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post("/auth/login", response_model=Token, tags=["Authentication"])
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Authenticates user with email and password, returning JWT access token."""
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    result = await db.execute(select(User).where(User.email == login_data.email))
    user = result.scalars().first()

    if not user or not verify_password(login_data.password, user.hashed_password):
        await record_audit_event(
            session=db,
            action="AUTH_LOGIN_FAILED",
            resource_type="user",
            resource_id=login_data.email,
            user_email=login_data.email,
            ip_address=ip_address,
            user_agent=user_agent,
            reason="Invalid credentials supplied."
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Contact Poseidon administrator."
        )

    # Update last login
    user.last_login = datetime.now(UTC)

    # Record success audit event
    await record_audit_event(
        session=db,
        action="AUTH_LOGIN_SUCCESS",
        resource_type="user",
        resource_id=user.id,
        user_id=user.id,
        user_email=user.email,
        ip_address=ip_address,
        user_agent=user_agent,
        reason="User successfully authenticated."
    )
    await db.commit()

    token_str = create_access_token(
        subject=user.id,
        extra_claims={
            "email": user.email,
            "role": user.role.value,
            "org_id": user.organization_id
        }
    )

    return Token(
        access_token=token_str,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user)
    )


@router.get("/auth/me", response_model=UserResponse, tags=["Authentication"])
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Returns the profile of the currently authenticated user."""
    return UserResponse.model_validate(current_user)


@router.post("/auth/logout", tags=["Authentication"])
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Logs out current user and records audit trail."""
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    await record_audit_event(
        session=db,
        action="AUTH_LOGOUT",
        resource_type="user",
        resource_id=current_user.id,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=ip_address,
        user_agent=user_agent,
        reason="User logged out."
    )
    await db.commit()
    return {"message": "Successfully logged out."}
