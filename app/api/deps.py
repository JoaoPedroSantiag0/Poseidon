"""FastAPI Application Dependencies for DB, Authentication, and RBAC."""
from collections.abc import AsyncGenerator, Callable

import structlog
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import has_permission
from app.core.security import decode_access_token
from app.db.session import AsyncSessionLocal
from app.models.enums import UserRole
from app.models.user import User

logger = structlog.get_logger(__name__)

# Standard Bearer scheme
security_bearer = HTTPBearer(auto_error=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that yields an async database session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(security_bearer),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Extracts and validates current authenticated user from Bearer JWT token."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token missing or malformed.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or corrupted token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload["sub"]
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    return user


def require_permission(permission: str) -> Callable:
    """Dependency factory checking whether current user has a specific granular permission."""
    async def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.is_superuser:
            return current_user
        if not has_permission(current_user.role, permission):
            logger.warning(
                "rbac_permission_denied",
                user_id=current_user.id,
                user_role=current_user.role,
                required_permission=permission
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Missing required permission: '{permission}'."
            )
        return current_user
    return permission_checker


def require_role(*allowed_roles: UserRole) -> Callable:
    """Dependency factory checking whether current user has one of the specified roles."""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.is_superuser or current_user.role in allowed_roles:
            return current_user
        logger.warning(
            "rbac_role_denied",
            user_id=current_user.id,
            user_role=current_user.role,
            allowed_roles=[r.value for r in allowed_roles]
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Role insufficient for this operation."
        )
    return role_checker
