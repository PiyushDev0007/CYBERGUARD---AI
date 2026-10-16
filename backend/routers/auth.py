"""
CYBERGUARD X — Authentication Router
=====================================

API endpoints:
    POST /auth/register
    POST /auth/login
    GET  /auth/me
    POST /auth/change-password
    POST /auth/deactivate
    GET  /auth/status

Responsibilities:
    - HTTP request/response handling
    - Request validation (Pydantic)
    - JWT authentication dependency
    - Delegation to auth_service.py

Business logic lives in:
    backend/auth_service.py
"""

from __future__ import annotations

from typing import Any, Generator

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from jose import JWTError, jwt


# ============================================================
# PROJECT IMPORTS
# ============================================================

try:
    from config import (
        ACCESS_TOKEN_EXPIRE_MINUTES,
        ALGORITHM,
        SECRET_KEY,
    )
except ImportError:
    from backend.config import (
        ACCESS_TOKEN_EXPIRE_MINUTES,
        ALGORITHM,
        SECRET_KEY,
    )

try:
    from database import get_db
except ImportError:
    from backend.database import get_db

try:
    from auth_service import (
        authenticate_user,
        build_login_response,
        build_registration_response,
        change_password,
        deactivate_user,
        get_current_user,
        get_user_profile,
        register_user,
        authentication_service_status,
    )
except ImportError:
    from backend.auth_service import (
        authenticate_user,
        build_login_response,
        build_registration_response,
        change_password,
        deactivate_user,
        get_current_user,
        get_user_profile,
        register_user,
        authentication_service_status,
    )

try:
    from schemas import (
        ChangePasswordRequest,
        UserCreate,
        UserLogin,
    )
except ImportError:
    from backend.schemas import (
        ChangePasswordRequest,
        UserCreate,
        UserLogin,
    )


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


# ============================================================
# SECURITY
# ============================================================

bearer_scheme = HTTPBearer(auto_error=False)


# ============================================================
# DATABASE DEPENDENCY
# ============================================================

def database_session() -> Generator[Any, None, None]:
    """FastAPI database dependency."""
    db = next(get_db())
    try:
        yield db
    finally:
        try:
            db.close()
        except Exception:
            pass


# ============================================================
# JWT DECODE
# ============================================================

def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT access token."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not (payload.get("sub") or payload.get("user_id")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token does not contain a user identifier.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


# ============================================================
# CURRENT USER DEPENDENCY
# ============================================================

def get_authenticated_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Any = Depends(database_session),
) -> Any:
    """Resolve the authenticated user from the Bearer token."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)

    return get_current_user(db=db, token_payload=payload)


# ============================================================
# POST /auth/register
# ============================================================

@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
async def register(
    user_data: UserCreate,
    db: Any = Depends(database_session),
):
    """Register a new CyberGuard X user."""
    user = register_user(db=db, user_data=user_data)
    return build_registration_response(user)


# ============================================================
# POST /auth/login
# ============================================================

@router.post(
    "/login",
    summary="Login and receive a JWT access token",
)
async def login(
    credentials: UserLogin,
    db: Any = Depends(database_session),
):
    """Authenticate a user and return a JWT."""
    user = authenticate_user(
        db=db,
        email=credentials.email,
        password=credentials.password,
    )
    return build_login_response(user)


# ============================================================
# GET /auth/me
# ============================================================

@router.get(
    "/me",
    summary="Get current user profile",
)
async def current_user_profile(
    current_user: Any = Depends(get_authenticated_user),
):
    """Return the authenticated user's profile."""
    return {
        "status": "success",
        "user": get_user_profile(current_user),
    }


# ============================================================
# POST /auth/change-password
# ============================================================

@router.post(
    "/change-password",
    summary="Change current user password",
)
async def update_password(
    request: ChangePasswordRequest,
    current_user: Any = Depends(get_authenticated_user),
    db: Any = Depends(database_session),
):
    """Change the authenticated user's password."""
    updated = change_password(
        db=db,
        user=current_user,
        current_password=request.current_password,
        new_password=request.new_password,
    )

    return {
        "status": "success",
        "message": "Password changed successfully.",
        "user": get_user_profile(updated),
    }


# ============================================================
# POST /auth/deactivate
# ============================================================

@router.post(
    "/deactivate",
    summary="Deactivate current user account",
)
async def deactivate_account(
    current_user: Any = Depends(get_authenticated_user),
    db: Any = Depends(database_session),
):
    """Deactivate the authenticated account."""
    updated = deactivate_user(db=db, user=current_user)

    return {
        "status": "success",
        "message": "Account deactivated successfully.",
        "user": get_user_profile(updated),
    }


# ============================================================
# GET /auth/status
# ============================================================

@router.get(
    "/status",
    summary="Authentication service status",
)
async def auth_status():
    """Return non-sensitive auth service info."""
    return authentication_service_status()
