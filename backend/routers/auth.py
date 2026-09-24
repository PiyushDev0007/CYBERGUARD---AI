"""
CYBERGUARD X — Authentication Router

API endpoints:

    POST /auth/register
    POST /auth/login
    GET  /auth/me
    POST /auth/change-password
    POST /auth/deactivate

Responsibilities:
    - HTTP request/response handling
    - Request validation
    - JWT authentication dependency
    - Database-session dependency
    - Delegation to auth_service.py

Business logic belongs in:
    services/auth_service.py

Database logic belongs in:
    database.py

Password/JWT cryptographic helpers belong in:
    security.py
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
from pydantic import BaseModel, Field

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
    from database import (
        get_db,
    )
except ImportError:
    from backend.database import (
        get_db,
    )

try:
    from services.auth_service import (
        authenticate_user,
        build_login_response,
        build_registration_response,
        change_password,
        deactivate_user,
        get_current_user,
        register_user,
    )
except ImportError:
    from backend.services.auth_service import (
        authenticate_user,
        build_login_response,
        build_registration_response,
        change_password,
        deactivate_user,
        get_current_user,
        register_user,
    )

try:
    from schemas import (
        UserCreate,
    )
except ImportError:
    from backend.schemas import (
        UserCreate,
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

bearer_scheme = HTTPBearer(
    auto_error=False,
)


# ============================================================
# REQUEST SCHEMAS
# ============================================================

class LoginRequest(BaseModel):
    """
    Login credentials.
    """

    email: str = Field(
        ...,
        min_length=3,
        max_length=320,
    )

    password: str = Field(
        ...,
        min_length=1,
        max_length=256,
    )


class ChangePasswordRequest(BaseModel):
    """
    Password-change request.
    """

    current_password: str = Field(
        ...,
        min_length=1,
        max_length=256,
    )

    new_password: str = Field(
        ...,
        min_length=8,
        max_length=256,
    )


class TokenResponse(BaseModel):
    """
    Basic JWT response schema.
    """

    access_token: str
    token_type: str = "bearer"


# ============================================================
# DATABASE DEPENDENCY
# ============================================================

def database_session() -> Generator[Any, None, None]:
    """
    FastAPI database dependency.

    Delegates database lifecycle management to database.py.
    """

    db = next(
        get_db()
    )

    try:
        yield db

    finally:
        try:
            db.close()
        except Exception:
            pass


# ============================================================
# JWT DECODING
# ============================================================

def decode_access_token(
    token: str,
) -> dict[str, Any]:
    """
    Decode and validate a JWT access token.

    The token must:
        - be correctly signed
        - use the configured algorithm
        - contain a subject/user identifier
        - not be expired
    """

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is required.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
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
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from exc

    if not isinstance(
        payload,
        dict,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    subject = (
        payload.get("sub")
        or payload.get("user_id")
    )

    if subject is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token does not contain a user identifier.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    return payload


# ============================================================
# CURRENT USER DEPENDENCY
# ============================================================

def get_authenticated_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
    db: Any = Depends(
        database_session
    ),
) -> Any:
    """
    FastAPI dependency that resolves the authenticated user.

    Usage:

        current_user = Depends(get_authenticated_user)
    """

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    if credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer authentication is required.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    payload = decode_access_token(
        credentials.credentials
    )

    return get_current_user(
        db=db,
        token_payload=payload,
    )


# ============================================================
# REGISTER
# ============================================================

@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user_data: UserCreate,
    db: Any = Depends(
        database_session
    ),
):
    """
    Register a new CyberGuard X user.

    Endpoint:

        POST /auth/register
    """

    user = register_user(
        db=db,
        user_data=user_data,
    )

    return build_registration_response(
        user
    )


# ============================================================
# LOGIN
# ============================================================

@router.post(
    "/login",
)
async def login(
    credentials: LoginRequest,
    db: Any = Depends(
        database_session
    ),
):
    """
    Authenticate a user and return a JWT access token.

    Endpoint:

        POST /auth/login
    """

    user = authenticate_user(
        db=db,
        email=credentials.email,
        password=credentials.password,
    )

    return build_login_response(
        user
    )


# ============================================================
# CURRENT USER
# ============================================================

@router.get(
    "/me",
)
async def current_user_profile(
    current_user: Any = Depends(
        get_authenticated_user
    ),
):
    """
    Return the currently authenticated user's profile.

    Endpoint:

        GET /auth/me
    """

    # Import locally to avoid unnecessary module coupling.
    try:
        from services.auth_service import (
            get_user_profile,
        )
    except ImportError:
        from backend.services.auth_service import (
            get_user_profile,
        )

    return {
        "status": "success",
        "user": get_user_profile(
            current_user
        ),
    }


# ============================================================
# CHANGE PASSWORD
# ============================================================

@router.post(
    "/change-password",
)
async def update_password(
    request: ChangePasswordRequest,
    current_user: Any = Depends(
        get_authenticated_user
    ),
    db: Any = Depends(
        database_session
    ),
):
    """
    Change the currently authenticated user's password.

    Endpoint:

        POST /auth/change-password
    """

    updated_user = change_password(
        db=db,
        user=current_user,
        current_password=request.current_password,
        new_password=request.new_password,
    )

    try:
        from services.auth_service import (
            get_user_profile,
        )
    except ImportError:
        from backend.services.auth_service import (
            get_user_profile,
        )

    return {
        "status": "success",
        "message": "Password changed successfully.",
        "user": get_user_profile(
            updated_user
        ),
    }


# ============================================================
# DEACTIVATE ACCOUNT
# ============================================================

@router.post(
    "/deactivate",
)
async def deactivate_account(
    current_user: Any = Depends(
        get_authenticated_user
    ),
    db: Any = Depends(
        database_session
    ),
):
    """
    Deactivate the currently authenticated account.

    Endpoint:

        POST /auth/deactivate
    """

    updated_user = deactivate_user(
        db=db,
        user=current_user,
    )

    try:
        from services.auth_service import (
            get_user_profile,
        )
    except ImportError:
        from backend.services.auth_service import (
            get_user_profile,
        )

    return {
        "status": "success",
        "message": "Account deactivated successfully.",
        "user": get_user_profile(
            updated_user
        ),
    }


# ============================================================
# AUTHENTICATION SERVICE STATUS
# ============================================================

@router.get(
    "/status",
)
async def authentication_status():
    """
    Return non-sensitive authentication service status.

    Endpoint:

        GET /auth/status

    This endpoint intentionally does not expose:
        - SECRET_KEY
        - database credentials
        - JWT tokens
        - API keys
    """

    try:
        from services.auth_service import (
            authentication_service_status,
        )
    except ImportError:
        from backend.services.auth_service import (
            authentication_service_status,
        )

    return authentication_service_status()
