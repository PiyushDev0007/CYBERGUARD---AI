"""
CYBERGUARD X — Authentication Service
======================================

Provides:
    - User registration
    - Password hashing (bcrypt via passlib)
    - Password verification
    - JWT token creation (python-jose)
    - User authentication
    - Current user resolution

Uses:
    - database.py (User model)
    - config.py (JWT settings)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext


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
    try:
        from backend.config import (
            ACCESS_TOKEN_EXPIRE_MINUTES,
            ALGORITHM,
            SECRET_KEY,
        )
    except ImportError:
        ACCESS_TOKEN_EXPIRE_MINUTES = 1440
        ALGORITHM = "HS256"
        SECRET_KEY = "change-me"


try:
    from database import User
except ImportError:
    try:
        from backend.database import User
    except ImportError:
        User = None


# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger("cyberguard.auth_service")


# ============================================================
# PASSWORD HASHING
# ============================================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


def get_password_hash(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    if not password:
        raise ValueError("Password cannot be empty.")

    password = str(password)[:72]
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    if not plain_password or not hashed_password:
        return False

    plain_password = str(plain_password)[:72]

    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False


# ============================================================
# JWT TOKEN CREATION
# ============================================================

def create_access_token(
    data: dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT access token."""
    to_encode = dict(data)

    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    expire = datetime.now(timezone.utc) + expires_delta
    to_encode["exp"] = expire

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ============================================================
# CONSTANTS
# ============================================================

AUTHENTICATION_ERROR = "Invalid email or password."
ACCOUNT_DISABLED_ERROR = "User account is disabled."
ACCOUNT_NOT_FOUND_ERROR = "User account not found."
DUPLICATE_EMAIL_ERROR = "An account with this email already exists."


# ============================================================
# HELPERS
# ============================================================

def _normalize_email(email: str) -> str:
    normalized = str(email or "").strip().lower()

    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address cannot be empty.",
        )

    if len(normalized) > 320:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address is too long.",
        )

    return normalized


def _normalize_name(name: Optional[str]) -> Optional[str]:
    if name is None:
        return None

    normalized = str(name).strip()

    if not normalized:
        return None

    return normalized[:120]


def _is_account_active(user: Any) -> bool:
    if hasattr(user, "is_active"):
        if getattr(user, "is_active") is False:
            return False
    return True


def _get_user_id(user: Any) -> str:
    user_id = getattr(user, "id", None)

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User record has no valid identifier.",
        )

    return str(user_id)


def _get_user_email(user: Any) -> str:
    return str(getattr(user, "email", "") or "").strip().lower()


def _find_user_by_email(db: Any, email: str) -> Any:
    normalized_email = _normalize_email(email)

    try:
        return (
            db.query(User)
            .filter(User.email == normalized_email)
            .first()
        )
    except AttributeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database model not configured correctly.",
        ) from exc


# ============================================================
# REGISTRATION
# ============================================================

def register_user(db: Any, user_data: Any) -> Any:
    email = _normalize_email(getattr(user_data, "email", ""))
    password = str(getattr(user_data, "password", "") or "")

    if not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password cannot be empty.",
        )

    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters.",
        )

    existing = _find_user_by_email(db, email)

    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=DUPLICATE_EMAIL_ERROR,
        )

    name = _normalize_name(getattr(user_data, "name", None))
    password_hash = get_password_hash(password)

    try:
        user = User(
            email=email,
            password_hash=password_hash,
        )
    except TypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User model misconfigured.",
        ) from exc

    if name is not None:
        user.name = name

    user.is_active = True

    try:
        db.add(user)
        db.commit()
        db.refresh(user)
    except Exception as exc:
        db.rollback()
        logger.exception("Failed to create user")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create user account.",
        ) from exc

    return user


# ============================================================
# AUTHENTICATION
# ============================================================

def authenticate_user(db: Any, email: str, password: str) -> Any:
    normalized_email = _normalize_email(email)
    password = str(password or "")

    if not password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTHENTICATION_ERROR,
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = _find_user_by_email(db, normalized_email)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTHENTICATION_ERROR,
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not _is_account_active(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ACCOUNT_DISABLED_ERROR,
        )

    stored_hash = getattr(user, "password_hash", None)

    if not stored_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTHENTICATION_ERROR,
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(password, stored_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTHENTICATION_ERROR,
            headers={"WWW-Authenticate": "Bearer"},
        )

    if hasattr(user, "last_login_at"):
        user.last_login_at = datetime.now(timezone.utc)

        try:
            db.commit()
            db.refresh(user)
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

    return user


# ============================================================
# TOKEN FOR USER
# ============================================================

def create_user_access_token(user: Any) -> str:
    user_id = _get_user_id(user)
    email = _get_user_email(user)

    payload = {
        "sub": user_id,
        "user_id": user_id,
    }

    if email:
        payload["email"] = email

    return create_access_token(data=payload)


# ============================================================
# CURRENT USER
# ============================================================

def get_current_user(db: Any, token_payload: dict[str, Any]) -> Any:
    if not token_payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = token_payload.get("sub") or token_payload.get("user_id")

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing user identifier.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user = (
            db.query(User)
            .filter(User.id == user_id)
            .first()
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database query failed.",
        )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ACCOUNT_NOT_FOUND_ERROR,
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not _is_account_active(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ACCOUNT_DISABLED_ERROR,
        )

    return user


# ============================================================
# USER PROFILE
# ============================================================

def get_user_profile(user: Any) -> dict[str, Any]:
    user_id = _get_user_id(user)

    return {
        "id": user_id,
        "email": _get_user_email(user),
        "name": getattr(user, "name", None),
        "is_active": _is_account_active(user),
        "created_at": (
            user.created_at.isoformat()
            if getattr(user, "created_at", None)
            else None
        ),
        "last_login_at": (
            user.last_login_at.isoformat()
            if getattr(user, "last_login_at", None)
            else None
        ),
    }


# ============================================================
# RESPONSE BUILDERS
# ============================================================

def build_login_response(user: Any) -> dict[str, Any]:
    if not _is_account_active(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ACCOUNT_DISABLED_ERROR,
        )

    access_token = create_user_access_token(user)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": get_user_profile(user),
    }


def build_registration_response(user: Any) -> dict[str, Any]:
    return {
        "message": "Account created successfully.",
        "user": get_user_profile(user),
    }


# ============================================================
# PASSWORD CHANGE
# ============================================================

def change_password(
    db: Any,
    user: Any,
    current_password: str,
    new_password: str,
) -> Any:
    if not _is_account_active(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ACCOUNT_DISABLED_ERROR,
        )

    current_password = str(current_password or "")
    new_password = str(new_password or "")

    if not current_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is required.",
        )

    if len(new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 8 characters.",
        )

    stored_hash = getattr(user, "password_hash", None)

    if not stored_hash or not verify_password(current_password, stored_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    if verify_password(new_password, stored_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different.",
        )

    user.password_hash = get_password_hash(new_password)

    try:
        db.commit()
        db.refresh(user)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not update password.",
        ) from exc

    return user


# ============================================================
# DEACTIVATE
# ============================================================

def deactivate_user(db: Any, user: Any) -> Any:
    if hasattr(user, "is_active"):
        user.is_active = False

    try:
        db.commit()
        db.refresh(user)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not deactivate account.",
        ) from exc

    return user


# ============================================================
# STATUS
# ============================================================

def authentication_service_status() -> dict[str, Any]:
    return {
        "service": "authentication",
        "status": "available",
        "password_hashing": "enabled",
        "jwt_authentication": "enabled",
        "account_status_validation": "enabled",
    }
