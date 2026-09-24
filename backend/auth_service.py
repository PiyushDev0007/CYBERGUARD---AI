"""
CYBERGUARD X — Authentication Service

Responsibilities:
    - User registration
    - Password hashing / verification
    - User authentication
    - JWT access-token creation
    - Current-user resolution
    - Account status validation
    - Duplicate-account protection
    - Safe authentication errors

This module contains authentication BUSINESS LOGIC.

HTTP routes belong in:
    backend/routers/auth.py

Database models/session management belong in:
    backend/database.py

Cryptographic/JWT helpers belong in:
    backend/security.py
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import HTTPException, status

# ============================================================
# PROJECT IMPORTS
# ============================================================

try:
    from database import (
        User,
        get_db,
    )
except ImportError:
    from backend.database import (
        User,
        get_db,
    )

try:
    from security import (
        create_access_token,
        get_password_hash,
        verify_password,
    )
except ImportError:
    from backend.security import (
        create_access_token,
        get_password_hash,
        verify_password,
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
# AUTHENTICATION CONSTANTS
# ============================================================

AUTHENTICATION_ERROR = "Invalid email or password."

ACCOUNT_DISABLED_ERROR = "User account is disabled."

ACCOUNT_NOT_FOUND_ERROR = "User account not found."

DUPLICATE_EMAIL_ERROR = "An account with this email already exists."


# ============================================================
# INTERNAL HELPERS
# ============================================================

def _normalize_email(email: str) -> str:
    """
    Normalize an email address before database lookup/storage.

    Email addresses are intentionally normalized to lowercase for
    consistent account lookup.
    """

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
    """
    Normalize an optional display name.
    """

    if name is None:
        return None

    normalized = str(name).strip()

    if not normalized:
        return None

    return normalized[:120]


def _is_account_active(user: Any) -> bool:
    """
    Determine whether a user account is active.

    Supports common model field names so the service remains
    compatible with the database model used by the project.
    """

    # Common field: is_active
    if hasattr(user, "is_active"):
        value = getattr(user, "is_active")

        if value is False:
            return False

    # Optional field: disabled
    if hasattr(user, "disabled"):
        value = getattr(user, "disabled")

        if value is True:
            return False

    # Optional field: status
    if hasattr(user, "status"):
        account_status = str(
            getattr(user, "status") or ""
        ).strip().lower()

        if account_status in {
            "disabled",
            "inactive",
            "blocked",
            "suspended",
            "banned",
        }:
            return False

    return True


def _set_if_exists(
    obj: Any,
    field_name: str,
    value: Any,
) -> None:
    """
    Set an ORM field only when that field exists on the model.

    This prevents authentication logic from breaking if the database
    model contains a slightly different optional field set.
    """

    if hasattr(obj, field_name):
        setattr(obj, field_name, value)


def _get_user_id(user: Any) -> str:
    """
    Extract the user's primary identifier.

    Supports:
        id
        user_id
    """

    user_id = getattr(user, "id", None)

    if user_id is None:
        user_id = getattr(user, "user_id", None)

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User record has no valid identifier.",
        )

    return str(user_id)


def _get_password_hash(user: Any) -> Optional[str]:
    """
    Extract stored password hash.

    Supports common database field names.
    """

    password_hash = getattr(
        user,
        "password_hash",
        None,
    )

    if password_hash:
        return str(password_hash)

    hashed_password = getattr(
        user,
        "hashed_password",
        None,
    )

    if hashed_password:
        return str(hashed_password)

    return None


def _get_user_email(user: Any) -> str:
    """
    Safely extract a user's email.
    """

    return str(
        getattr(user, "email", "") or ""
    ).strip().lower()


def _find_user_by_email(
    db: Any,
    email: str,
) -> Any:
    """
    Find a user by normalized email.

    This function assumes a SQLAlchemy-style session, which is the
    expected database implementation for the project.
    """

    normalized_email = _normalize_email(email)

    try:
        return (
            db.query(User)
            .filter(
                User.email == normalized_email
            )
            .first()
        )

    except AttributeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database user model is not configured correctly.",
        ) from exc


# ============================================================
# USER LOOKUP
# ============================================================

def get_user_by_email(
    db: Any,
    email: str,
) -> Any:
    """
    Public helper for retrieving a user by email.

    Returns:
        User object or None
    """

    return _find_user_by_email(
        db=db,
        email=email,
    )


def get_user_by_id(
    db: Any,
    user_id: str | int,
) -> Any:
    """
    Retrieve a user by primary key.
    """

    try:
        return (
            db.query(User)
            .filter(
                User.id == user_id
            )
            .first()
        )

    except AttributeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database user model is not configured correctly.",
        ) from exc


# ============================================================
# USER REGISTRATION
# ============================================================

def register_user(
    db: Any,
    user_data: UserCreate,
) -> Any:
    """
    Create a new CyberGuard X user.

    Responsibilities:
        - Normalize email
        - Validate duplicate account
        - Hash password
        - Create ORM user
        - Commit transaction
        - Refresh ORM object
        - Roll back safely on database failure

    Passwords are NEVER stored in plaintext.
    """

    email = _normalize_email(
        getattr(
            user_data,
            "email",
            "",
        )
    )

    password = str(
        getattr(
            user_data,
            "password",
            "",
        )
        or ""
    )

    if not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password cannot be empty.",
        )

    existing_user = _find_user_by_email(
        db=db,
        email=email,
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=DUPLICATE_EMAIL_ERROR,
        )

    name = _normalize_name(
        getattr(
            user_data,
            "name",
            None,
        )
    )

    password_hash = get_password_hash(
        password
    )

    # --------------------------------------------------------
    # Create ORM object
    # --------------------------------------------------------

    try:
        user = User(
            email=email,
            password_hash=password_hash,
        )

    except TypeError:
        # Compatibility with models using hashed_password.
        try:
            user = User(
                email=email,
                hashed_password=password_hash,
            )

        except TypeError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "User model does not support the required "
                    "authentication fields."
                ),
            ) from exc

    # --------------------------------------------------------
    # Optional user fields
    # --------------------------------------------------------

    if name is not None:
        _set_if_exists(
            user,
            "name",
            name,
        )

        _set_if_exists(
            user,
            "full_name",
            name,
        )

        _set_if_exists(
            user,
            "display_name",
            name,
        )

    # New accounts should normally be active.
    _set_if_exists(
        user,
        "is_active",
        True,
    )

    _set_if_exists(
        user,
        "disabled",
        False,
    )

    _set_if_exists(
        user,
        "status",
        "active",
    )

    # Optional creation timestamp.
    now = datetime.now(timezone.utc)

    _set_if_exists(
        user,
        "created_at",
        now,
    )

    _set_if_exists(
        user,
        "updated_at",
        now,
    )

    # --------------------------------------------------------
    # Database transaction
    # --------------------------------------------------------

    try:
        db.add(user)
        db.commit()
        db.refresh(user)

    except Exception as exc:
        db.rollback()

        # Do not leak raw database errors to clients.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create user account.",
        ) from exc

    return user


# ============================================================
# PASSWORD AUTHENTICATION
# ============================================================

def authenticate_user(
    db: Any,
    email: str,
    password: str,
) -> Any:
    """
    Authenticate a user using email and password.

    Returns:
        User object when credentials are valid.

    Raises:
        HTTPException 401 for invalid credentials.
        HTTPException 403 for disabled accounts.

    Important:
        The same invalid-credential message is returned for unknown
        email and incorrect password to reduce account enumeration.
    """

    normalized_email = _normalize_email(
        email
    )

    password = str(password or "")

    if not password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTHENTICATION_ERROR,
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    user = _find_user_by_email(
        db=db,
        email=normalized_email,
    )

    # --------------------------------------------------------
    # Do not reveal whether the email exists.
    # --------------------------------------------------------

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTHENTICATION_ERROR,
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    if not _is_account_active(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ACCOUNT_DISABLED_ERROR,
        )

    stored_hash = _get_password_hash(
        user
    )

    if not stored_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTHENTICATION_ERROR,
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    try:
        valid_password = verify_password(
            password,
            stored_hash,
        )

    except Exception:
        valid_password = False

    if not valid_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTHENTICATION_ERROR,
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    # --------------------------------------------------------
    # Update login metadata when supported.
    # --------------------------------------------------------

    now = datetime.now(timezone.utc)

    _set_if_exists(
        user,
        "last_login_at",
        now,
    )

    _set_if_exists(
        user,
        "updated_at",
        now,
    )

    try:
        db.commit()
        db.refresh(user)

    except Exception:
        # Authentication itself succeeded. A metadata update should
        # not turn a successful login into a false authentication
        # failure.
        try:
            db.rollback()
        except Exception:
            pass

    return user


# ============================================================
# ACCESS TOKEN
# ============================================================

def create_user_access_token(
    user: Any,
) -> str:
    """
    Create a JWT access token for an authenticated user.

    The subject (`sub`) contains the stable user identifier.

    Additional claims:
        user_id
        email
    """

    user_id = _get_user_id(
        user
    )

    email = _get_user_email(
        user
    )

    payload = {
        "sub": user_id,
        "user_id": user_id,
    }

    if email:
        payload["email"] = email

    return create_access_token(
        data=payload
    )


# ============================================================
# CURRENT USER
# ============================================================

def get_current_user(
    db: Any,
    token_payload: dict[str, Any],
) -> Any:
    """
    Resolve a JWT payload into a database user.

    Expected token claims:

        sub
        or
        user_id

    The router/dependency responsible for decoding the JWT should
    pass the decoded payload to this function.
    """

    if not token_payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    user_id = (
        token_payload.get("sub")
        or token_payload.get("user_id")
    )

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token does not contain a user identifier.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    user = get_user_by_id(
        db=db,
        user_id=user_id,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ACCOUNT_NOT_FOUND_ERROR,
            headers={
                "WWW-Authenticate": "Bearer",
            },
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

def get_user_profile(
    user: Any,
) -> dict[str, Any]:
    """
    Return a safe public representation of a user.

    Password hashes and authentication secrets are intentionally
    excluded.
    """

    user_id = _get_user_id(
        user
    )

    email = _get_user_email(
        user
    )

    name = (
        getattr(user, "name", None)
        or getattr(user, "full_name", None)
        or getattr(user, "display_name", None)
    )

    is_active = _is_account_active(
        user
    )

    result = {
        "id": user_id,
        "email": email,
        "name": name,
        "is_active": is_active,
    }

    # Optional profile metadata.
    if hasattr(user, "created_at"):
        result["created_at"] = getattr(
            user,
            "created_at",
        )

    if hasattr(user, "last_login_at"):
        result["last_login_at"] = getattr(
            user,
            "last_login_at",
        )

    if hasattr(user, "status"):
        result["status"] = getattr(
            user,
            "status",
        )

    return result


# ============================================================
# ACCOUNT STATUS
# ============================================================

def ensure_user_active(
    user: Any,
) -> None:
    """
    Raise an exception if the account is disabled.
    """

    if not _is_account_active(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ACCOUNT_DISABLED_ERROR,
        )


# ============================================================
# PASSWORD CHANGE
# ============================================================

def change_password(
    db: Any,
    user: Any,
    current_password: str,
    new_password: str,
) -> Any:
    """
    Change an authenticated user's password.

    Security requirements:
        - Current password must be verified.
        - New password must not be empty.
        - New password must differ from current password.
        - New password is hashed before storage.
    """

    ensure_user_active(
        user
    )

    current_password = str(
        current_password or ""
    )

    new_password = str(
        new_password or ""
    )

    if not current_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is required.",
        )

    if not new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password is required.",
        )

    stored_hash = _get_password_hash(
        user
    )

    if not stored_hash:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User password configuration is invalid.",
        )

    try:
        current_valid = verify_password(
            current_password,
            stored_hash,
        )

    except Exception:
        current_valid = False

    if not current_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    try:
        same_password = verify_password(
            new_password,
            stored_hash,
        )

    except Exception:
        same_password = False

    if same_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the current password.",
        )

    new_hash = get_password_hash(
        new_password
    )

    if hasattr(user, "password_hash"):
        user.password_hash = new_hash

    elif hasattr(user, "hashed_password"):
        user.hashed_password = new_hash

    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User model does not contain a password field.",
        )

    _set_if_exists(
        user,
        "updated_at",
        datetime.now(timezone.utc),
    )

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
# ACCOUNT DEACTIVATION
# ============================================================

def deactivate_user(
    db: Any,
    user: Any,
) -> Any:
    """
    Deactivate a user account.

    The account is disabled rather than physically deleted.

    This preserves historical scan ownership and audit records.
    """

    if hasattr(user, "is_active"):
        user.is_active = False

    if hasattr(user, "disabled"):
        user.disabled = True

    if hasattr(user, "status"):
        user.status = "disabled"

    _set_if_exists(
        user,
        "updated_at",
        datetime.now(timezone.utc),
    )

    try:
        db.commit()
        db.refresh(user)

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not deactivate user account.",
        ) from exc

    return user


# ============================================================
# AUTHENTICATION RESULT
# ============================================================

def build_login_response(
    user: Any,
) -> dict[str, Any]:
    """
    Build the standard authentication response.

    Router code can return this directly through the appropriate
    Pydantic response schema.
    """

    ensure_user_active(
        user
    )

    access_token = create_user_access_token(
        user
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": get_user_profile(
            user
        ),
    }


# ============================================================
# REGISTRATION RESULT
# ============================================================

def build_registration_response(
    user: Any,
) -> dict[str, Any]:
    """
    Build the standard registration response.

    The newly created account is returned as a safe profile.

    Login/token issuance remains a separate operation.
    """

    return {
        "message": "Account created successfully.",
        "user": get_user_profile(
            user
        ),
    }


# ============================================================
# SERVICE HEALTH INFORMATION
# ============================================================

def authentication_service_status() -> dict[str, Any]:
    """
    Return basic service capability information.

    This does not expose secrets or configuration values.
    """

    return {
        "service": "authentication",
        "status": "available",
        "password_hashing": "enabled",
        "jwt_authentication": "enabled",
        "account_status_validation": "enabled",
    }
