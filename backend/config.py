"""
CYBERGUARD X — Central Configuration
=====================================

Single source of truth for application configuration.

Provides:
    - Application settings
    - JWT / auth settings
    - Database settings
    - Threat-intelligence settings
    - CORS settings
    - Rate limiting
    - Scan limits
    - Logging

Every setting is environment-driven with safe defaults.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ============================================================
# PROJECT PATHS
# ============================================================

CONFIG_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CONFIG_DIR.parent

DATA_DIR = PROJECT_ROOT / "data"
TEMP_DIR = DATA_DIR / "tmp"
LOG_DIR = PROJECT_ROOT / "logs"
UPLOAD_DIR = DATA_DIR / "uploads"

for directory in (DATA_DIR, TEMP_DIR, LOG_DIR, UPLOAD_DIR):
    directory.mkdir(parents=True, exist_ok=True)


# ============================================================
# HELPERS
# ============================================================

def _parse_csv(value) -> List[str]:
    """Convert comma-separated string to list."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).split(",") if v.strip()]


# ============================================================
# SETTINGS CLASS
# ============================================================

class Settings(BaseSettings):
    """
    CyberGuard X application settings.

    All values load from environment variables or .env file.
    """

    # ========================================================
    # APPLICATION
    # ========================================================

    APP_NAME: str = Field(
        default="CYBERGUARD X",
        alias="APP_NAME",
    )

    APP_VERSION: str = Field(
        default="3.0.0",
        alias="APP_VERSION",
    )

    APP_DESCRIPTION: str = Field(
        default=(
            "CYBERGUARD X — Multi-signal cybersecurity "
            "threat detection and analysis platform."
        ),
        alias="APP_DESCRIPTION",
    )

    ENVIRONMENT: str = Field(
        default="development",
        alias="ENVIRONMENT",
    )

    # Backwards-compat alias
    app_env: str = Field(
        default="development",
        alias="APP_ENV",
    )

    DEBUG: bool = Field(
        default=False,
        alias="DEBUG",
    )

    HOST: str = Field(
        default="0.0.0.0",
        alias="HOST",
    )

    PORT: int = Field(
        default=8000,
        alias="PORT",
    )

    API_PREFIX: str = Field(
        default="/api/v1",
        alias="API_PREFIX",
    )

    # ========================================================
    # SECURITY / JWT
    # ========================================================

    SECRET_KEY: str = Field(
        default="change-me-in-production-please-use-openssl-rand-hex-32",
        alias="SECRET_KEY",
    )

    ALGORITHM: str = Field(
        default="HS256",
        alias="ALGORITHM",
    )

    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=60 * 24,  # 24 hours
        alias="ACCESS_TOKEN_EXPIRE_MINUTES",
    )

    # Lowercase alias for backward compat
    @property
    def secret_key(self) -> str:
        return self.SECRET_KEY

    # ========================================================
    # DATABASE
    # ========================================================

    DATABASE_URL: str = Field(
        default=f"sqlite:///{PROJECT_ROOT / 'cyberguard.db'}",
        alias="DATABASE_URL",
    )

    database_url: str = Field(
        default=f"sqlite:///{PROJECT_ROOT / 'cyberguard.db'}",
        alias="DATABASE_URL_LEGACY",
    )

    DATABASE_ECHO: bool = Field(
        default=False,
        alias="DATABASE_ECHO",
    )

    # ========================================================
    # CORS
    # ========================================================

    CORS_ORIGINS: str = Field(
        default="*",
        alias="CORS_ORIGINS",
    )

    CORS_ALLOW_CREDENTIALS: bool = Field(
        default=False,
        alias="CORS_ALLOW_CREDENTIALS",
    )

    @property
    def CORS_ORIGINS_LIST(self) -> List[str]:
        """Return CORS origins as a list."""
        return _parse_csv(self.CORS_ORIGINS)

    # ========================================================
    # THREAT INTELLIGENCE
    # ========================================================

    VIRUSTOTAL_API_KEY: str = Field(
        default="",
        alias="VIRUSTOTAL_API_KEY",
    )

    CYBERGUARD_VT_API_KEY: str = Field(
        default="",
        alias="CYBERGUARD_VT_API_KEY",
    )

    VIRUSTOTAL_ENABLED: bool = Field(
        default=True,
        alias="VIRUSTOTAL_ENABLED",
    )

    RDAP_ENABLED: bool = Field(
        default=True,
        alias="RDAP_ENABLED",
    )

    DNS_ENABLED: bool = Field(
        default=True,
        alias="DNS_ENABLED",
    )

    THREAT_INTEL_TIMEOUT: float = Field(
        default=10.0,
        alias="THREAT_INTEL_TIMEOUT",
    )

    # ========================================================
    # SCAN LIMITS
    # ========================================================

    MAX_URL_LENGTH: int = Field(
        default=4096,
        alias="MAX_URL_LENGTH",
    )

    MAX_TEXT_LENGTH: int = Field(
        default=50000,
        alias="MAX_TEXT_LENGTH",
    )

    MAX_UPLOAD_SIZE_MB: int = Field(
        default=10,
        alias="MAX_UPLOAD_SIZE_MB",
    )

    MAX_REDIRECT_HOPS: int = Field(
        default=10,
        alias="MAX_REDIRECT_HOPS",
    )

    MAX_PAGE_REQUESTS: int = Field(
        default=80,
        alias="MAX_PAGE_REQUESTS",
    )

    MAX_REQUEST_BODY_BYTES: int = Field(
        default=10 * 1024 * 1024,  # 10 MB
        alias="MAX_REQUEST_BODY_BYTES",
    )

    # ========================================================
    # NETWORK TIMEOUTS
    # ========================================================

    REQUEST_TIMEOUT_SECONDS: float = Field(
        default=12.0,
        alias="REQUEST_TIMEOUT_SECONDS",
    )

    RDAP_TIMEOUT_SECONDS: float = Field(
        default=8.0,
        alias="RDAP_TIMEOUT_SECONDS",
    )

    # ========================================================
    # RATE LIMITING
    # ========================================================

    RATE_LIMIT_ENABLED: bool = Field(
        default=True,
        alias="RATE_LIMIT_ENABLED",
    )

    RATE_LIMIT_REQUESTS: int = Field(
        default=60,
        alias="RATE_LIMIT_REQUESTS",
    )

    RATE_LIMIT_WINDOW_SECONDS: int = Field(
        default=60,
        alias="RATE_LIMIT_WINDOW_SECONDS",
    )

    # ========================================================
    # PLAYWRIGHT (optional)
    # ========================================================

    PLAYWRIGHT_ENABLED: bool = Field(
        default=True,
        alias="PLAYWRIGHT_ENABLED",
    )

    PLAYWRIGHT_HEADLESS: bool = Field(
        default=True,
        alias="PLAYWRIGHT_HEADLESS",
    )

    PLAYWRIGHT_BROWSER: str = Field(
        default="chromium",
        alias="PLAYWRIGHT_BROWSER",
    )

    # ========================================================
    # LOGGING
    # ========================================================

    LOG_LEVEL: str = Field(
        default="INFO",
        alias="LOG_LEVEL",
    )

    LOG_FILE: str = Field(
        default=str(LOG_DIR / "cyberguard.log"),
        alias="LOG_FILE",
    )

    # ========================================================
    # SSRF / NETWORK SECURITY
    # ========================================================

    ALLOW_PRIVATE_NETWORKS: bool = Field(
        default=False,
        alias="ALLOW_PRIVATE_NETWORKS",
    )

    ENABLE_HSTS: bool = Field(
        default=False,
        alias="ENABLE_HSTS",
    )

    TRUST_PROXY_HEADERS: bool = Field(
        default=False,
        alias="TRUST_PROXY_HEADERS",
    )

    # ========================================================
    # PYDANTIC CONFIG
    # ========================================================

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
        populate_by_name=True,
    )

    # ========================================================
    # VALIDATORS
    # ========================================================

    @field_validator("ENVIRONMENT", "app_env", mode="before")
    @classmethod
    def validate_environment(cls, value):
        value = str(value or "development").strip().lower()
        allowed = {"development", "testing", "staging", "production"}
        if value not in allowed:
            return "development"
        return value

    @field_validator("LOG_LEVEL", mode="before")
    @classmethod
    def validate_log_level(cls, value):
        value = str(value or "INFO").strip().upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if value not in allowed:
            return "INFO"
        return value

    # ========================================================
    # PROPERTIES
    # ========================================================

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"

    @property
    def MAX_UPLOAD_SIZE_BYTES(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    @property
    def CORS_ORIGINS_FINAL(self) -> List[str]:
        """Final CORS origins list with defaults."""
        origins = self.CORS_ORIGINS_LIST
        if not origins:
            return [
                "http://localhost:3000",
                "http://localhost:5173",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:5173",
            ]
        return origins

    @property
    def VIRUSTOTAL_KEY_FINAL(self) -> str:
        """Return whichever VT key is configured."""
        return (
            self.VIRUSTOTAL_API_KEY
            or self.CYBERGUARD_VT_API_KEY
            or ""
        ).strip()

    # ========================================================
    # PUBLIC SAFE DICT
    # ========================================================

    def public_dict(self) -> dict:
        """Return configuration safe for logging."""
        return {
            "app_name": self.APP_NAME,
            "app_version": self.APP_VERSION,
            "environment": self.ENVIRONMENT,
            "debug": self.DEBUG,
            "host": self.HOST,
            "port": self.PORT,
            "api_prefix": self.API_PREFIX,
            "cors_origins": self.CORS_ORIGINS_LIST,
            "virustotal_configured": bool(self.VIRUSTOTAL_KEY_FINAL),
            "rdap_enabled": self.RDAP_ENABLED,
            "dns_enabled": self.DNS_ENABLED,
            "rate_limit_enabled": self.RATE_LIMIT_ENABLED,
            "max_url_length": self.MAX_URL_LENGTH,
            "max_text_length": self.MAX_TEXT_LENGTH,
            "max_upload_size_mb": self.MAX_UPLOAD_SIZE_MB,
            "playwright_enabled": self.PLAYWRIGHT_ENABLED,
            "log_level": self.LOG_LEVEL,
        }


# ============================================================
# SINGLETON
# ============================================================

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings singleton."""
    return Settings()


settings = get_settings()


# ============================================================
# COMPATIBILITY EXPORTS
# ============================================================
# These allow old code to keep working without changes.

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

DATABASE_URL = settings.DATABASE_URL
VIRUSTOTAL_API_KEY = settings.VIRUSTOTAL_KEY_FINAL
CORS_ORIGINS = settings.CORS_ORIGINS_FINAL

MAX_URL_LENGTH = settings.MAX_URL_LENGTH
MAX_TEXT_LENGTH = settings.MAX_TEXT_LENGTH
MAX_UPLOAD_SIZE_MB = settings.MAX_UPLOAD_SIZE_MB
MAX_UPLOAD_SIZE_BYTES = settings.MAX_UPLOAD_SIZE_BYTES

MAX_REDIRECT_HOPS = settings.MAX_REDIRECT_HOPS
MAX_PAGE_REQUESTS = settings.MAX_PAGE_REQUESTS
REQUEST_TIMEOUT_SECONDS = settings.REQUEST_TIMEOUT_SECONDS
RDAP_TIMEOUT_SECONDS = settings.RDAP_TIMEOUT_SECONDS

ENVIRONMENT = settings.ENVIRONMENT


# ============================================================
# SELF TEST
# ============================================================

if __name__ == "__main__":
    print()
    print("=" * 60)
    print("CYBERGUARD X — Configuration Test")
    print("=" * 60)
    print()

    for key, value in settings.public_dict().items():
        print(f"  {key:28} : {value}")

    print()
    print("=" * 60)
    print("Configuration loaded successfully.")
    print("=" * 60)
