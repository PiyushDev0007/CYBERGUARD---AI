"""
CYBERGUARD X — Central Configuration
====================================

Single source of truth for application configuration.

Responsibilities:
    - Load environment variables safely
    - Validate configuration
    - Provide typed application settings
    - Configure database settings
    - Configure threat-intelligence providers
    - Configure network / SSRF limits
    - Configure upload limits
    - Configure Playwright scanning
    - Configure CORS
    - Configure logging
    - Keep secrets outside source code

Recommended environment file:

    .env

Example:

    APP_ENV=development
    DEBUG=true
    HOST=0.0.0.0
    PORT=8000

    DATABASE_URL=sqlite:///./data/cyberguard.db

    VIRUSTOTAL_API_KEY=

    MAX_URL_LENGTH=4096
    MAX_TEXT_LENGTH=50000
    MAX_UPLOAD_SIZE_MB=10

    MAX_REDIRECT_HOPS=10
    MAX_PAGE_REQUESTS=80

    REQUEST_TIMEOUT_SECONDS=12
    RDAP_TIMEOUT_SECONDS=8
    THREAT_INTEL_TIMEOUT_SECONDS=10

    CORS_ORIGINS=http://localhost:3000,http://localhost:5173

IMPORTANT:
    Never commit real API keys or secrets to Git.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Set

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ============================================================
# PROJECT PATHS
# ============================================================

# config.py is expected to live inside the backend package/directory.
CONFIG_DIR = Path(__file__).resolve().parent

PROJECT_ROOT = CONFIG_DIR.parent

DATA_DIR = PROJECT_ROOT / "data"
TEMP_DIR = DATA_DIR / "tmp"
LOG_DIR = PROJECT_ROOT / "logs"
UPLOAD_DIR = DATA_DIR / "uploads"

for directory in (
    DATA_DIR,
    TEMP_DIR,
    LOG_DIR,
    UPLOAD_DIR,
):
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )


# ============================================================
# ENVIRONMENT PARSING HELPERS
# ============================================================

def _parse_csv(value: str | List[str] | None) -> List[str]:
    """
    Convert comma-separated environment variables into a list.

    Example:

        CORS_ORIGINS=http://localhost:3000,http://localhost:5173

    becomes:

        [
            "http://localhost:3000",
            "http://localhost:5173",
        ]
    """

    if value is None:
        return []

    if isinstance(value, list):
        return [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]

    return [
        item.strip()
        for item in str(value).split(",")
        if item.strip()
    ]


# ============================================================
# SETTINGS
# ============================================================

class Settings(BaseSettings):
    """
    CYBERGUARD X application configuration.

    Values are loaded from environment variables and .env.
    """

    # ========================================================
    # APPLICATION
    # ========================================================

    app_name: str = Field(
        default="CYBERGUARD X",
        validation_alias="APP_NAME",
    )

    app_version: str = Field(
        default="3.0.0",
        validation_alias="APP_VERSION",
    )

    app_env: str = Field(
        default="development",
        validation_alias="APP_ENV",
    )

    debug: bool = Field(
        default=False,
        validation_alias="DEBUG",
    )

    host: str = Field(
        default="0.0.0.0",
        validation_alias="HOST",
    )

    port: int = Field(
        default=8000,
        validation_alias="PORT",
        ge=1,
        le=65535,
    )

    api_prefix: str = Field(
        default="",
        validation_alias="API_PREFIX",
    )

    # ========================================================
    # SECURITY
    # ========================================================

    secret_key: str = Field(
        default="",
        validation_alias="SECRET_KEY",
    )

    environment_secret_required: bool = Field(
        default=False,
        validation_alias="ENVIRONMENT_SECRET_REQUIRED",
    )

    # ========================================================
    # DATABASE
    # ========================================================

    database_url: str = Field(
        default="sqlite:///./data/cyberguard.db",
        validation_alias="DATABASE_URL",
    )

    database_echo: bool = Field(
        default=False,
        validation_alias="DATABASE_ECHO",
    )

    database_pool_size: int = Field(
        default=5,
        validation_alias="DATABASE_POOL_SIZE",
        ge=1,
        le=100,
    )

    database_max_overflow: int = Field(
        default=10,
        validation_alias="DATABASE_MAX_OVERFLOW",
        ge=0,
        le=100,
    )

    # ========================================================
    # CORS
    # ========================================================

    cors_origins: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
        ],
        validation_alias="CORS_ORIGINS",
    )

    cors_allow_credentials: bool = Field(
        default=True,
        validation_alias="CORS_ALLOW_CREDENTIALS",
    )

    cors_allow_methods: List[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        validation_alias="CORS_ALLOW_METHODS",
    )

    cors_allow_headers: List[str] = Field(
        default_factory=lambda: ["*"],
        validation_alias="CORS_ALLOW_HEADERS",
    )

    # ========================================================
    # URL SCANNING
    # ========================================================

    max_url_length: int = Field(
        default=4096,
        validation_alias="MAX_URL_LENGTH",
        ge=128,
        le=100000,
    )

    max_text_length: int = Field(
        default=50000,
        validation_alias="MAX_TEXT_LENGTH",
        ge=100,
        le=1000000,
    )

    max_redirect_hops: int = Field(
        default=10,
        validation_alias="MAX_REDIRECT_HOPS",
        ge=1,
        le=50,
    )

    max_page_requests: int = Field(
        default=80,
        validation_alias="MAX_PAGE_REQUESTS",
        ge=5,
        le=1000,
    )

    # ========================================================
    # NETWORK TIMEOUTS
    # ========================================================

    request_timeout_seconds: float = Field(
        default=12.0,
        validation_alias="REQUEST_TIMEOUT_SECONDS",
        gt=0,
        le=120,
    )

    rdap_timeout_seconds: float = Field(
        default=8.0,
        validation_alias="RDAP_TIMEOUT_SECONDS",
        gt=0,
        le=120,
    )

    threat_intel_timeout_seconds: float = Field(
        default=10.0,
        validation_alias="THREAT_INTEL_TIMEOUT_SECONDS",
        gt=0,
        le=120,
    )

    connect_timeout_seconds: float = Field(
        default=5.0,
        validation_alias="CONNECT_TIMEOUT_SECONDS",
        gt=0,
        le=60,
    )

    # ========================================================
    # SSRF / NETWORK SECURITY
    # ========================================================

    allow_private_networks: bool = Field(
        default=False,
        validation_alias="ALLOW_PRIVATE_NETWORKS",
    )

    allow_loopback: bool = Field(
        default=False,
        validation_alias="ALLOW_LOOPBACK",
    )

    allow_link_local: bool = Field(
        default=False,
        validation_alias="ALLOW_LINK_LOCAL",
    )

    allow_reserved_addresses: bool = Field(
        default=False,
        validation_alias="ALLOW_RESERVED_ADDRESSES",
    )

    block_ipv6: bool = Field(
        default=False,
        validation_alias="BLOCK_IPV6",
    )

    # ========================================================
    # UPLOAD SECURITY
    # ========================================================

    max_upload_size_mb: int = Field(
        default=10,
        validation_alias="MAX_UPLOAD_SIZE_MB",
        ge=1,
        le=100,
    )

    max_upload_size_bytes: int = Field(
        default=10 * 1024 * 1024,
        validation_alias="MAX_UPLOAD_SIZE_BYTES",
        ge=1024,
    )

    allowed_image_types: List[str] = Field(
        default_factory=lambda: [
            "image/png",
            "image/jpeg",
            "image/webp",
        ],
        validation_alias="ALLOWED_IMAGE_TYPES",
    )

    allowed_image_extensions: List[str] = Field(
        default_factory=lambda: [
            ".png",
            ".jpg",
            ".jpeg",
            ".webp",
        ],
        validation_alias="ALLOWED_IMAGE_EXTENSIONS",
    )

    # ========================================================
    # PLAYWRIGHT
    # ========================================================

    playwright_enabled: bool = Field(
        default=True,
        validation_alias="PLAYWRIGHT_ENABLED",
    )

    playwright_headless: bool = Field(
        default=True,
        validation_alias="PLAYWRIGHT_HEADLESS",
    )

    playwright_browser: str = Field(
        default="chromium",
        validation_alias="PLAYWRIGHT_BROWSER",
    )

    playwright_navigation_timeout_ms: int = Field(
        default=12000,
        validation_alias="PLAYWRIGHT_NAVIGATION_TIMEOUT_MS",
        ge=1000,
        le=120000,
    )

    playwright_wait_until: str = Field(
        default="domcontentloaded",
        validation_alias="PLAYWRIGHT_WAIT_UNTIL",
    )

    # ========================================================
    # THREAT INTELLIGENCE
    # ========================================================

    virustotal_api_key: str = Field(
        default="",
        validation_alias="VIRUSTOTAL_API_KEY",
    )

    virustotal_enabled: bool = Field(
        default=True,
        validation_alias="VIRUSTOTAL_ENABLED",
    )

    virustotal_base_url: str = Field(
        default="https://www.virustotal.com/api/v3",
        validation_alias="VIRUSTOTAL_BASE_URL",
    )

    virustotal_timeout_seconds: float = Field(
        default=15.0,
        validation_alias="VIRUSTOTAL_TIMEOUT_SECONDS",
        gt=0,
        le=120,
    )

    virustotal_submit_unknown_urls: bool = Field(
        default=False,
        validation_alias="VIRUSTOTAL_SUBMIT_UNKNOWN_URLS",
    )

    # ========================================================
    # RDAP
    # ========================================================

    rdap_enabled: bool = Field(
        default=True,
        validation_alias="RDAP_ENABLED",
    )

    rdap_base_url: str = Field(
        default="https://rdap.org/domain",
        validation_alias="RDAP_BASE_URL",
    )

    # ========================================================
    # LOGGING
    # ========================================================

    log_level: str = Field(
        default="INFO",
        validation_alias="LOG_LEVEL",
    )

    log_file: str = Field(
        default=str(LOG_DIR / "cyberguard.log"),
        validation_alias="LOG_FILE",
    )

    log_json: bool = Field(
        default=False,
        validation_alias="LOG_JSON",
    )

    # ========================================================
    # RATE LIMITING
    # ========================================================

    rate_limit_enabled: bool = Field(
        default=True,
        validation_alias="RATE_LIMIT_ENABLED",
    )

    rate_limit_requests: int = Field(
        default=60,
        validation_alias="RATE_LIMIT_REQUESTS",
        ge=1,
        le=100000,
    )

    rate_limit_window_seconds: int = Field(
        default=60,
        validation_alias="RATE_LIMIT_WINDOW_SECONDS",
        ge=1,
        le=3600,
    )

    # ========================================================
    # SCAN BEHAVIOUR
    # ========================================================

    scan_concurrency: int = Field(
        default=4,
        validation_alias="SCAN_CONCURRENCY",
        ge=1,
        le=100,
    )

    enable_url_scanning: bool = Field(
        default=True,
        validation_alias="ENABLE_URL_SCANNING",
    )

    enable_text_scanning: bool = Field(
        default=True,
        validation_alias="ENABLE_TEXT_SCANNING",
    )

    enable_qr_scanning: bool = Field(
        default=True,
        validation_alias="ENABLE_QR_SCANNING",
    )

    enable_threat_intelligence: bool = Field(
        default=True,
        validation_alias="ENABLE_THREAT_INTELLIGENCE",
    )

    enable_domain_age_lookup: bool = Field(
        default=True,
        validation_alias="ENABLE_DOMAIN_AGE_LOOKUP",
    )

    enable_redirect_analysis: bool = Field(
        default=True,
        validation_alias="ENABLE_REDIRECT_ANALYSIS",
    )

    # ========================================================
    # API DOCUMENTATION
    # ========================================================

    docs_enabled: bool = Field(
        default=True,
        validation_alias="DOCS_ENABLED",
    )

    redoc_enabled: bool = Field(
        default=True,
        validation_alias="REDOC_ENABLED",
    )

    # ========================================================
    # PYDANTIC SETTINGS CONFIGURATION
    # ========================================================

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ========================================================
    # VALIDATORS
    # ========================================================

    @field_validator("app_env")
    @classmethod
    def validate_environment(
        cls,
        value: str,
    ) -> str:
        value = str(value).strip().lower()

        allowed = {
            "development",
            "testing",
            "staging",
            "production",
        }

        if value not in allowed:
            raise ValueError(
                "APP_ENV must be one of: "
                "development, testing, staging, production."
            )

        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(
        cls,
        value: str,
    ) -> str:
        value = str(value).strip().upper()

        allowed = {
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
            "CRITICAL",
        }

        if value not in allowed:
            raise ValueError(
                "LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR or CRITICAL."
            )

        return value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def validate_cors_origins(
        cls,
        value,
    ) -> List[str]:
        return _parse_csv(value)

    @field_validator("cors_allow_methods", mode="before")
    @classmethod
    def validate_cors_methods(
        cls,
        value,
    ) -> List[str]:
        return _parse_csv(value)

    @field_validator("cors_allow_headers", mode="before")
    @classmethod
    def validate_cors_headers(
        cls,
        value,
    ) -> List[str]:
        return _parse_csv(value)

    @field_validator("allowed_image_types", mode="before")
    @classmethod
    def validate_image_types(
        cls,
        value,
    ) -> List[str]:
        return _parse_csv(value)

    @field_validator("allowed_image_extensions", mode="before")
    @classmethod
    def validate_image_extensions(
        cls,
        value,
    ) -> List[str]:
        values = _parse_csv(value)

        return [
            item.lower()
            if item.startswith(".")
            else f".{item.lower()}"
            for item in values
        ]

    @field_validator("playwright_browser")
    @classmethod
    def validate_browser(
        cls,
        value: str,
    ) -> str:
        value = str(value).strip().lower()

        allowed = {
            "chromium",
            "firefox",
            "webkit",
        }

        if value not in allowed:
            raise ValueError(
                "PLAYWRIGHT_BROWSER must be chromium, firefox or webkit."
            )

        return value

    @field_validator("playwright_wait_until")
    @classmethod
    def validate_wait_until(
        cls,
        value: str,
    ) -> str:
        value = str(value).strip().lower()

        allowed = {
            "commit",
            "domcontentloaded",
            "load",
            "networkidle",
        }

        if value not in allowed:
            raise ValueError(
                "PLAYWRIGHT_WAIT_UNTIL must be commit, "
                "domcontentloaded, load or networkidle."
            )

        return value

    # ========================================================
    # POST-VALIDATION
    # ========================================================

    def model_post_init(
        self,
        __context,
    ) -> None:
        """
        Apply derived configuration after Pydantic validation.
        """

        calculated_bytes = (
            self.max_upload_size_mb
            * 1024
            * 1024
        )

        # Keep MB and byte configuration consistent.
        object.__setattr__(
            self,
            "max_upload_size_bytes",
            calculated_bytes,
        )

        # Production should never accidentally run unrestricted CORS.
        if self.app_env == "production":
            if "*" in self.cors_origins:
                raise ValueError(
                    "Wildcard CORS origin is not allowed in production."
                )

            if self.debug:
                raise ValueError(
                    "DEBUG must be disabled in production."
                )

            if self.environment_secret_required and not self.secret_key:
                raise ValueError(
                    "SECRET_KEY must be configured in production."
                )

    # ========================================================
    # SECURITY HELPERS
    # ========================================================

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    @property
    def upload_size_bytes(self) -> int:
        return (
            self.max_upload_size_mb
            * 1024
            * 1024
        )

    @property
    def cors_origins_set(self) -> Set[str]:
        return set(self.cors_origins)

    # ========================================================
    # SAFE PUBLIC CONFIG
    # ========================================================

    def public_dict(self) -> dict:
        """
        Return configuration safe to expose through diagnostics.

        Secrets/API keys are intentionally excluded.
        """

        return {
            "app_name": self.app_name,
            "app_version": self.app_version,
            "app_env": self.app_env,
            "debug": self.debug,
            "host": self.host,
            "port": self.port,

            "database": {
                "configured": bool(self.database_url),
            },

            "scanning": {
                "url": self.enable_url_scanning,
                "text": self.enable_text_scanning,
                "qr": self.enable_qr_scanning,
                "threat_intelligence": self.enable_threat_intelligence,
                "domain_age": self.enable_domain_age_lookup,
                "redirect_analysis": self.enable_redirect_analysis,
            },

            "security": {
                "ssrf_private_networks_allowed": self.allow_private_networks,
                "ssrf_loopback_allowed": self.allow_loopback,
                "ssrf_link_local_allowed": self.allow_link_local,
                "ssrf_reserved_allowed": self.allow_reserved_addresses,
                "block_ipv6": self.block_ipv6,
            },

            "limits": {
                "max_url_length": self.max_url_length,
                "max_text_length": self.max_text_length,
                "max_redirect_hops": self.max_redirect_hops,
                "max_page_requests": self.max_page_requests,
                "max_upload_size_mb": self.max_upload_size_mb,
            },

            "playwright": {
                "enabled": self.playwright_enabled,
                "headless": self.playwright_headless,
                "browser": self.playwright_browser,
            },

            "threat_intelligence": {
                "enabled": self.enable_threat_intelligence,
                "virustotal_enabled": self.virustotal_enabled,
                "virustotal_configured": bool(
                    self.virustotal_api_key
                ),
            },

            "rdap": {
                "enabled": self.rdap_enabled,
            },

            "rate_limit": {
                "enabled": self.rate_limit_enabled,
                "requests": self.rate_limit_requests,
                "window_seconds": self.rate_limit_window_seconds,
            },

            "logging": {
                "level": self.log_level,
                "json": self.log_json,
            },
        }


# ============================================================
# SETTINGS SINGLETON
# ============================================================

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the cached application settings.

    Using a cached singleton prevents every module from repeatedly
    parsing the .env file.
    """

    return Settings()


settings = get_settings()


# ============================================================
# COMPATIBILITY CONSTANTS
# ============================================================

# These aliases make migration from the old app_upgraded-5.py easier.

MAX_REDIRECT_HOPS = settings.max_redirect_hops
MAX_PAGE_REQUESTS = settings.max_page_requests
MAX_URL_LENGTH = settings.max_url_length
MAX_TEXT_LENGTH = settings.max_text_length

REQUEST_TIMEOUT_SECONDS = settings.request_timeout_seconds
RDAP_TIMEOUT_SECONDS = settings.rdap_timeout_seconds
THREAT_INTEL_TIMEOUT_SECONDS = settings.threat_intel_timeout_seconds

MAX_UPLOAD_SIZE_MB = settings.max_upload_size_mb
MAX_UPLOAD_SIZE_BYTES = settings.upload_size_bytes

VIRUSTOTAL_API_KEY = settings.virustotal_api_key
VIRUSTOTAL_ENABLED = settings.virustotal_enabled

RDAP_ENABLED = settings.rdap_enabled
RDAP_BASE_URL = settings.rdap_base_url

PLAYWRIGHT_ENABLED = settings.playwright_enabled
PLAYWRIGHT_HEADLESS = settings.playwright_headless
PLAYWRIGHT_BROWSER = settings.playwright_browser

DATA_DIR = DATA_DIR
TEMP_DIR = TEMP_DIR
LOG_DIR = LOG_DIR
UPLOAD_DIR = UPLOAD_DIR


# ============================================================
# LOCAL SELF-TEST
# ============================================================

if __name__ == "__main__":
    print()
    print("=" * 60)
    print("CYBERGUARD X — Configuration Test")
    print("=" * 60)

    print(f"Application : {settings.app_name}")
    print(f"Version     : {settings.app_version}")
    print(f"Environment : {settings.app_env}")
    print(f"Debug       : {settings.debug}")
    print(f"Host        : {settings.host}")
    print(f"Port        : {settings.port}")

    print()
    print("Scanning")
    print("-" * 60)
    print(f"URL scanning       : {settings.enable_url_scanning}")
    print(f"Text scanning      : {settings.enable_text_scanning}")
    print(f"QR scanning        : {settings.enable_qr_scanning}")
    print(
        "Threat intelligence: "
        f"{settings.enable_threat_intelligence}"
    )

    print()
    print("Security")
    print("-" * 60)
    print(
        "Private networks  : "
        f"{settings.allow_private_networks}"
    )
    print(
        "Loopback          : "
        f"{settings.allow_loopback}"
    )
    print(
        "Link-local        : "
        f"{settings.allow_link_local}"
    )
    print(
        "IPv6 blocked      : "
        f"{settings.block_ipv6}"
    )

    print()
    print("Limits")
    print("-" * 60)
    print(f"Max URL           : {settings.max_url_length}")
    print(f"Max text          : {settings.max_text_length}")
    print(f"Max redirects     : {settings.max_redirect_hops}")
    print(f"Max page requests : {settings.max_page_requests}")
    print(f"Max upload        : {settings.max_upload_size_mb} MB")

    print()
    print("Threat Intelligence")
    print("-" * 60)
    print(
        "VirusTotal enabled: "
        f"{settings.virustotal_enabled}"
    )
    print(
        "VirusTotal key    : "
        f"{'configured' if settings.virustotal_api_key else 'not configured'}"
    )

    print()
    print("Public configuration:")
    print(settings.public_dict())

    print()
    print("Configuration loaded successfully.")
    print("=" * 60)
