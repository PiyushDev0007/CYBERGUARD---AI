"""
CYBERGUARD X — Security & Request Protection Layer

Responsibilities
----------------
- Secure environment/configuration helpers
- URL validation
- SSRF protection
- DNS/IP safety checks
- DNS rebinding protection
- Upload validation
- Filename sanitization
- Request-size protection
- Basic in-memory rate limiting
- Security headers
- Trusted-host configuration
- External-request safety helpers
- API-key validation
- Safe error/message helpers

This module is intentionally independent from FastAPI route handlers
so it can be reused by:

    app_upgraded-5.py
    scan_service.py
    threat_intelligence.py
    database.py
    future API modules

IMPORTANT
---------
SSRF protection is defense-in-depth. Network infrastructure should
also enforce outbound firewall/egress restrictions in production.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse, urlunparse

from fastapi import HTTPException, Request, UploadFile


# ============================================================
# ENVIRONMENT HELPERS
# ============================================================

def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
        "enabled",
    }


def _env_int(name: str, default: int, minimum: int | None = None) -> int:
    value = os.getenv(name)

    if value is None:
        result = default
    else:
        try:
            result = int(value)
        except (TypeError, ValueError):
            result = default

    if minimum is not None:
        result = max(result, minimum)

    return result


def _env_float(
    name: str,
    default: float,
    minimum: float | None = None,
) -> float:
    value = os.getenv(name)

    if value is None:
        result = default
    else:
        try:
            result = float(value)
        except (TypeError, ValueError):
            result = default

    if minimum is not None:
        result = max(result, minimum)

    return result


def _env_list(
    name: str,
    default: Iterable[str] = (),
) -> list[str]:
    value = os.getenv(name)

    if value is None:
        return [str(item).strip() for item in default if str(item).strip()]

    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


# ============================================================
# SECURITY CONFIGURATION
# ============================================================

@dataclass(frozen=True)
class SecurityConfig:
    """
    Central security configuration.

    Values can be overridden with environment variables.
    """

    max_url_length: int = _env_int(
        "CYBERGUARD_MAX_URL_LENGTH",
        4096,
        256,
    )

    max_text_length: int = _env_int(
        "CYBERGUARD_MAX_TEXT_LENGTH",
        50000,
        1000,
    )

    max_upload_size: int = _env_int(
        "CYBERGUARD_MAX_UPLOAD_SIZE",
        10 * 1024 * 1024,
        1024,
    )

    max_redirects: int = _env_int(
        "CYBERGUARD_MAX_REDIRECTS",
        10,
        1,
    )

    external_request_timeout: float = _env_float(
        "CYBERGUARD_EXTERNAL_TIMEOUT",
        8.0,
        1.0,
    )

    rate_limit_requests: int = _env_int(
        "CYBERGUARD_RATE_LIMIT_REQUESTS",
        30,
        1,
    )

    rate_limit_window_seconds: int = _env_int(
        "CYBERGUARD_RATE_LIMIT_WINDOW",
        60,
        1,
    )

    max_page_requests: int = _env_int(
        "CYBERGUARD_MAX_PAGE_REQUESTS",
        80,
        1,
    )

    allow_private_networks: bool = _env_bool(
        "CYBERGUARD_ALLOW_PRIVATE_NETWORKS",
        False,
    )

    enforce_https: bool = _env_bool(
        "CYBERGUARD_ENFORCE_HTTPS",
        False,
    )

    trust_proxy_headers: bool = _env_bool(
        "CYBERGUARD_TRUST_PROXY_HEADERS",
        False,
    )

    allowed_hosts: tuple[str, ...] = tuple(
        _env_list(
            "CYBERGUARD_ALLOWED_HOSTS",
            ["*"],
        )
    )

    allowed_upload_types: tuple[str, ...] = (
        "image/png",
        "image/jpeg",
        "image/webp",
    )


SECURITY_CONFIG = SecurityConfig()


# ============================================================
# COMMON SECURITY CONSTANTS
# ============================================================

BLOCKED_SCHEMES = {
    "file",
    "ftp",
    "ftps",
    "gopher",
    "data",
    "javascript",
    "vbscript",
    "about",
    "blob",
}

ALLOWED_URL_SCHEMES = {
    "http",
    "https",
}

PRIVATE_NETWORK_NAMES = {
    "localhost",
    "localhost.localdomain",
}

DANGEROUS_FILENAME_CHARS = re.compile(
    r"[^A-Za-z0-9._-]+"
)

CONTROL_CHARS = re.compile(
    r"[\x00-\x1f\x7f]"
)

MULTIPLE_SLASHES = re.compile(
    r"/{2,}"
)


# ============================================================
# BASIC NORMALIZATION
# ============================================================

def normalize_text(value: str, max_length: int | None = None) -> str:
    """
    Normalize ordinary text safely.

    Does not perform HTML escaping because security analysis may need
    the original textual content.
    """

    if value is None:
        raise ValueError("Text cannot be None.")

    value = str(value).replace("\x00", "").strip()

    limit = max_length or SECURITY_CONFIG.max_text_length

    if len(value) > limit:
        raise ValueError(
            f"Text exceeds maximum length of {limit} characters."
        )

    return value


def sanitize_filename(filename: str | None) -> str:
    """
    Convert an uploaded filename into a safe local filename.

    The returned value must still be treated as untrusted metadata.
    """

    if not filename:
        return "upload"

    filename = os.path.basename(str(filename))

    filename = filename.replace("\\", "_")
    filename = CONTROL_CHARS.sub("", filename)
    filename = DANGEROUS_FILENAME_CHARS.sub("_", filename)

    filename = filename.strip(" .")

    if not filename:
        filename = "upload"

    # Prevent hidden/path-like special names.
    if filename in {".", ".."}:
        filename = "upload"

    return filename[:100]


# ============================================================
# URL PARSING
# ============================================================

def parse_http_url(
    target_url: str,
):
    """
    Parse and validate the structural form of an HTTP/HTTPS URL.
    """

    if target_url is None:
        raise ValueError("URL cannot be empty.")

    target_url = str(target_url).strip()

    if not target_url:
        raise ValueError("URL cannot be empty.")

    if len(target_url) > SECURITY_CONFIG.max_url_length:
        raise ValueError(
            "URL exceeds the maximum permitted length."
        )

    parsed = urlparse(target_url)

    scheme = parsed.scheme.lower()

    if scheme not in ALLOWED_URL_SCHEMES:
        raise ValueError(
            "Only HTTP and HTTPS URLs are supported."
        )

    if not parsed.hostname:
        raise ValueError(
            "URL must contain a valid hostname."
        )

    if CONTROL_CHARS.search(target_url):
        raise ValueError(
            "URL contains invalid control characters."
        )

    if parsed.fragment:
        # Fragments are not sent to the server and can be removed
        # for consistent security analysis.
        parsed = parsed._replace(fragment="")

    return parsed


def normalize_http_url(target_url: str) -> str:
    """
    Return a normalized HTTP/HTTPS URL.
    """

    parsed = parse_http_url(target_url)

    hostname = parsed.hostname or ""

    # IDN hostnames should be represented in ASCII form when possible.
    try:
        hostname_ascii = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        hostname_ascii = hostname

    hostname_ascii = hostname_ascii.lower().rstrip(".")

    if not hostname_ascii:
        raise ValueError("Invalid hostname.")

    # Preserve explicit port.
    netloc = hostname_ascii

    if parsed.port is not None:
        netloc = f"{hostname_ascii}:{parsed.port}"

    if parsed.username is not None or parsed.password is not None:
        # Do not reconstruct userinfo into normalized URLs.
        raise ValueError(
            "URLs containing username/password components are not allowed."
        )

    normalized = urlunparse(
        (
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            "",
        )
    )

    return normalized


# ============================================================
# HOSTNAME / IP HELPERS
# ============================================================

def get_hostname(target_url: str) -> str:
    try:
        return (
            urlparse(target_url)
            .hostname
            or ""
        ).lower().strip().rstrip(".")
    except Exception:
        return ""


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def classify_ip(address: str) -> str:
    """
    Return a simple security classification for an IP.
    """

    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "invalid"

    if ip.is_loopback:
        return "loopback"

    if ip.is_private:
        return "private"

    if ip.is_link_local:
        return "link_local"

    if ip.is_reserved:
        return "reserved"

    if ip.is_multicast:
        return "multicast"

    if ip.is_unspecified:
        return "unspecified"

    if getattr(ip, "is_site_local", False):
        return "site_local"

    return "public"


def is_public_ip(address: str) -> bool:
    """
    Return True only when the IP is suitable for public outbound
    scanning.

    This intentionally rejects private, loopback, reserved,
    link-local, multicast and unspecified addresses.
    """

    return classify_ip(address) == "public"


def resolve_hostname(hostname: str) -> list[str]:
    """
    Resolve both IPv4 and IPv6 addresses.

    Returns unique addresses.
    """

    hostname = str(hostname or "").strip().rstrip(".")

    if not hostname:
        return []

    if is_ip_address(hostname):
        return [hostname]

    addresses: set[str] = set()

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        for result in results:
            sockaddr = result[4]

            if not sockaddr:
                continue

            address = sockaddr[0]

            try:
                ipaddress.ip_address(address)
                addresses.add(address)
            except ValueError:
                continue

    except (
        socket.gaierror,
        OSError,
    ):
        return []

    return sorted(addresses)


# ============================================================
# SSRF PROTECTION
# ============================================================

def validate_hostname(hostname: str) -> None:
    """
    Validate hostname syntax and reject obvious dangerous forms.
    """

    hostname = str(hostname or "").strip().rstrip(".")

    if not hostname:
        raise HTTPException(
            status_code=400,
            detail="URL hostname is missing.",
        )

    if len(hostname) > 253:
        raise HTTPException(
            status_code=400,
            detail="URL hostname is too long.",
        )

    if hostname.lower() in PRIVATE_NETWORK_NAMES:
        raise HTTPException(
            status_code=400,
            detail="Localhost targets are not permitted.",
        )

    if hostname.endswith(".local"):
        raise HTTPException(
            status_code=400,
            detail="Local network hostnames are not permitted.",
        )

    if any(
        char.isspace()
        for char in hostname
    ):
        raise HTTPException(
            status_code=400,
            detail="Hostname contains whitespace.",
        )


def validate_url_syntax(target_url: str) -> str:
    """
    Validate URL structure without DNS resolution.
    """

    try:
        normalized = normalize_http_url(target_url)
        parsed = urlparse(normalized)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    validate_hostname(parsed.hostname or "")

    try:
        port = parsed.port

        if port is not None and not (
            1 <= port <= 65535
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid URL port.",
            )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid URL port.",
        ) from exc

    if (
        SECURITY_CONFIG.enforce_https
        and parsed.scheme.lower() != "https"
    ):
        raise HTTPException(
            status_code=400,
            detail="HTTPS is required by server security policy.",
        )

    return normalized


def validate_public_target(
    target_url: str,
    *,
    allow_private: bool | None = None,
) -> str:
    """
    Validate a target against SSRF risks.

    The hostname is resolved immediately and every resolved IP must
    satisfy the public-network policy.

    This should be performed immediately before an outbound request.
    """

    normalized = validate_url_syntax(target_url)

    parsed = urlparse(normalized)
    hostname = parsed.hostname or ""

    allow_private_networks = (
        SECURITY_CONFIG.allow_private_networks
        if allow_private is None
        else bool(allow_private)
    )

    if allow_private_networks:
        return normalized

    # Direct IP target.
    if is_ip_address(hostname):
        if not is_public_ip(hostname):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Security Exception: target IP belongs to a "
                    "restricted or non-public network."
                ),
            )

        return normalized

    addresses = resolve_hostname(hostname)

    if not addresses:
        raise HTTPException(
            status_code=400,
            detail=(
                "Security Exception: hostname could not be resolved."
            ),
        )

    restricted = [
        address
        for address in addresses
        if not is_public_ip(address)
    ]

    if restricted:
        raise HTTPException(
            status_code=400,
            detail=(
                "Security Exception: hostname resolves to a "
                "restricted or non-public network address."
            ),
        )

    return normalized


def is_safe_target(target_url: str) -> bool:
    """
    Boolean SSRF-safe check.

    Intended for internal guard logic.
    """

    try:
        validate_public_target(target_url)
        return True
    except (
        HTTPException,
        ValueError,
    ):
        return False


def validate_redirect_target(
    target_url: str,
    previous_url: str | None = None,
) -> str:
    """
    Validate a redirect destination before following it.
    """

    normalized = validate_public_target(target_url)

    if previous_url:
        previous_host = get_hostname(previous_url)
        current_host = get_hostname(normalized)

        # Host changes are allowed because legitimate redirectors exist,
        # but the new host must independently pass SSRF validation.
        if previous_host != current_host:
            pass

    return normalized


# ============================================================
# DNS REBINDING DEFENSE
# ============================================================

@dataclass(frozen=True)
class ResolvedTarget:
    hostname: str
    addresses: tuple[str, ...]


def resolve_and_lock_target(
    target_url: str,
) -> ResolvedTarget:
    """
    Resolve a hostname and retain the exact approved IP set.

    Callers performing high-security outbound connections should use
    this information with an HTTP client/network layer that can bind
    the connection to the validated address.

    Merely resolving once does not completely prevent DNS rebinding.
    """

    normalized = validate_public_target(target_url)

    hostname = get_hostname(normalized)

    addresses = tuple(
        resolve_hostname(hostname)
    )

    if not addresses:
        raise HTTPException(
            status_code=400,
            detail="Target hostname has no valid DNS addresses.",
        )

    if not all(
        is_public_ip(address)
        for address in addresses
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Security Exception: DNS resolution returned "
                "a restricted address."
            ),
        )

    return ResolvedTarget(
        hostname=hostname,
        addresses=addresses,
    )


# ============================================================
# UPLOAD SECURITY
# ============================================================

def validate_upload_metadata(
    file: UploadFile,
) -> None:
    """
    Validate basic upload metadata.

    Content type alone is NOT sufficient to trust a file.
    Callers should also inspect the decoded file contents.
    """

    if file is None:
        raise HTTPException(
            status_code=400,
            detail="No upload was provided.",
        )

    filename = sanitize_filename(
        file.filename
    )

    if not filename:
        raise HTTPException(
            status_code=400,
            detail="Invalid upload filename.",
        )

    content_type = (
        file.content_type
        or ""
    ).lower().strip()

    if content_type not in SECURITY_CONFIG.allowed_upload_types:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported file type. Allowed types: "
                + ", ".join(
                    SECURITY_CONFIG.allowed_upload_types
                )
            ),
        )


async def read_upload_safely(
    file: UploadFile,
    *,
    max_size: int | None = None,
) -> bytes:
    """
    Read an uploaded file while enforcing a hard byte limit.

    The entire file is returned only after validation succeeds.
    """

    validate_upload_metadata(file)

    limit = (
        max_size
        if max_size is not None
        else SECURITY_CONFIG.max_upload_size
    )

    if limit <= 0:
        raise HTTPException(
            status_code=500,
            detail="Invalid upload-size security configuration.",
        )

    chunks: list[bytes] = []
    total = 0
    chunk_size = 1024 * 1024

    while True:
        chunk = await file.read(chunk_size)

        if not chunk:
            break

        total += len(chunk)

        if total > limit:
            raise HTTPException(
                status_code=413,
                detail=(
                    f"Uploaded file exceeds the maximum size "
                    f"of {limit} bytes."
                ),
            )

        chunks.append(chunk)

    return b"".join(chunks)


# ============================================================
# IMAGE SIGNATURE VALIDATION
# ============================================================

IMAGE_SIGNATURES = {
    "image/png": [
        b"\x89PNG\r\n\x1a\n",
    ],
    "image/jpeg": [
        b"\xff\xd8\xff",
    ],
    "image/webp": [
        b"RIFF",
    ],
}


def validate_image_signature(
    content: bytes,
    content_type: str,
) -> bool:
    """
    Validate common magic-byte signatures.

    WEBP additionally requires RIFF/WEBP structure.
    """

    content_type = (
        str(content_type or "")
        .lower()
        .strip()
    )

    signatures = IMAGE_SIGNATURES.get(
        content_type
    )

    if not signatures:
        return False

    if not any(
        content.startswith(signature)
        for signature in signatures
    ):
        return False

    if content_type == "image/webp":
        return (
            len(content) >= 12
            and content[8:12] == b"WEBP"
        )

    return True


def validate_image_upload_bytes(
    content: bytes,
    content_type: str,
) -> None:
    """
    Validate upload size and magic bytes.
    """

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Uploaded image is empty.",
        )

    if len(content) > SECURITY_CONFIG.max_upload_size:
        raise HTTPException(
            status_code=413,
            detail="Uploaded image exceeds the permitted size.",
        )

    if not validate_image_signature(
        content,
        content_type,
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Uploaded image content does not match the "
                "declared image type."
            ),
        )


# ============================================================
# SAFE TEMPORARY FILE PATH
# ============================================================

def build_safe_temp_path(
    directory: str | Path,
    filename: str | None,
    prefix: str = "cyberguard_",
) -> Path:
    """
    Build a safe temporary file path.

    The generated filename never trusts user-controlled path
    components.
    """

    base = Path(directory).resolve()
    base.mkdir(
        parents=True,
        exist_ok=True,
    )

    safe_name = sanitize_filename(filename)

    random_id = hashlib.sha256(
        f"{time.time_ns()}:{safe_name}".encode()
    ).hexdigest()[:24]

    path = base / (
        f"{prefix}{random_id}_{safe_name}"
    )

    resolved = path.resolve()

    if base not in resolved.parents:
        raise HTTPException(
            status_code=500,
            detail="Unsafe temporary path generated.",
        )

    return resolved


# ============================================================
# API KEY HELPERS
# ============================================================

def get_api_key(
    environment_variable: str,
) -> str | None:
    """
    Read an API key from an environment variable.

    Empty values are treated as missing.
    """

    value = os.getenv(
        environment_variable
    )

    if value is None:
        return None

    value = value.strip()

    return value or None


def require_api_key(
    environment_variable: str,
) -> str:
    """
    Require an API key from the environment.

    Never hard-code production API keys in source code.
    """

    key = get_api_key(
        environment_variable
    )

    if not key:
        raise RuntimeError(
            f"Required API key is not configured: "
            f"{environment_variable}"
        )

    return key


def mask_secret(
    value: str | None,
    visible_prefix: int = 4,
) -> str:
    """
    Safely display a secret for logs/debug output.
    """

    if not value:
        return "[not configured]"

    value = str(value)

    if len(value) <= visible_prefix:
        return "*" * len(value)

    return (
        value[:visible_prefix]
        + "..."
        + "*" * min(
            8,
            max(4, len(value) - visible_prefix),
        )
    )


# ============================================================
# EXTERNAL REQUEST SAFETY
# ============================================================

def external_request_headers(
    *,
    user_agent: str = "CyberGuard-X-SecurityScanner/1.0",
) -> dict[str, str]:
    """
    Return conservative headers for external security lookups.
    """

    return {
        "User-Agent": user_agent[:200],
        "Accept": "application/json,text/plain,*/*",
        "Connection": "close",
    }


def external_request_timeout(
    override: float | None = None,
) -> float:
    """
    Return a safe external-request timeout.
    """

    timeout = (
        SECURITY_CONFIG.external_request_timeout
        if override is None
        else float(override)
    )

    return max(
        1.0,
        min(timeout, 60.0),
    )


# ============================================================
# RATE LIMITING
# ============================================================

class InMemoryRateLimiter:
    """
    Simple process-local sliding-window rate limiter.

    Suitable for:
        - development
        - single-process deployments
        - basic abuse protection

    For multi-worker production deployments, replace this with
    Redis or another shared store.
    """

    def __init__(
        self,
        max_requests: int | None = None,
        window_seconds: int | None = None,
    ) -> None:

        self.max_requests = (
            max_requests
            if max_requests is not None
            else SECURITY_CONFIG.rate_limit_requests
        )

        self.window_seconds = (
            window_seconds
            if window_seconds is not None
            else SECURITY_CONFIG.rate_limit_window_seconds
        )

        self._requests: dict[str, deque[float]] = defaultdict(
            deque
        )

        self._lock = threading.Lock()

    def allow(
        self,
        key: str,
    ) -> tuple[bool, int]:
        """
        Return:

            (allowed, retry_after_seconds)
        """

        now = time.monotonic()

        with self._lock:
            bucket = self._requests[key]

            cutoff = (
                now - self.window_seconds
            )

            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self.max_requests:
                retry_after = max(
                    1,
                    int(
                        bucket[0]
                        + self.window_seconds
                        - now
                    ),
                )

                return False, retry_after

            bucket.append(now)

            return True, 0

    def cleanup(self) -> None:
        """
        Remove expired buckets.
        """

        now = time.monotonic()

        with self._lock:
            empty_keys = []

            for key, bucket in self._requests.items():

                cutoff = (
                    now - self.window_seconds
                )

                while bucket and bucket[0] <= cutoff:
                    bucket.popleft()

                if not bucket:
                    empty_keys.append(key)

            for key in empty_keys:
                self._requests.pop(
                    key,
                    None,
                )


rate_limiter = InMemoryRateLimiter()


def get_client_identifier(
    request: Request,
) -> str:
    """
    Get a client identifier.

    Proxy headers are trusted only when explicitly enabled.
    """

    if SECURITY_CONFIG.trust_proxy_headers:

        forwarded = request.headers.get(
            "x-forwarded-for"
        )

        if forwarded:
            first = forwarded.split(",")[0].strip()

            if first:
                return first[:100]

        real_ip = request.headers.get(
            "x-real-ip"
        )

        if real_ip:
            return real_ip[:100]

    client = request.client

    if client and client.host:
        return client.host[:100]

    return "unknown"


async def enforce_rate_limit(
    request: Request,
    limiter: InMemoryRateLimiter | None = None,
) -> None:
    """
    FastAPI dependency/helper for rate limiting.
    """

    limiter = limiter or rate_limiter

    identifier = get_client_identifier(
        request
    )

    allowed, retry_after = limiter.allow(
        identifier
    )

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=(
                "Rate limit exceeded. Please retry later."
            ),
            headers={
                "Retry-After": str(retry_after),
            },
        )


# ============================================================
# REQUEST BODY SIZE
# ============================================================

def get_content_length(
    request: Request,
) -> int | None:
    value = request.headers.get(
        "content-length"
    )

    if not value:
        return None

    try:
        return int(value)
    except ValueError:
        return None


def enforce_content_length(
    request: Request,
    maximum_bytes: int,
) -> None:
    """
    Reject obviously oversized requests before application parsing.

    This is an early check; upload readers must still enforce their
    own hard limits.
    """

    if maximum_bytes <= 0:
        raise ValueError(
            "maximum_bytes must be positive."
        )

    content_length = get_content_length(
        request
    )

    if (
        content_length is not None
        and content_length > maximum_bytes
    ):
        raise HTTPException(
            status_code=413,
            detail="Request body is too large.",
        )


# ============================================================
# SECURITY HEADERS
# ============================================================

def security_headers() -> dict[str, str]:
    """
    HTTP response security headers.
    """

    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": (
            "camera=(), microphone=(), geolocation=()"
        ),
        "Cache-Control": (
            "no-store, no-cache, must-revalidate"
        ),
        "Pragma": "no-cache",
    }


async def security_headers_middleware(
    request: Request,
    call_next,
):
    """
    FastAPI/Starlette middleware helper.

    Usage:

        app.middleware("http")(
            security_headers_middleware
        )
    """

    response = await call_next(request)

    for key, value in security_headers().items():
        response.headers[key] = value

    return response


# ============================================================
# TRUSTED HOST VALIDATION
# ============================================================

def validate_host(
    host: str | None,
) -> bool:
    """
    Validate Host against configured allowed hosts.

    '*' disables host restriction.
    """

    if not host:
        return False

    host = host.split(":")[0].lower().strip()

    allowed_hosts = SECURITY_CONFIG.allowed_hosts

    if "*" in allowed_hosts:
        return True

    for allowed in allowed_hosts:

        allowed = allowed.lower().strip()

        if allowed == host:
            return True

        if allowed.startswith("*."):
            suffix = allowed[1:]

            if host.endswith(suffix):
                return True

    return False


# ============================================================
# SECURITY EVENT MODEL
# ============================================================

@dataclass(frozen=True)
class SecurityEvent:
    event_type: str
    message: str
    severity: str = "INFO"


def make_security_event(
    event_type: str,
    message: str,
    severity: str = "INFO",
) -> SecurityEvent:
    """
    Create a structured security event.

    Logging infrastructure can serialize this object later.
    """

    allowed_severities = {
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    normalized = str(
        severity
    ).upper()

    if normalized not in allowed_severities:
        normalized = "INFO"

    return SecurityEvent(
        event_type=str(
            event_type
        )[:100],
        message=str(
            message
        )[:1000],
        severity=normalized,
    )


# ============================================================
# SAFE EXCEPTION MESSAGES
# ============================================================

def safe_http_error(
    status_code: int,
    public_message: str,
) -> HTTPException:
    """
    Create an HTTP exception without exposing internal details.
    """

    return HTTPException(
        status_code=status_code,
        detail=str(public_message)[:500],
    )


# ============================================================
# SECURITY VALIDATION HELPERS
# ============================================================

def validate_scan_text(
    text: str,
) -> str:
    """
    Validate text submitted to the scanner.
    """

    try:
        return normalize_text(
            text,
            SECURITY_CONFIG.max_text_length,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


def validate_scan_url(
    target_url: str,
) -> str:
    """
    Validate and normalize a scanner URL.

    This performs SSRF-safe DNS validation.
    """

    return validate_public_target(
        target_url
    )


def validate_redirect_chain(
    chain: Iterable[str],
) -> list[str]:
    """
    Validate a redirect chain before accepting it into a scan result.
    """

    result: list[str] = []

    for index, target in enumerate(chain):

        if index >= SECURITY_CONFIG.max_redirects:
            raise HTTPException(
                status_code=400,
                detail="Maximum redirect depth exceeded.",
            )

        result.append(
            validate_redirect_target(
                target
            )
        )

    return result


# ============================================================
# STARTUP SECURITY CHECK
# ============================================================

def security_startup_check() -> dict[str, object]:
    """
    Perform lightweight startup validation.

    Does not contact external services.
    """

    warnings: list[str] = []

    if "*" in SECURITY_CONFIG.allowed_hosts:
        warnings.append(
            "Allowed hosts are unrestricted. "
            "Set CYBERGUARD_ALLOWED_HOSTS in production."
        )

    if SECURITY_CONFIG.trust_proxy_headers:
        warnings.append(
            "Proxy headers are trusted. "
            "Use only behind a trusted reverse proxy."
        )

    if SECURITY_CONFIG.allow_private_networks:
        warnings.append(
            "Private-network outbound targets are enabled."
        )

    if not SECURITY_CONFIG.enforce_https:
        warnings.append(
            "HTTPS enforcement is disabled."
        )

    return {
        "status": "ok",
        "warnings": warnings,
        "max_url_length": SECURITY_CONFIG.max_url_length,
        "max_text_length": SECURITY_CONFIG.max_text_length,
        "max_upload_size": SECURITY_CONFIG.max_upload_size,
        "rate_limit_requests": SECURITY_CONFIG.rate_limit_requests,
        "rate_limit_window_seconds": (
            SECURITY_CONFIG.rate_limit_window_seconds
        ),
        "external_request_timeout": (
            SECURITY_CONFIG.external_request_timeout
        ),
    }


# ============================================================
# PUBLIC EXPORTS
# ============================================================

__all__ = [
    "SecurityConfig",
    "SECURITY_CONFIG",
    "ResolvedTarget",
    "SecurityEvent",
    "normalize_text",
    "sanitize_filename",
    "parse_http_url",
    "normalize_http_url",
    "get_hostname",
    "is_ip_address",
    "classify_ip",
    "is_public_ip",
    "resolve_hostname",
    "validate_hostname",
    "validate_url_syntax",
    "validate_public_target",
    "validate_redirect_target",
    "is_safe_target",
    "resolve_and_lock_target",
    "validate_upload_metadata",
    "read_upload_safely",
    "validate_image_signature",
    "validate_image_upload_bytes",
    "build_safe_temp_path",
    "get_api_key",
    "require_api_key",
    "mask_secret",
    "external_request_headers",
    "external_request_timeout",
    "InMemoryRateLimiter",
    "rate_limiter",
    "get_client_identifier",
    "enforce_rate_limit",
    "get_content_length",
    "enforce_content_length",
    "security_headers",
    "security_headers_middleware",
    "validate_host",
    "make_security_event",
    "safe_http_error",
    "validate_scan_text",
    "validate_scan_url",
    "validate_redirect_chain",
    "security_startup_check",
]


# ============================================================
# LOCAL SELF-TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("CYBERGUARD X — Security Layer Self-Test")
    print("=" * 60)

    print("\nConfiguration:")
    print(
        security_startup_check()
    )

    print("\nFilename sanitization:")
    print(
        sanitize_filename(
            "../../dangerous file?.png"
        )
    )

    print("\nURL validation:")

    test_urls = [
        "https://example.com",
        "http://example.com/test",
        "http://127.0.0.1",
        "http://localhost",
        "file:///etc/passwd",
    ]

    for target in test_urls:

        try:
            result = validate_scan_url(
                target
            )

            print(
                f"[SAFE] {target} -> {result}"
            )

        except Exception as exc:

            print(
                f"[BLOCKED] {target} -> "
                f"{getattr(exc, 'detail', str(exc))}"
            )

    print("\nIP classification:")

    for address in [
        "8.8.8.8",
        "127.0.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "::1",
        "10.0.0.1",
    ]:

        print(
            f"{address:16} -> "
            f"{classify_ip(address)}"
        )

    print("\nSecurity headers:")

    for key, value in security_headers().items():
        print(
            f"{key}: {value}"
        )

    print("\nAPI key masking:")

    print(
        mask_secret(
            "1234567890abcdef"
        )
    )

    print("\nSecurity layer self-test completed.")
