import atexit
import hashlib
import math
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import sys
import threading
import time
import uuid
from copy import deepcopy
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path, PurePosixPath
from secrets import compare_digest
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple
from xml.etree.ElementTree import Element, SubElement, tostring
from logging.handlers import RotatingFileHandler
from urllib.parse import urlencode as _compat_urlencode, urlparse, unquote

from markupsafe import escape

from itsdangerous import BadSignature, URLSafeSerializer

try:
    import werkzeug.urls as _werkzeug_urls

    if not hasattr(_werkzeug_urls, "url_encode"):

        def _url_encode_compat(params: Any, charset: str = "utf-8", sort: bool = False) -> str:
            """Compatibility shim for Flask-WTF on Werkzeug >= 3.0."""

            if params is None:
                return ""

            if hasattr(params, "items"):
                iterable = params.items()
            else:
                iterable = params

            items: List[tuple[str, Any]] = []
            for key, value in iterable:
                key_str = str(key)
                if isinstance(value, (list, tuple, set)):
                    for member in value:
                        items.append((key_str, "" if member is None else str(member)))
                else:
                    items.append((key_str, "" if value is None else str(value)))

            if sort:
                items.sort(key=lambda item: item[0])

            return _compat_urlencode(items, doseq=True)

        setattr(_werkzeug_urls, "url_encode", _url_encode_compat)
        export_list = getattr(_werkzeug_urls, "__all__", None)
        if isinstance(export_list, list) and "url_encode" not in export_list:
            export_list.append("url_encode")
except Exception:  # pragma: no cover - defensive best-effort shim
    pass

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.jobstores.base import JobLookupError
except ModuleNotFoundError:  # pragma: no cover - fallback for offline environments
    BackgroundScheduler = None  # type: ignore[assignment]

    class JobLookupError(Exception):
        """Fallback job lookup error used when APScheduler is unavailable."""

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    HAS_LIMITER = True
except ModuleNotFoundError:  # pragma: no cover - fallback for offline environments
    HAS_LIMITER = False

    class Limiter:  # type: ignore[override]
        def __init__(self, *args, **kwargs):
            self.limit = self._passthrough

        def _passthrough(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

        def __getattr__(self, name):
            def method(*args, **kwargs):
                return None

            return method

    def get_remote_address() -> str:
        return request.remote_addr or "127.0.0.1"
from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    has_request_context,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
try:
    from flask_wtf.csrf import CSRFProtect, CSRFError
    HAS_FLASK_WTF = True
except ModuleNotFoundError:  # pragma: no cover - fallback for test environments
    HAS_FLASK_WTF = False
    class CSRFError(Exception):
        """Fallback CSRF error used when Flask-WTF is unavailable."""


    class CSRFProtect:  # type: ignore[override]
        def __init__(self, app: Optional[Flask] = None) -> None:
            if app is not None:
                self.init_app(app)

        def init_app(self, app: Flask) -> None:
            app.logger.warning(
                "Flask-WTF is not installed; CSRF protection is disabled."
            )

        def exempt(self, view: Callable) -> Callable:
            return view

    def validate_csrf(token: str) -> None:  # type: ignore[override]
        if not token:
            raise CSRFError("Missing CSRF token")

from .storage import (
    DATA_DIR,
    LOGS_DIR,
    UPLOADS_DIR,
    batch_update_metadata,
    RESERVED_DIRECT_PATHS,
    cleanup_expired_files,
    cleanup_orphaned_files,
    cleanup_temp_files,
    count_directories,
    count_files,
    create_directory,
    delete_directory,
    delete_file,
    download_file_from_url,
    download_file_from_url_to_path,
    ensure_directories,
    get_db,
    get_directory,
    get_file,
    get_file_by_direct_path,
    get_file_metadata,
    get_storage_statistics,
    get_storage_path,
    iter_files,
    list_directories,
    list_directory_files,
    list_files,
    load_config,
    get_config_mtime,
    hash_api_key,
    prune_empty_upload_dirs,
    register_file,
    save_config,
    update_file_metadata,
    update_directory_file_count,
    DEFAULT_MAX_CONCURRENT_UPLOADS,
)

_CONFIG_CACHE: Dict[str, Any] = load_config()
_CONFIG_CACHE_MTIME: float = get_config_mtime()
_config_lock = threading.RLock()
quota_lock = threading.RLock()

# Constants for file operations and limits
PENDING_API_KEY_TTL_SECONDS = 600
CHUNK_SIZE_BYTES = 1024 * 1024  # 1 MB chunks for streaming
LOG_FILE_MAX_BYTES = 5 * 1024 * 1024  # 5 MB max log file size
LOG_FILE_BACKUP_COUNT = 3  # Number of log file backups to keep
BYTES_PER_MB = 1024 * 1024
DEFAULT_MAX_UPLOAD_SIZE_MB = 500
PASSWORD_MIN_LENGTH = 12  # Minimum password length for security

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
numeric_level = getattr(logging, LOG_LEVEL, logging.INFO)
logging.basicConfig(
    level=numeric_level,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

RESERVED_ROUTE_ENDPOINTS = {
    "hosting": "hosting",
    "upload-a-file": "upload_file_page",
    "logs": "logs_page",
    "api-docs": "api_docs",
    "settings": "settings",
}


def _load_secret_key() -> str:
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret:
        return env_secret

    secret_path = DATA_DIR / ".secret_key"
    try:
        ensure_directories()

        # Try to create file exclusively (fails if exists) to avoid race condition
        try:
            # Use exclusive creation mode with secure permissions to prevent race conditions
            # Set permissions atomically during file creation to avoid security window
            fd = os.open(
                secret_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600
            )
            generated = secrets.token_hex(32)
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    f.write(generated)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                # Close fd if fdopen failed
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            logging.warning("Generated new secret key - stored in %s", secret_path)
            return generated
        except FileExistsError:
            # File was created by another worker, read it
            existing = secret_path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
            # File exists but is empty, try to regenerate (edge case)
            logging.getLogger("localhosting.config").warning(
                "Secret key file exists but is empty, regenerating"
            )
            generated = secrets.token_hex(32)
            # Write with secure permissions atomically
            fd = os.open(secret_path, os.O_WRONLY | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    f.write(generated)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            return generated
    except OSError as error:
        logging.getLogger("localhosting.config").critical(
            "SECURITY WARNING: Using in-memory secret key. Sessions will not persist across restarts. "
            "Set SECRET_KEY environment variable for production use. Error: %s",
            error,
        )
        return secrets.token_hex(32)


_SECRET_KEY_VALUE: Optional[str] = None
_api_key_serializer: Optional[URLSafeSerializer] = None
MAX_FILENAME_LENGTH = int(os.environ.get("LOCALHOSTING_MAX_FILENAME_LENGTH", "255"))
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f\n\r]")
API_KEY_ENCRYPTION_VERSION = 1


class StorageQuotaExceededError(RuntimeError):
    """Raised when an upload would exceed the configured storage quota."""

    def __init__(self, current_usage: int, quota_limit: int) -> None:
        super().__init__("Storage quota exceeded")
        self.current_usage = current_usage
        self.quota_limit = quota_limit


def sanitize_log_value(value: Any) -> Any:
    """Remove control characters from log values to prevent log injection."""

    if isinstance(value, str):
        escaped = value.replace("\n", "\\n").replace("\r", "\\r")
        return _CONTROL_CHAR_PATTERN.sub(
            lambda match: f"\\x{ord(match.group()):02x}", escaped
        )
    return value


def _get_object_size(obj: Any, seen: Optional[Set[int]] = None, depth: int = 0, max_depth: int = 100) -> int:
    """
    Recursively calculate approximate size of an object in bytes.

    Args:
        obj: The object to measure
        seen: Set of object IDs already visited (prevents cycles)
        depth: Current recursion depth
        max_depth: Maximum recursion depth to prevent stack overflow

    Returns:
        Approximate size in bytes
    """
    # Prevent stack overflow with deeply nested objects
    if depth > max_depth:
        return sys.getsizeof(obj)

    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()

    obj_id = id(obj)
    if obj_id in seen:
        return 0
    seen.add(obj_id)

    if isinstance(obj, dict):
        size += sum(_get_object_size(v, seen, depth + 1, max_depth) for v in obj.values())
        size += sum(_get_object_size(k, seen, depth + 1, max_depth) for k in obj.keys())
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        try:
            size += sum(_get_object_size(i, seen, depth + 1, max_depth) for i in obj)
        except TypeError:
            pass  # Not iterable after all

    return size


def blocked_extensions() -> Set[str]:
    """Return the configured set of blocked file extensions."""

    raw_value = os.environ.get("LOCALHOSTING_BLOCKED_EXTENSIONS", "")
    return {
        entry.strip().lower().lstrip(".")
        for entry in raw_value.split(",")
        if entry.strip()
    }


def validate_filename(filename: str) -> tuple[bool, Optional[str]]:
    """Validate filenames for length and disallowed characters."""

    if not filename:
        return False, "Filename cannot be empty"

    if len(filename) > MAX_FILENAME_LENGTH:
        return (
            False,
            f"Filename exceeds maximum length of {MAX_FILENAME_LENGTH} characters",
        )

    if "\x00" in filename:
        return False, "Filename contains invalid characters"

    blocked = blocked_extensions()
    if blocked:
        extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if extension and extension in blocked:
            return (
                False,
                f"File extension '.{extension}' is not allowed",
            )

    return True, None


def validate_upload_mimetype(filename: str, declared_type: Optional[str]) -> bool:
    """Check for suspicious mismatches between filename and declared type."""

    if not filename or not declared_type:
        return True

    declared_type = declared_type.strip().lower()
    guessed_type, _ = mimetypes.guess_type(filename)
    if not guessed_type:
        return True

    guessed_type = guessed_type.lower()
    if declared_type == guessed_type:
        return True

    declared_major = declared_type.split("/", 1)[0]
    guessed_major = guessed_type.split("/", 1)[0]

    # Permit text types to be interchangeable (e.g., text/plain vs text/csv).
    if declared_major == "text" and guessed_major == "text":
        return True

    # Allow binary "octet-stream" fallbacks when the extension is unknown.
    if "octet-stream" in {declared_type, guessed_type}:
        return True

    return declared_major == guessed_major


def is_dangerous_content_type(content_type: Optional[str]) -> bool:
    """Check if content type is potentially dangerous (executable content)."""

    if not content_type:
        return False

    content_type_lower = content_type.lower().split(';')[0].strip()

    # Block dangerous executable content types
    dangerous_types = {
        'application/x-executable',
        'application/x-msdownload',
        'application/x-msdos-program',
        'application/x-sh',
        'application/x-csh',
        'application/x-bat',
        'application/x-apple-diskimage',
        'application/vnd.microsoft.portable-executable',
        'application/x-sharedlib',
        'application/x-elf',
        'application/x-dosexec',
    }

    return content_type_lower in dangerous_types


def _secret_fingerprint() -> str:
    """Derive a stable fingerprint of the active secret key."""

    secret = get_secret_key_value()
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


class UploadConcurrencyLimiter:
    """Track active uploads and enforce a configurable concurrency cap."""

    def __init__(self, limit: int) -> None:
        self._limit = max(1, int(limit))
        self._active = 0
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)

    def acquire(self) -> bool:
        with self._condition:
            if self._active >= self._limit:
                return False
            self._active += 1
            return True

    def release(self, acquired: bool) -> None:
        if not acquired:
            return
        with self._condition:
            if self._active > 0:
                self._active -= 1
                self._condition.notify_all()

    def update_limit(self, new_limit: int) -> None:
        with self._condition:
            self._limit = max(1, int(new_limit))
            self._condition.notify_all()

    def available_slots(self) -> int:
        with self._condition:
            return max(self._limit - self._active, 0)

    @property
    def current_limit(self) -> int:
        with self._condition:
            return self._limit


class AmbiguousAPIKeyError(Exception):
    """Raised when multiple API keys are provided in a single request."""


def rollback_successful_uploads(records: Iterable[Tuple[str, str]]) -> List[str]:
    failed: List[str] = []
    for uploaded_id, stored_name in records:
        try:
            record = get_file(uploaded_id)
            if not record:
                if stored_name:
                    path = get_storage_path(uploaded_id, stored_name)
                    if path.exists():
                        path.unlink(missing_ok=True)
                        prune_empty_upload_dirs(path.parent)
                continue
            if not delete_file(uploaded_id):
                failed.append(uploaded_id)
        except Exception:
            lifecycle_logger.warning(
                "rollback_delete_failed file_id=%s",
                sanitize_log_value(uploaded_id),
            )
            failed.append(uploaded_id)
    return failed


def storage_quota_limit_bytes() -> Optional[int]:
    """Return the configured storage quota in bytes, if any."""

    limit_gb = _get_optional_float_env("LOCALHOSTING_STORAGE_QUOTA_GB")
    if limit_gb is None or limit_gb <= 0:
        return None
    return int(limit_gb * (1024 ** 3))


def enforce_storage_quota_for_size(size: int) -> Tuple[int, int]:
    """Ensure storing an additional ``size`` bytes will not exceed the quota."""

    quota_limit_bytes = storage_quota_limit_bytes()
    if quota_limit_bytes is None:
        return 0, 0

    stats = get_storage_statistics()
    current_usage = int(stats.get("total_bytes", 0))
    if current_usage + size > quota_limit_bytes:
        raise StorageQuotaExceededError(current_usage, quota_limit_bytes)

    return current_usage, quota_limit_bytes


def _parse_origin(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    if value.strip().lower() == "null":
        return None
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def ensure_same_origin(response_format: str = "json") -> Optional[Response]:
    """Reject cross-site form submissions when API keys are not supplied."""

    # Skip CSRF checks in testing mode
    if app.config.get("TESTING") or not app.config.get("WTF_CSRF_ENABLED", True):
        return None

    def _reject(message: str, status_code: int = 403) -> Response:
        payload = {"error": message}
        if response_format == "box":
            return _box_error("access_denied", message, status=status_code)
        if response_format == "s3":
            return _s3_error_response("AccessDenied", message, status_code=status_code)
        return make_response(jsonify(payload), status_code)

    allowed_origin = _parse_origin(request.host_url)
    origin = _parse_origin(request.headers.get("Origin"))
    referer = _parse_origin(request.headers.get("Referer"))

    # Browser contexts typically supply an Origin or Referer header. When neither
    # header is present and an API key authenticated the request, treat it as a
    # non-browser client and skip CSRF validation.
    if not origin and not referer and getattr(g, "api_key_authenticated", False):
        return None

    # Require at least one header (Origin or Referer) when not API authenticated
    if not origin and not referer:
        lifecycle_logger.warning(
            "csrf_blocked_missing_headers path=%s",
            sanitize_log_value(request.path),
        )
        return _reject("Missing Origin or Referer header for CSRF protection")

    for candidate in (origin, referer):
        if candidate and candidate != allowed_origin:
            lifecycle_logger.warning(
                "csrf_blocked origin=%s path=%s",
                sanitize_log_value(candidate or "unknown"),
                sanitize_log_value(request.path),
            )
            return _reject("Cross-site requests are not allowed")

    return None


def get_secret_key_value() -> str:
    global _SECRET_KEY_VALUE
    if _SECRET_KEY_VALUE is None:
        _SECRET_KEY_VALUE = _load_secret_key()
    return _SECRET_KEY_VALUE


def _get_api_key_serializer() -> Optional[URLSafeSerializer]:
    global _api_key_serializer
    if _api_key_serializer is None:
        try:
            _api_key_serializer = URLSafeSerializer(
                get_secret_key_value(), salt="api-key"
            )
        except (TypeError, ValueError) as e:
            # Log specific serializer initialization errors
            logging.getLogger("localhosting.security").warning(
                "api_key_serializer_init_failed: %s", str(e)
            )
            return None
    return _api_key_serializer


def _encrypt_api_key(value: str) -> Optional[str]:
    """
    Encrypt an API key for secure storage.

    Returns None only if encryption is explicitly disabled via environment variable.
    Raises RuntimeError if encryption fails unexpectedly.
    """
    serializer = _get_api_key_serializer()
    if not serializer:
        security_logger = logging.getLogger("localhosting.security")
        # Check if plaintext storage is explicitly allowed
        allow_plaintext = os.environ.get("LOCALHOSTING_ALLOW_PLAINTEXT_API_KEYS", "").lower() == "true"
        if allow_plaintext:
            security_logger.warning(
                "api_key_encryption_unavailable: Plaintext storage explicitly allowed via LOCALHOSTING_ALLOW_PLAINTEXT_API_KEYS. "
                "This is NOT recommended for production use."
            )
            return None
        else:
            security_logger.error(
                "api_key_encryption_unavailable: SECRET_KEY not configured and plaintext storage not allowed. "
                "Set SECRET_KEY environment variable or set LOCALHOSTING_ALLOW_PLAINTEXT_API_KEYS=true to allow plaintext storage (NOT RECOMMENDED)."
            )
            raise RuntimeError("API key encryption is unavailable. Configure SECRET_KEY or explicitly allow plaintext storage.")
    try:
        return serializer.dumps(value)
    except Exception as e:
        logging.getLogger("localhosting.security").exception(
            "api_key_encryption_failed: Unexpected error during API key encryption"
        )
        raise RuntimeError(f"Failed to encrypt API key: {e}") from e


def _decrypt_api_key(token: str) -> Optional[str]:
    serializer = _get_api_key_serializer()
    if not serializer or not token:
        return None
    try:
        return serializer.loads(token)
    except (BadSignature, ValueError):
        return None


def validate_password_strength(password: str) -> tuple[bool, Optional[str]]:
    """
    Validate password meets minimum security requirements.

    Returns:
        (is_valid, error_message) tuple
    """
    if not password:
        return False, "Password cannot be empty"

    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters long"

    # Check for uppercase, lowercase, digit, and special character
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    if not has_upper:
        return False, "Password must contain at least one uppercase letter"

    if not has_lower:
        return False, "Password must contain at least one lowercase letter"

    if not has_digit:
        return False, "Password must contain at least one number"

    if not has_special:
        return False, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"

    # Check against common weak passwords
    common_weak = ['password', '12345678', 'qwerty', 'admin', 'letmein', 'welcome', 'monkey', 'dragon']
    if password.lower() in common_weak:
        return False, "This password is too common. Please choose a stronger password."

    return True, None


class RequestAwareLogger:
    """Logger wrapper that injects request IDs into log messages."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def _with_request(self, message: str) -> str:
        if has_request_context():
            request_id = getattr(g, "request_id", None)
            if request_id:
                return f"request_id={request_id} {message}"
        return message

    def debug(self, msg: str, *args, **kwargs) -> None:
        self._logger.debug(self._with_request(msg), *args, **kwargs)

    def info(self, msg: str, *args, **kwargs) -> None:
        self._logger.info(self._with_request(msg), *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs) -> None:
        self._logger.warning(self._with_request(msg), *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        self._logger.error(self._with_request(msg), *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs) -> None:
        self._logger.critical(self._with_request(msg), *args, **kwargs)

    def exception(self, msg: str, *args, **kwargs) -> None:
        self._logger.exception(self._with_request(msg), *args, **kwargs)

    def log(self, level: int, msg: str, *args, **kwargs) -> None:
        self._logger.log(level, self._with_request(msg), *args, **kwargs)

    def __getattr__(self, name: str):  # pragma: no cover - passthrough
        return getattr(self._logger, name)


def _configure_file_logging() -> Path:
    """Attach a rotating file handler for application and lifecycle logs."""

    ensure_directories()
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOGS_DIR / "application.log"
    root_logger = logging.getLogger()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")

    for handler in root_logger.handlers:
        if isinstance(handler, RotatingFileHandler) and getattr(handler, "baseFilename", "") == str(log_path):
            handler.setLevel(numeric_level)
            handler.setFormatter(formatter)
            return log_path

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=LOG_FILE_MAX_BYTES,
        backupCount=LOG_FILE_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    return log_path


APP_LOG_PATH = _configure_file_logging()
MAX_LOG_LINES = int(os.environ.get("LOCALHOSTING_LOG_MAX_LINES", "1000"))


def _resolve_docker_log_path() -> Optional[Path]:
    candidate = os.environ.get("LOCALHOSTING_DOCKER_LOG_PATH")
    if candidate:
        return Path(candidate).expanduser()

    fallback = LOGS_DIR / "docker.log"
    if fallback.exists():
        return fallback
    return None


def _get_log_sources() -> List[dict]:
    sources: List[dict] = [
        {
            "id": "application",
            "label": "Application & Uploads",
            "description": "Combined application output including upload lifecycle events.",
            "path": APP_LOG_PATH,
        }
    ]

    docker_path = _resolve_docker_log_path()
    if docker_path and docker_path != APP_LOG_PATH:
        sources.append(
            {
                "id": "docker",
                "label": "Docker Container",
                "description": "Tail of the Docker container logs (if provided).",
                "path": docker_path,
            }
        )

    return sources


def _load_log_payload(source: dict, *, max_lines: int = MAX_LOG_LINES) -> dict:
    """
    Load log file contents efficiently, reading only the last N lines.

    For large files, seeks to end and reads backwards to avoid loading
    the entire file into memory.
    """
    path: Path = source["path"]
    try:
        stat = path.stat()
        available = True
    except FileNotFoundError:
        available = False
        stat = None

    text = ""
    line_count = 0
    if available:
        try:
            # For small files, use simple approach
            # For large files (>10MB), use efficient tail approach
            if stat and stat.st_size > 10 * BYTES_PER_MB:
                # Efficient tail for large files
                with path.open("rb") as handle:
                    # Estimate: average line ~100 bytes, read 2x to be safe
                    bytes_to_read = min(max_lines * 200, stat.st_size)
                    handle.seek(max(0, stat.st_size - bytes_to_read))
                    # Read and decode
                    chunk = handle.read()
                    text_full = chunk.decode("utf-8", errors="replace")
                    # Split into lines and take last max_lines
                    lines = text_full.splitlines(keepends=True)
                    # Skip first potentially partial line if we didn't start at beginning
                    if stat.st_size > bytes_to_read and lines:
                        lines = lines[1:]
                    buffer = lines[-max_lines:] if len(lines) > max_lines else lines
                    line_count = len(buffer)
                    text = "".join(buffer)
            else:
                # Simple approach for smaller files
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    buffer = deque(handle, maxlen=max_lines)
                    line_count = len(buffer)
                    text = "".join(buffer)
        except OSError:
            available = False

    payload = {
        "available": available,
        "line_count": line_count,
        "text": text,
        "path": str(path),
    }

    if stat is not None:
        payload.update(
            {
                "size_bytes": stat.st_size,
                "last_modified": stat.st_mtime,
                "last_modified_iso": isoformat_utc(stat.st_mtime),
            }
        )

    if not available:
        payload["message"] = "Log file is not available yet."

    return payload


def _select_log_source(source_id: Optional[str]) -> tuple[dict, List[dict]]:
    sources = _get_log_sources()
    selected = next((entry for entry in sources if entry["id"] == source_id), sources[0])
    return selected, sources


def _build_log_response(source: dict) -> dict:
    payload = _load_log_payload(source)
    generated_at = time.time()
    if payload.get("size_bytes") is not None:
        payload["size_human"] = human_filesize(int(payload["size_bytes"]))
    payload.update(
        {
            "source": source["id"],
            "label": source["label"],
            "description": source["description"],
            "generated_at": generated_at,
            "generated_at_iso": isoformat_utc(generated_at),
            "max_lines": MAX_LOG_LINES,
        }
    )
    return payload


def _apply_upload_limit(config: Dict[str, Any]) -> None:
    flask_app = globals().get("app")
    if flask_app is None:
        return

    try:
        size_mb = float(config.get("max_upload_size_mb", 0))
    except (TypeError, ValueError):
        size_mb = 0.0

    size_mb = max(1.0, size_mb)
    limit_bytes = int(size_mb * BYTES_PER_MB)
    flask_app.config["MAX_CONTENT_LENGTH"] = limit_bytes
    flask_app.config["MAX_UPLOAD_SIZE_MB"] = size_mb


def _coerce_positive_int(value: Any, fallback: int) -> int:
    try:
        parsed = int(float(value))
    except (TypeError, ValueError):
        return max(1, fallback)
    return max(1, parsed)


def _memory_based_concurrency_cap(default: int) -> int:
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        phys_pages = os.sysconf("SC_PHYS_PAGES")
        approx = int((page_size * phys_pages) / (100 * 1024 * 1024))
        return max(1, approx)
    except (AttributeError, OSError, ValueError):
        return max(1, default)


def _apply_concurrency_limit(config: Dict[str, Any]) -> None:
    global upload_limiter, max_concurrent_uploads_setting

    fallback_default = max(1, int(DEFAULT_MAX_CONCURRENT_UPLOADS))
    requested_limit = _coerce_positive_int(
        config.get("max_concurrent_uploads"), max_concurrent_uploads_setting or fallback_default
    )
    hard_cap = min(fallback_default, _memory_based_concurrency_cap(fallback_default))
    new_limit = min(requested_limit, hard_cap)

    if new_limit < requested_limit:
        logging.getLogger("localhosting.performance").warning(
            "concurrency_limit_reduced requested=%d applied=%d cap=%d",
            requested_limit,
            new_limit,
            hard_cap,
        )

    if new_limit != max_concurrent_uploads_setting:
        upload_limiter.update_limit(new_limit)
        max_concurrent_uploads_setting = new_limit


def _apply_cleanup_schedule(config: Dict[str, Any]) -> None:
    global cleanup_interval_minutes_setting, scheduler, _fallback_schedulers

    new_interval = _coerce_positive_int(
        config.get("cleanup_interval_minutes"), cleanup_interval_minutes_setting or 5
    )

    if new_interval == cleanup_interval_minutes_setting:
        return

    cleanup_interval_minutes_setting = new_interval

    if BackgroundScheduler is not None and scheduler is not None:
        try:
            scheduler.reschedule_job(
                "cleanup_expired_files",
                trigger="interval",
                minutes=max(1, new_interval),
            )
        except JobLookupError:
            scheduler.add_job(
                func=cleanup_expired_files,
                trigger="interval",
                minutes=max(1, new_interval),
                id="cleanup_expired_files",
                name="Clean up expired files",
                replace_existing=True,
            )
    else:
        for worker in _fallback_schedulers:
            if getattr(worker, "func", None) is cleanup_expired_files:
                worker.update_interval(new_interval)


def _apply_runtime_settings(config: Dict[str, Any]) -> None:
    _apply_upload_limit(config)
    _apply_concurrency_limit(config)
    _apply_cleanup_schedule(config)


def get_config(refresh: bool = False) -> Dict[str, Any]:
    global _CONFIG_CACHE, _CONFIG_CACHE_MTIME
    with _config_lock:
        current_mtime = get_config_mtime()
        if not refresh and current_mtime > _CONFIG_CACHE_MTIME:
            refresh = True

        if refresh or _CONFIG_CACHE is None:
            _CONFIG_CACHE = load_config()
            # Use already-fetched mtime to avoid race condition
            _CONFIG_CACHE_MTIME = current_mtime

        if has_request_context():
            cached = getattr(g, "_app_config", None)
            if cached is None or refresh:
                g._app_config = _CONFIG_CACHE.copy()  # Make a copy to avoid race conditions
            config = g._app_config
        else:
            # Make a copy to prevent race conditions when applying settings outside lock
            config = _CONFIG_CACHE.copy()

    _apply_runtime_settings(config)
    return config


def ui_auth_enabled() -> bool:
    config = get_config()
    return bool(config.get("ui_auth_enabled"))


def ui_user_authenticated() -> bool:
    return bool(session.get("ui_authenticated"))


def require_ui_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not ui_auth_enabled() or ui_user_authenticated():
            return view(*args, **kwargs)

        next_target = request.full_path if request.query_string else request.path
        session["ui_next"] = (next_target or "/").rstrip("?")
        flash("Please log in to access the dashboard.", "info")
        return redirect(url_for("login"))

    return wrapped


def api_auth_enabled() -> bool:
    config = get_config()
    return bool(config.get("api_auth_enabled"))


def _iter_api_keys(config: Optional[Dict[str, Any]] = None) -> Iterable[dict]:
    config = config or get_config()
    for entry in config.get("api_keys", []):
        if isinstance(entry, dict) and entry.get("key_hash") and entry.get("id"):
            yield entry


def get_ui_api_key(config: Optional[Dict[str, Any]] = None) -> Optional[dict]:
    config = config or get_config()
    key_id = config.get("api_ui_key_id") or ""
    if not key_id:
        return None
    for entry in _iter_api_keys(config):
        if entry.get("id") == key_id:
            result = dict(entry)
            fingerprint = entry.get("secret_fingerprint")
            current_fingerprint = _secret_fingerprint()
            plaintext = ""
            has_plaintext = False
            if fingerprint and fingerprint != current_fingerprint:
                logging.getLogger("localhosting.security").warning(
                    "api_key_secret_mismatch key_id=%s", entry.get("id")
                )
                result["encryption_mismatch"] = True
            else:
                plaintext = _decrypt_api_key(entry.get("key_encrypted", "")) or ""
                has_plaintext = bool(plaintext)
            result["key"] = plaintext
            result["has_plaintext"] = has_plaintext
            return result
    return None


def render_settings_page(config: Dict[str, Any]):
    """Render the general settings dashboard."""

    storage_stats_raw = get_storage_statistics()
    storage_overview = {
        "total_bytes": storage_stats_raw["total_bytes"],
        "total_gb": storage_stats_raw["total_bytes"] / (1024 ** 3)
        if storage_stats_raw["total_bytes"]
        else 0.0,
        "active_count": storage_stats_raw["active_count"],
        "expired_count": storage_stats_raw["expired_count"],
    }

    storage_quota_limit = _get_optional_float_env("LOCALHOSTING_STORAGE_QUOTA_GB")

    # Ensure all numeric values are properly formatted
    performance_settings = {
        "max_upload_size_mb": float(config.get("max_upload_size_mb", 500)),
        "max_concurrent_uploads": int(float(config.get("max_concurrent_uploads", 10))),
        "cleanup_interval_minutes": int(float(config.get("cleanup_interval_minutes", 5))),
        "rate_limits": {
            "upload_per_hour": int(float(config.get("upload_rate_limit_per_hour", 100))),
            "login_per_minute": int(float(config.get("login_rate_limit_per_minute", 10))),
            "download_per_minute": int(float(config.get("download_rate_limit_per_minute", 120))),
        },
    }

    blocked_extensions_raw = os.environ.get("LOCALHOSTING_BLOCKED_EXTENSIONS", "")
    blocked_extensions = [
        item.strip()
        for item in blocked_extensions_raw.split(",")
        if item.strip()
    ]

    file_policy_settings = {
        "blocked_extensions": blocked_extensions,
        "max_filename_length": _get_optional_int_env(
            "LOCALHOSTING_MAX_FILENAME_LENGTH"
        ),
        "sharding_enabled": _get_optional_bool_env("LOCALHOSTING_ENABLE_SHARDING"),
        "raw_urls_enabled": _get_optional_bool_env("LOCALHOSTING_ENABLE_RAW_URLS"),
        "blocked_extensions_raw": blocked_extensions_raw,
    }

    return render_template(
        "settings.html",
        config=config,
        storage_overview=storage_overview,
        storage_quota_limit=storage_quota_limit,
        performance_settings=performance_settings,
        file_policy_settings=file_policy_settings,
    )


def render_api_keys_page(config: Dict[str, Any]):
    """Render the API key management dashboard."""

    pending_keys: List[Dict[str, Any]] = []
    now = time.time()

    pending_entry = session.pop("pending_api_key_display_once", None)
    if isinstance(pending_entry, dict):
        raw_value = pending_entry.get("key") or pending_entry.get("value")
        expires_raw = pending_entry.get("expires")
        try:
            expires_at = float(expires_raw) if expires_raw is not None else now
        except (TypeError, ValueError):
            expires_at = now
        if raw_value and expires_at > now:
            pending_keys.append(
                {
                    "id": str(pending_entry.get("id") or uuid.uuid4().hex),
                    "value": str(raw_value),
                }
            )
        session.modified = True

    legacy_pending = session.pop("pending_api_keys", None)
    if not pending_keys and isinstance(legacy_pending, list):
        for entry in legacy_pending:
            if not isinstance(entry, dict):
                continue
            value = entry.get("value")
            if not value:
                continue
            pending_keys.append(
                {
                    "id": str(entry.get("id") or uuid.uuid4().hex),
                    "value": str(value),
                }
            )
            break
        session.modified = True

    legacy_key = session.pop("last_generated_api_key", None)
    if legacy_key and not pending_keys:
        if isinstance(legacy_key, dict):
            value = legacy_key.get("value")
        else:
            value = str(legacy_key)
        if value:
            pending_keys.append(
                {
                    "id": uuid.uuid4().hex,
                    "value": value,
                }
            )
        session.modified = True

    fingerprint = _secret_fingerprint()
    encryption_warning = any(
        entry.get("key_encrypted")
        and (
            not entry.get("secret_fingerprint")
            or entry.get("secret_fingerprint") != fingerprint
        )
        for entry in config.get("api_keys", [])
        if isinstance(entry, dict)
    )

    return render_template(
        "api_keys.html",
        config=config,
        api_ui_key=get_ui_api_key(config),
        pending_keys=pending_keys,
        encryption_warning=encryption_warning,
    )


def _extract_api_key_from_request() -> Optional[str]:
    candidates: List[str] = []

    header_key = request.headers.get("X-API-Key")
    if header_key:
        candidates.append(header_key.strip())

    authorization = request.headers.get("Authorization", "").strip()
    if authorization.lower().startswith("bearer "):
        candidates.append(authorization[7:].strip())
    elif authorization.lower().startswith("token "):
        candidates.append(authorization[6:].strip())

    query_key = request.args.get("api_key")
    if query_key:
        candidates.append(query_key.strip())

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        if isinstance(payload, dict):
            json_key = payload.get("api_key")
            if isinstance(json_key, str):
                candidates.append(json_key.strip())

    unique = {candidate for candidate in candidates if candidate}
    if len(unique) > 1:
        raise AmbiguousAPIKeyError("Multiple API keys provided")
    return next(iter(unique)) if unique else None


def _api_auth_error(response_format: str = "json") -> Response:
    """Return an API authentication error response.

    For authentication failures (missing credentials), HTTP 401 is the correct
    status code across all formats. HTTP 403 is reserved for authorization
    failures (invalid credentials).
    """
    message = "API authentication required."
    if response_format == "box":
        return _box_error("access_denied", message, status=401)
    if response_format == "s3":
        return _s3_error_response("AccessDenied", message, status_code=401)
    return make_response(jsonify({"error": message}), 401)


def _api_key_matches(provided: Optional[str]) -> bool:
    if not provided:
        return False
    provided_hash = hash_api_key(provided)
    for entry in _iter_api_keys():
        if compare_digest(entry.get("key_hash", ""), provided_hash):
            return True
    return False


def require_api_auth(response_format: str = "json"):
    def decorator(view: Callable):
        @wraps(view)
        def wrapped(*args, **kwargs):
            g.api_key_authenticated = False
            if not api_auth_enabled():
                # When API auth is disabled, still require proper CSRF headers
                # API clients must include Origin/Referer OR use API keys to bypass CSRF
                return view(*args, **kwargs)

            if ui_auth_enabled() and ui_user_authenticated():
                # When user is authenticated via UI, treat as authenticated to skip CSRF checks
                g.api_key_authenticated = True
                return view(*args, **kwargs)

            try:
                provided = _extract_api_key_from_request()
            except AmbiguousAPIKeyError:
                message = "Multiple API keys provided"
                lifecycle_logger.warning(
                    "api_auth_ambiguous_keys endpoint=%s method=%s",
                    request.endpoint,
                    request.method,
                )
                if response_format == "box":
                    return _box_error("access_denied", message, status=400)
                if response_format == "s3":
                    return _s3_error_response(
                        "AccessDenied", message, status_code=400
                    )
                return make_response(jsonify({"error": message}), 400)

            if _api_key_matches(provided):
                g.api_key_authenticated = True
                return view(*args, **kwargs)

            lifecycle_logger.warning(
                "api_auth_failed endpoint=%s method=%s", request.endpoint, request.method
            )
            return _api_auth_error(response_format)

        return wrapped

    return decorator


def _generate_api_key_entry(label: str = "") -> dict:
    raw_key = secrets.token_urlsafe(32)
    encrypted = _encrypt_api_key(raw_key)
    if encrypted is None:
        raise RuntimeError("Failed to encrypt API key")
    fingerprint = _secret_fingerprint()
    return {
        "id": uuid.uuid4().hex,
        "key": raw_key,
        "key_hash": hash_api_key(raw_key),
        "key_encrypted": encrypted,
        "label": (label or "").strip(),
        "created_at": time.time(),
        "encryption_version": API_KEY_ENCRYPTION_VERSION,
        "secret_fingerprint": fingerprint,
    }


def _store_pending_api_key_entry(key_id: str, raw_value: str) -> None:
    """Persist a generated API key in the user's session until acknowledged."""

    if not raw_value:
        return

    expires_at = time.time() + PENDING_API_KEY_TTL_SECONDS
    session["pending_api_key_display_once"] = {
        "id": key_id,
        "key": raw_value,
        "expires": expires_at,
    }
    session["pending_api_keys"] = [
        {
            "id": key_id,
            "value": raw_value,
            "created_at": time.time(),
            "viewed_at": None,
        }
    ]
    session.modified = True


class _FallbackCleanupScheduler:
    """Minimal interval scheduler used when APScheduler is unavailable."""

    def __init__(self, func, *, minutes: int) -> None:
        self.func = func
        self.interval_seconds = max(60, minutes * 60)
        self._logger = logging.getLogger("localhosting.scheduler")
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name="cleanup-scheduler", daemon=True)

    def start(self) -> None:
        if not self._thread.is_alive():
            self._thread.start()

    def shutdown(self, wait: bool = False) -> None:
        self._stop_event.set()
        if wait and self._thread.is_alive():
            self._thread.join()

    def update_interval(self, minutes: int) -> None:
        """Update the interval used for scheduled execution."""

        self.interval_seconds = max(60, minutes * 60)

    def _run(self) -> None:
        while not self._stop_event.wait(self.interval_seconds):
            try:
                self.func()
            except Exception:  # pragma: no cover - defensive logging
                self._logger.exception("Cleanup job failed")

scheduler = None
_fallback_schedulers: List[_FallbackCleanupScheduler] = []
try:
    _env_concurrency = int(
        os.environ.get(
            "LOCALHOSTING_MAX_CONCURRENT_UPLOADS", str(int(DEFAULT_MAX_CONCURRENT_UPLOADS))
        )
    )
except (TypeError, ValueError):
    _env_concurrency = int(DEFAULT_MAX_CONCURRENT_UPLOADS)

max_concurrent_uploads_setting = max(1, _env_concurrency)
cleanup_interval_minutes_setting = 5
upload_limiter = UploadConcurrencyLimiter(max_concurrent_uploads_setting)

app = Flask(__name__)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get("LOCALHOSTING_RATE_LIMIT_STORAGE", "memory://"),
)


def _get_optional_float_env(env_key: str) -> Optional[float]:
    raw_value = os.environ.get(env_key)
    if raw_value is None or raw_value == "":
        return None
    try:
        return float(raw_value)
    except ValueError:
        return None


def _get_optional_int_env(env_key: str) -> Optional[int]:
    raw_value = os.environ.get(env_key)
    if raw_value is None or raw_value == "":
        return None
    try:
        return int(raw_value)
    except ValueError:
        return None


def _get_optional_bool_env(env_key: str) -> Optional[bool]:
    raw_value = os.environ.get(env_key)
    if raw_value is None:
        return None
    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def upload_rate_limit_string() -> str:
    config = get_config()
    value = _coerce_positive_int(config.get("upload_rate_limit_per_hour"), 100)
    return f"{value} per hour"


def login_rate_limit_string() -> str:
    config = get_config()
    value = _coerce_positive_int(config.get("login_rate_limit_per_minute"), 10)
    return f"{value} per minute"


def download_rate_limit_string() -> str:
    config = get_config()
    value = _coerce_positive_int(config.get("download_rate_limit_per_minute"), 120)
    return f"{value} per minute"


def api_rate_limit_string() -> str:
    """Rate limit for general API endpoints (200 per minute)."""
    return "200 per minute"


app.config["MAX_CONTENT_LENGTH"] = int(
    _coerce_positive_int(_CONFIG_CACHE.get("max_upload_size_mb"), DEFAULT_MAX_UPLOAD_SIZE_MB) * BYTES_PER_MB
)
app.config["MAX_UPLOAD_SIZE_MB"] = _CONFIG_CACHE.get("max_upload_size_mb", DEFAULT_MAX_UPLOAD_SIZE_MB)
app.config["SECRET_KEY"] = get_secret_key_value()
_session_cookie_secure_override = _get_optional_bool_env("SESSION_COOKIE_SECURE")
if _session_cookie_secure_override is None:
    app.config["SESSION_COOKIE_SECURE"] = not app.config.get("TESTING", False)
else:
    app.config["SESSION_COOKIE_SECURE"] = _session_cookie_secure_override

# Warn if HTTPS is not enforced in production
if not app.config["SESSION_COOKIE_SECURE"] and not app.config.get("TESTING", False):
    security_logger = logging.getLogger("localhosting.security")
    security_logger.warning(
        "SECURITY WARNING: SESSION_COOKIE_SECURE is disabled. "
        "Cookies will be transmitted over unencrypted HTTP connections. "
        "This is NOT recommended for production use. "
        "Enable HTTPS and set SESSION_COOKIE_SECURE=true environment variable."
    )

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)
csrf = CSRFProtect(app)
app.logger.setLevel(numeric_level)

_apply_runtime_settings(_CONFIG_CACHE)

_base_lifecycle_logger = logging.getLogger("localhosting.lifecycle")
_base_lifecycle_logger.setLevel(numeric_level)
lifecycle_logger = RequestAwareLogger(_base_lifecycle_logger)


def _close_stream_safely(stream: Any, context: str) -> None:
    """Close an upload/input stream while logging failures."""

    if stream is None or not hasattr(stream, "close"):
        return

    try:
        stream.close()
    except OSError as error:
        lifecycle_logger.warning(
            "stream_close_failed context=%s error=%s",
            context,
            sanitize_log_value(str(error)),
        )


@contextmanager
def upload_stream_handler(file_storage: FileStorage) -> Iterator[FileStorage]:
    """Ensure uploaded file streams are always closed."""

    try:
        yield file_storage
    finally:
        _close_stream_safely(
            getattr(file_storage, "stream", None),
            f"upload_stream_handler filename={getattr(file_storage, 'filename', 'unknown')}",
        )


if not HAS_FLASK_WTF:

    @app.context_processor
    def _inject_csrf_stub():  # pragma: no cover - used when Flask-WTF missing
        return {"csrf_token": lambda: ""}


@contextmanager
def upload_slot() -> Iterator[bool]:
    acquired = upload_limiter.acquire()
    try:
        yield acquired
    finally:
        # Always release if we acquired a slot
        if acquired:
            upload_limiter.release(True)


@app.before_request
def add_request_id() -> None:
    """Assign a request identifier for downstream logging."""

    g.request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex)


@app.after_request
def log_request_completion(response: Response):
    """Emit lifecycle logs for every completed request."""

    lifecycle_logger.info(
        "request_completed method=%s path=%s status=%d size=%s",
        request.method,
        sanitize_log_value(request.path),
        response.status_code,
        response.calculate_content_length() if hasattr(response, "calculate_content_length") else response.content_length or 0,
    )
    return response


@app.after_request
def add_security_headers(response: Response):
    """Attach security-focused response headers."""

    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://code.ionicframework.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://code.ionicframework.com; "
        "connect-src 'self';"
    )
    response.headers["Content-Security-Policy"] = csp
    return response


@app.after_request
def add_request_id_header(response: Response):
    """Expose the current request identifier to clients."""

    if hasattr(g, "request_id"):
        response.headers["X-Request-ID"] = g.request_id
    return response


@app.errorhandler(413)
def handle_file_too_large(error):  # pragma: no cover - framework hook
    message = {"error": "File too large"}
    api_paths = ("/fileupload", "/s3/", "/2.0/")
    if request.path.startswith(api_paths) or (
        request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html
    ):
        return jsonify(message), 413
    if request.accept_mimetypes.accept_html:
        flash("The uploaded file exceeds the allowed size limit.", "error")
        return redirect(request.referrer or url_for("upload_file_page")), 303
    return jsonify(message), 413


@app.errorhandler(429)
def handle_rate_limit(error):  # pragma: no cover - framework hook
    description = getattr(error, "description", "Too many requests")
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({"error": "Rate limit exceeded", "message": str(description)}), 429
    flash("Too many requests. Please try again later.", "error")
    return redirect(request.referrer or url_for("hosting")), 303


@app.errorhandler(CSRFError)
def handle_csrf_error(error):  # pragma: no cover - framework hook
    description = getattr(error, "description", "Invalid CSRF token")
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({"error": description}), 400
    flash("Your session has expired or the form was invalid. Please try again.", "error")
    return redirect(request.referrer or url_for("login")), 303


@app.context_processor
def inject_ui_state():
    config = get_config()
    return {
        "ui_auth_enabled": bool(config.get("ui_auth_enabled")),
        "ui_authenticated": ui_user_authenticated(),
        "ui_username": config.get("ui_username", "admin"),
        "api_auth_enabled": bool(config.get("api_auth_enabled")),
        "api_ui_key_id": config.get("api_ui_key_id", ""),
    }


def isoformat_utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def remove_orphaned_record(file_id: str) -> None:
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
    except Exception as error:  # pragma: no cover - defensive logging
        lifecycle_logger.warning(
            "orphan_record_cleanup_failed file_id=%s error=%s", file_id, error
        )

# Schedule periodic cleanup so requests are not blocked by retention pruning.
cleanup_interval_minutes_setting = _coerce_positive_int(
    _CONFIG_CACHE.get("cleanup_interval_minutes"), cleanup_interval_minutes_setting or 5
)

if BackgroundScheduler is not None:
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=cleanup_expired_files,
        trigger="interval",
        minutes=max(1, cleanup_interval_minutes_setting),
        id="cleanup_expired_files",
        name="Clean up expired files",
        replace_existing=True,
    )
    scheduler.add_job(
        func=cleanup_orphaned_files,
        trigger="interval",
        hours=1,
        id="cleanup_orphaned_files",
        name="Clean up orphaned files",
        replace_existing=True,
    )
    scheduler.add_job(
        func=cleanup_temp_files,
        trigger="interval",
        hours=1,
        id="cleanup_temp_files",
        name="Clean up temporary files",
        replace_existing=True,
    )
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown(wait=False))
else:  # pragma: no cover - exercised in environments without APScheduler
    _fallback_schedulers = [
        _FallbackCleanupScheduler(
            cleanup_expired_files,
            minutes=max(1, cleanup_interval_minutes_setting),
        ),
        _FallbackCleanupScheduler(
            cleanup_orphaned_files,
            minutes=60,
        ),
        _FallbackCleanupScheduler(
            cleanup_temp_files,
            minutes=60,
        ),
    ]

    for _scheduler in _fallback_schedulers:
        _scheduler.start()

    atexit.register(lambda: [sched.shutdown(wait=False) for sched in _fallback_schedulers])

# Run a single cleanup on startup to enforce retention before serving traffic.
cleanup_expired_files()


class RetentionValidationError(ValueError):
    """Raised when a requested retention period is invalid."""

    def __init__(self, message: str, allowed_range: Optional[Iterable[float]] = None):
        super().__init__(message)
        self.allowed_range = list(allowed_range) if allowed_range is not None else None

    def to_payload(self) -> dict:
        payload = {"error": str(self)}
        if self.allowed_range is not None:
            payload["allowed_range"] = self.allowed_range
        return payload


def resolve_retention(config: dict, *candidates: Optional[str]) -> float:
    """Resolve and validate a retention value from the provided candidates."""

    chosen: Optional[str] = None
    for candidate in candidates:
        if candidate not in (None, ""):
            chosen = candidate
            break

    if chosen is None:
        return config.get("retention_hours", 24.0)

    allowed_range = (
        config.get("retention_min_hours", 0.0),
        config.get("retention_max_hours", config.get("retention_hours", 24.0)),
    )

    try:
        retention = float(chosen)

        # Check for NaN and infinity
        import math
        if math.isnan(retention) or math.isinf(retention):
            raise ValueError("Invalid retention value: must be a finite number")
        if not (0 <= retention <= 8760):
            raise ValueError("Retention must be between 0 and 8760 hours")
    except (TypeError, ValueError) as error:
        raise RetentionValidationError(
            "Invalid retention_hours value",
            allowed_range=allowed_range,
        ) from error

    if not (allowed_range[0] <= retention <= allowed_range[1]):
        raise RetentionValidationError(
            "Retention must be within the configured range.",
            allowed_range=allowed_range,
        )

    return retention


def _box_error(
    code: str,
    message: str,
    *,
    status: int = 400,
    context: Optional[Dict[str, str]] = None,
) -> Response:
    payload: Dict[str, object] = {
        "type": "error",
        "status": status,
        "code": code,
        "message": message,
    }
    if context:
        payload["context_info"] = context
    return make_response(jsonify(payload), status)


def _s3_error_response(
    code: str,
    message: str,
    *,
    status_code: int = 400,
    bucket: Optional[str] = None,
    key: Optional[str] = None,
) -> Response:
    root = Element("Error")
    SubElement(root, "Code").text = code
    SubElement(root, "Message").text = message
    if bucket is not None:
        SubElement(root, "BucketName").text = bucket
    if key is not None:
        SubElement(root, "Key").text = key

    payload = tostring(root, encoding="utf-8")
    response = make_response(payload, status_code)
    response.mimetype = "application/xml"
    response.headers["x-amz-request-id"] = uuid.uuid4().hex
    return response


def _build_s3_post_success(bucket: str, key: str, location: str, etag: str):
    root = Element("PostResponse")
    SubElement(root, "Location").text = location
    SubElement(root, "Bucket").text = bucket
    SubElement(root, "Key").text = key
    SubElement(root, "ETag").text = f'"{etag}"'
    payload = tostring(root, encoding="utf-8")
    response = make_response(payload, 201)
    response.mimetype = "application/xml"
    response.headers["ETag"] = f'"{etag}"'
    response.headers["Location"] = location
    response.headers["x-amz-request-id"] = uuid.uuid4().hex
    return response


def _build_s3_put_success(bucket: str, key: str, location: str, etag: str):
    root = Element("PutObjectResult")
    SubElement(root, "Bucket").text = bucket
    SubElement(root, "Key").text = key
    SubElement(root, "Location").text = location
    SubElement(root, "ETag").text = f'"{etag}"'
    payload = tostring(root, encoding="utf-8")
    response = make_response(payload, 200)
    response.mimetype = "application/xml"
    response.headers["ETag"] = f'"{etag}"'
    response.headers["Location"] = location
    response.headers["x-amz-request-id"] = uuid.uuid4().hex
    return response


@app.context_processor
def inject_utilities():
    now_utc = datetime.now(tz=timezone.utc)
    return {"now": lambda: datetime.now(tz=timezone.utc), "current_year": now_utc.year}


@app.template_filter("human_datetime")
def human_datetime(value: float) -> str:
    dt = datetime.fromtimestamp(value, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


@app.template_filter("human_filesize")
def human_filesize(num: int) -> str:
    if num < 1024:
        return f"{num} B"
    for unit in ["KB", "MB", "GB", "TB"]:
        num /= 1024.0
        if abs(num) < 1024.0:
            return f"{num:.2f} {unit}"
    return f"{num:.2f} PB"


@app.template_filter("human_timedelta")
def human_timedelta(seconds: float) -> str:
    total_seconds = int(seconds)
    if total_seconds <= 0:
        return "Expired"

    minutes, _ = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)

    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes and len(parts) < 2:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append("<1m")
    return " ".join(parts)


@app.route("/")
@require_ui_auth
def index():
    return redirect(url_for("hosting"))


@app.route("/health")
def health_check():
    checks: Dict[str, Any] = {}
    healthy = True

    try:
        with get_db() as conn:
            conn.execute("SELECT 1").fetchone()
            conn.execute("SELECT COUNT(*) FROM files").fetchone()
        checks["database"] = "ok"
    except Exception as error:
        checks["database"] = f"error: {str(error)[:100]}"
        healthy = False

    try:
        ensure_directories()
        usage = shutil.disk_usage(UPLOADS_DIR)
        disk_free_gb = usage.free / (1024 ** 3)
        checks["disk_space_gb"] = round(disk_free_gb, 2)
        if disk_free_gb < 1:
            checks["disk_space_status"] = "critical"
            healthy = False
        elif disk_free_gb < 5:
            checks["disk_space_status"] = "warning"
        else:
            checks["disk_space_status"] = "ok"
    except Exception as error:
        checks["disk_space_gb"] = 0
        checks["disk_space_status"] = f"error: {str(error)[:100]}"
        healthy = False

    try:
        ensure_directories()
        probe_file = UPLOADS_DIR / f".health_check_{uuid.uuid4().hex}"
        probe_file.write_text("health_check", encoding="utf-8")
        probe_file.unlink(missing_ok=True)
        checks["uploads_writable"] = "ok"
    except Exception as error:
        checks["uploads_writable"] = f"error: {str(error)[:100]}"
        healthy = False

    try:
        if BackgroundScheduler is not None and scheduler is not None:
            job = scheduler.get_job("cleanup_expired_files")
            if job and job.next_run_time:
                checks["cleanup"] = "scheduled"
                checks["cleanup_next_run"] = job.next_run_time.isoformat()
            else:
                checks["cleanup"] = "not_scheduled"
            checks["scheduler_running"] = bool(scheduler.running)
        else:
            checks["cleanup"] = "fallback_scheduler"
            checks["scheduler_running"] = False
    except Exception as error:
        checks["cleanup"] = f"error: {str(error)[:100]}"
        checks["scheduler_running"] = False

    try:
        checks["upload_limit"] = upload_limiter.current_limit
        available_slots = upload_limiter.available_slots()
        checks["upload_slots_available"] = available_slots
        checks["semaphore_available"] = available_slots
    except Exception as error:
        checks["upload_limit"] = "unknown"
        checks["upload_slots_available"] = f"error: {str(error)[:100]}"
        checks["semaphore_available"] = f"error: {str(error)[:100]}"

    status = "healthy" if healthy else "unhealthy"
    code = 200 if healthy else 503

    return jsonify(
        {
            "status": status,
            "timestamp": time.time(),
            "checks": checks,
            "version": "1.0.0",
        }
    ), code


@app.route("/hosting")
@require_ui_auth
def hosting():
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = request.args.get("per_page", 50, type=int)
    per_page = max(1, min(per_page, 200))
    search = request.args.get("search", "").strip()
    sort_by = request.args.get("sort", "uploaded_at")
    sort_order = request.args.get("order", "desc").lower()
    if sort_by not in {"name", "size", "uploaded_at", "expires_at"}:
        sort_by = "uploaded_at"
    sort_order = sort_order if sort_order in {"asc", "desc"} else "desc"

    total_files = count_files(search_term=search or None)
    total_pages = max(1, math.ceil(total_files / per_page)) if total_files else 1
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page

    records = list_files(
        limit=per_page,
        offset=offset,
        search_term=search or None,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    page_files = list(iter_files(records))

    for file in page_files:
        file["download_url"] = url_for("download", file_id=file["id"])
        file["direct_download_url"] = url_for(
            "direct_download", file_id=file["id"], filename=file["original_name"]
        )
        if file.get("raw_download_path"):
            file["raw_download_url"] = url_for(
                "serve_raw_file", direct_path=file["raw_download_path"]
            )

    return render_template(
        "hosting.html",
        files=page_files,
        page=page,
        per_page=per_page,
        total_files=total_files,
        total_pages=total_pages,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@app.route("/upload-a-file")
@require_ui_auth
def upload_file_page():
    config = get_config()
    return render_template(
        "upload_file.html",
        config=config,
        api_auth_enabled=bool(config.get("api_auth_enabled")),
        api_ui_key=get_ui_api_key(config),
        max_upload_size=app.config.get("MAX_CONTENT_LENGTH", DEFAULT_MAX_UPLOAD_SIZE_MB * BYTES_PER_MB),
    )


@app.route("/api-docs")
@require_ui_auth
def api_docs():
    config = get_config()
    return render_template("api_docs.html", config=config)


@app.route("/logs")
@require_ui_auth
def logs_page():
    source_id = request.args.get("source")
    selected, sources = _select_log_source(source_id)
    payload = _build_log_response(selected)
    return render_template(
        "logs.html",
        title="Logs",
        sources=sources,
        selected_source=selected["id"],
        log_payload=payload,
    )


@app.route("/logs/data")
@require_ui_auth
def logs_data():
    source_id = request.args.get("source")
    selected, _ = _select_log_source(source_id)
    payload = _build_log_response(selected)
    return jsonify(payload)


@app.route("/hosting/delete/<file_id>", methods=["POST"])
@require_ui_auth
def hosting_delete(file_id: str):
    search_term = (request.form.get("search") or "").strip()

    sort_by = request.form.get("sort", "uploaded_at")
    if sort_by not in {"name", "size", "uploaded_at", "expires_at"}:
        sort_by = "uploaded_at"

    sort_order = (request.form.get("order") or "desc").lower()
    if sort_order not in {"asc", "desc"}:
        sort_order = "desc"

    try:
        per_page = int(request.form.get("per_page", 50))
    except (TypeError, ValueError):
        per_page = 50
    per_page = max(1, min(per_page, 200))

    try:
        page = int(request.form.get("page", 1))
    except (TypeError, ValueError):
        page = 1
    page = max(page, 1)

    if delete_file(file_id):
        flash("File deleted successfully.", "success")
        lifecycle_logger.info(
            "file_deleted_manual file_id=%s user=%s ip=%s",
            file_id,
            sanitize_log_value(session.get("ui_username", "anonymous")),
            request.remote_addr or "unknown",
        )
    else:
        flash("File not found.", "error")
        lifecycle_logger.warning(
            "file_delete_missing file_id=%s user=%s ip=%s",
            file_id,
            sanitize_log_value(session.get("ui_username", "anonymous")),
            request.remote_addr or "unknown",
        )

    total_files = count_files(search_term=search_term or None)
    total_pages = max(1, math.ceil(total_files / per_page)) if total_files else 1
    if page > total_pages:
        page = total_pages

    redirect_params = {
        "page": page,
        "per_page": per_page,
        "sort": sort_by,
        "order": sort_order,
    }
    if search_term:
        redirect_params["search"] = search_term

    return redirect(url_for("hosting", **redirect_params))


@app.route("/settings", methods=["GET", "POST"])
@require_ui_auth
def settings():
    config = get_config()
    if request.method == "POST":
        action = request.form.get("action", "update_retention")
        refreshed = False

        if action == "update_retention":
            try:
                retention_min = float(
                    request.form.get("retention_min_hours", config["retention_min_hours"])
                )
                retention_max = float(
                    request.form.get("retention_max_hours", config["retention_max_hours"])
                )
                retention_hours = float(
                    request.form.get("retention_hours", config["retention_hours"])
                )
            except (TypeError, ValueError):
                flash("Please provide valid numbers for retention settings.", "error")
                return render_settings_page(deepcopy(config))

            proposed = deepcopy(config)
            proposed.update(
                {
                    "retention_min_hours": retention_min,
                    "retention_max_hours": retention_max,
                    "retention_hours": retention_hours,
                }
            )

            if retention_min < 0:
                flash("Minimum retention cannot be negative.", "error")
                return render_settings_page(proposed)
            if retention_max <= retention_min:
                flash(
                    "Maximum retention must be greater than the minimum.",
                    "error",
                )
                return render_settings_page(proposed)
            if not (retention_min <= retention_hours <= retention_max):
                flash(
                    "Default retention must fall within the configured bounds.",
                    "error",
                )
                return render_settings_page(proposed)
            save_config(proposed)
            config = get_config(refresh=True)
            refreshed = True
            lifecycle_logger.info(
                "settings_updated retention_min=%.2f retention_max=%.2f retention_default=%.2f",
                retention_min,
                retention_max,
                retention_hours,
            )
            flash("Retention settings updated.", "success")

        elif action == "update_performance":
            # Get all field values including max_upload_size_mb
            field_inputs = {
                "max_upload_size_mb": request.form.get("max_upload_size_mb"),
                "max_concurrent_uploads": request.form.get("max_concurrent_uploads"),
                "cleanup_interval_minutes": request.form.get("cleanup_interval_minutes"),
                "upload_rate_limit_per_hour": request.form.get("upload_rate_limit_per_hour"),
                "login_rate_limit_per_minute": request.form.get("login_rate_limit_per_minute"),
                "download_rate_limit_per_minute": request.form.get("download_rate_limit_per_minute"),
            }

            # Validate all fields are present (including max_upload_size_mb)
            missing_fields = [key for key, value in field_inputs.items() if value in (None, "")]
            if missing_fields:
                flash(f"Missing required fields: {', '.join(missing_fields)}", "error")
                proposed = deepcopy(config)
                for key, value in field_inputs.items():
                    if value is not None and value != "":
                        try:
                            proposed[key] = float(value)
                        except (TypeError, ValueError):
                            pass
                return render_settings_page(proposed)

            # Parse and validate all numeric values
            try:
                parsed_values = {}
                for key, value in field_inputs.items():
                    parsed = float(value)
                    if parsed < 1:
                        flash(f"{key.replace('_', ' ').title()} must be at least 1.", "error")
                        proposed = deepcopy(config)
                        for k, v in field_inputs.items():
                            if v is not None and v != "":
                                try:
                                    proposed[k] = float(v)
                                except (TypeError, ValueError):
                                    pass
                        return render_settings_page(proposed)

                    # Store with appropriate type
                    if key in {"max_concurrent_uploads", "cleanup_interval_minutes",
                               "upload_rate_limit_per_hour", "login_rate_limit_per_minute",
                               "download_rate_limit_per_minute"}:
                        parsed_values[key] = int(parsed)
                    else:
                        # max_upload_size_mb stays as float
                        parsed_values[key] = parsed

            except (TypeError, ValueError) as e:
                flash("Please provide valid positive numbers for all performance settings.", "error")
                proposed = deepcopy(config)
                for key, value in field_inputs.items():
                    if value is not None and value != "":
                        try:
                            proposed[key] = float(value)
                        except (TypeError, ValueError):
                            pass
                return render_settings_page(proposed)

            # Save the config with all validated values
            proposed = deepcopy(config)
            proposed.update(parsed_values)

            # Log the update for debugging
            lifecycle_logger.info(
                "performance_settings_updated max_upload_size=%.2f max_concurrent=%d cleanup_interval=%d upload_rate=%d login_rate=%d download_rate=%d",
                parsed_values.get("max_upload_size_mb", 0),
                parsed_values.get("max_concurrent_uploads", 0),
                parsed_values.get("cleanup_interval_minutes", 0),
                parsed_values.get("upload_rate_limit_per_hour", 0),
                parsed_values.get("login_rate_limit_per_minute", 0),
                parsed_values.get("download_rate_limit_per_minute", 0),
            )

            save_config(proposed)
            config = get_config(refresh=True)
            refreshed = True

            flash("Performance settings updated successfully.", "success")

        elif action == "update_ui_auth":
            auth_enabled = request.form.get("ui_auth_enabled") == "on"
            username = request.form.get("ui_username", config.get("ui_username", "admin")).strip()
            password = request.form.get("ui_password", "")
            confirm = request.form.get("ui_password_confirm", "")

            proposed = deepcopy(config)
            proposed["ui_auth_enabled"] = auth_enabled
            proposed["ui_username"] = username or config.get("ui_username", "admin")

            if auth_enabled and not username:
                flash("Username cannot be empty when UI authentication is enabled.", "error")
                return render_settings_page(proposed)

            if password or confirm:
                if password != confirm:
                    flash("Password confirmation does not match.", "error")
                    return render_settings_page(proposed)
                # Validate password strength
                is_valid, error_msg = validate_password_strength(password)
                if not is_valid:
                    flash(error_msg, "error")
                    return render_settings_page(proposed)
                proposed["ui_password_hash"] = generate_password_hash(password)

            save_config(proposed)
            get_config(refresh=True)
            refreshed = True

            session.pop("ui_authenticated", None)
            session.pop("ui_username", None)

            if auth_enabled:
                flash(
                    "UI authentication updated. Please sign in with the new credentials.",
                    "info",
                )

            lifecycle_logger.info(
                "ui_auth_updated enabled=%s username=%s",
                auth_enabled,
                proposed["ui_username"],
            )
            flash("UI authentication settings updated.", "success")

        elif action == "cleanup_expired_now":
            removed = cleanup_expired_files()
            lifecycle_logger.info("cleanup_expired_manual removed=%d", removed)
            flash(
                f"Expired file cleanup complete. Removed {removed} entr{'y' if removed == 1 else 'ies'}.",
                "success" if removed else "info",
            )

        elif action == "cleanup_orphaned_now":
            removed = cleanup_orphaned_files()
            lifecycle_logger.info("cleanup_orphaned_manual removed=%d", removed)
            flash(
                f"Orphaned file cleanup complete. Removed {removed} item{'s' if removed != 1 else ''}.",
                "success" if removed else "info",
            )

        else:
            flash("Unsupported settings action.", "error")

        if refreshed:
            config = get_config()
        return redirect(url_for("settings"))

    return render_settings_page(config)


@app.route("/apikeys", methods=["GET", "POST"])
@require_ui_auth
def api_keys():
    config = get_config()
    if request.method == "POST":
        action = request.form.get("action", "")
        refreshed = False

        if action == "update_api_auth":
            enable_api_auth = request.form.get("api_auth_enabled") == "on"
            proposed = deepcopy(config)
            proposed["api_auth_enabled"] = enable_api_auth

            auto_key = None
            auto_key_raw = None
            if enable_api_auth and not list(_iter_api_keys(proposed)):
                try:
                    generated_key = _generate_api_key_entry()
                except RuntimeError as error:
                    lifecycle_logger.error(
                        "api_key_generate_failed reason=encrypt_error error=%s",
                        sanitize_log_value(str(error)),
                    )
                    flash(
                        "Unable to generate API key. Please try again later.",
                        "error",
                    )
                    return redirect(url_for("api_keys"))
                auto_key_raw = generated_key.pop("key")
                auto_key = generated_key
                proposed.setdefault("api_keys", []).append(generated_key)
                proposed["api_ui_key_id"] = generated_key["id"]

            save_config(proposed)
            get_config(refresh=True)
            refreshed = True

            lifecycle_logger.info("api_auth_updated enabled=%s", enable_api_auth)
            if auto_key:
                lifecycle_logger.info("api_key_generated id=%s", auto_key["id"])
                if auto_key_raw:
                    _store_pending_api_key_entry(auto_key["id"], auto_key_raw)
                    flash(f"Generated new API key: {escape(auto_key_raw)}", "success")
                    flash("Copy this key now! You won't be able to see it again.", "warning")
                flash(
                    "API authentication enabled. A new key was generated automatically.",
                    "info",
                )
            flash("API authentication settings updated.", "success")

        elif action == "generate_api_key":
            label = request.form.get("api_key_label", "").strip()
            try:
                new_key = _generate_api_key_entry(label)
            except RuntimeError as error:
                lifecycle_logger.error(
                    "api_key_generate_failed reason=encrypt_error error=%s",
                    sanitize_log_value(str(error)),
                )
                flash("Unable to generate API key. Please try again later.", "error")
                return redirect(url_for("api_keys"))
            new_key_raw = new_key.pop("key")
            proposed = deepcopy(config)
            proposed.setdefault("api_keys", []).append(new_key)
            if not proposed.get("api_ui_key_id"):
                proposed["api_ui_key_id"] = new_key["id"]

            save_config(proposed)
            get_config(refresh=True)
            refreshed = True

            lifecycle_logger.info(
                "api_key_generated id=%s label=%s",
                new_key["id"],
                sanitize_log_value(label or ""),
            )
            if new_key_raw:
                _store_pending_api_key_entry(new_key["id"], new_key_raw)
                flash(f"Generated new API key: {escape(new_key_raw)}", "success")
                flash("Copy this key now! You won't be able to see it again.", "warning")

        elif action == "delete_api_key":
            key_id = request.form.get("api_key_id", "").strip()
            proposed = deepcopy(config)
            before = list(_iter_api_keys(proposed))
            remaining = [entry for entry in before if entry.get("id") != key_id]

            if len(remaining) == len(before):
                flash("API key not found.", "error")
                return redirect(url_for("api_keys"))

            proposed["api_keys"] = remaining
            if proposed.get("api_ui_key_id") == key_id:
                proposed["api_ui_key_id"] = remaining[0]["id"] if remaining else ""

            save_config(proposed)
            get_config(refresh=True)
            refreshed = True

            lifecycle_logger.info("api_key_deleted id=%s", key_id)
            flash("API key deleted.", "success")

        elif action == "set_primary_api_key":
            key_id = request.form.get("api_key_id", "").strip()
            proposed = deepcopy(config)
            if not any(entry.get("id") == key_id for entry in _iter_api_keys(proposed)):
                flash("API key not found.", "error")
                return redirect(url_for("api_keys"))

            proposed["api_ui_key_id"] = key_id
            save_config(proposed)
            get_config(refresh=True)
            refreshed = True

            lifecycle_logger.info("api_key_promoted id=%s", key_id)
            flash("Dashboard uploads will use the selected API key.", "success")

        elif action == "acknowledge_api_key":
            pending_id = request.form.get("pending_key_id", "").strip()
            removed = False
            if session.pop("pending_api_key_display_once", None) is not None:
                session.modified = True
                removed = True
            pending = session.get("pending_api_keys")
            if isinstance(pending, list):
                remaining = [
                    entry
                    for entry in pending
                    if isinstance(entry, dict) and entry.get("id") != pending_id
                ]
                if remaining:
                    session["pending_api_keys"] = remaining
                else:
                    session.pop("pending_api_keys", None)
                session.modified = True
                removed = True
            lifecycle_logger.info(
                "api_key_pending_acknowledged key_id=%s", pending_id or "unknown"
            )
            if removed:
                flash("Pending API key hidden. Ensure the value is stored securely.", "info")
            else:
                flash("No pending API key to hide.", "info")

        else:
            flash("Unsupported API key action.", "error")

        if refreshed:
            config = get_config()
        return redirect(url_for("api_keys"))

    return render_api_keys_page(config)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: login_rate_limit_string())
def login():
    config = get_config()
    if not config.get("ui_auth_enabled"):
        next_url = session.pop("ui_next", None)
        return redirect(next_url or url_for("hosting"))

    if ui_user_authenticated():
        next_url = session.pop("ui_next", None)
        return redirect(next_url or url_for("hosting"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        expected_username = config.get("ui_username", "admin")
        password_hash = config.get("ui_password_hash", "")

        if compare_digest(username, expected_username) and check_password_hash(
            password_hash, password
        ):
            old_next = session.get("ui_next")
            session.clear()
            session.modified = True
            session["ui_authenticated"] = True
            session["ui_username"] = expected_username
            session["last_activity"] = time.time()  # Track session age
            flash("Logged in successfully.", "success")
            return redirect(old_next or url_for("hosting"))

        flash("Invalid username or password.", "error")

    return render_template("login.html", config=config)


@app.route("/logout", methods=["POST"])
@require_ui_auth
def logout():
    session.pop("ui_authenticated", None)
    session.pop("ui_username", None)
    flash("You have been logged out.", "success")
    if ui_auth_enabled():
        return redirect(url_for("login"))
    return redirect(url_for("hosting"))


@csrf.exempt
@app.route("/fileupload", methods=["POST"])
@require_api_auth()
@limiter.limit(lambda: upload_rate_limit_string())
def fileupload():
    with upload_slot() as acquired:
        if not acquired:
            return jsonify({"error": "Too many concurrent uploads"}), 503

        origin_error = ensure_same_origin("json")
        if origin_error is not None:
            return origin_error

        if "file" not in request.files:
            app.logger.warning("upload_failed reason=no_file_part")
            return jsonify({"error": "No file part"}), 400

        max_bytes = app.config.get("MAX_CONTENT_LENGTH")
        if max_bytes and request.content_length and request.content_length > max_bytes:
            return jsonify({"error": "File too large"}), 413

        uploads = request.files.getlist("file")
        preflight_failures: List[Dict[str, str]] = []
        valid_uploads = []
        for upload in uploads:
            if not isinstance(upload, FileStorage) or not upload or upload.filename == "":
                continue
            filename = secure_filename(upload.filename)
            if not filename:
                preflight_failures.append(
                    {
                        "filename": upload.filename or "",
                        "reason": "invalid_filename",
                        "detail": "Filename could not be sanitized",
                    }
                )
                continue

            is_valid_name, name_error = validate_filename(filename)
            if not is_valid_name:
                preflight_failures.append(
                    {
                        "filename": filename,
                        "reason": "invalid_filename",
                        "detail": name_error or "Invalid filename",
                    }
                )
                continue
            if not validate_upload_mimetype(filename, upload.content_type):
                lifecycle_logger.warning(
                    "upload_suspicious_mimetype filename=%s declared=%s",
                    sanitize_log_value(filename),
                    upload.content_type,
                )
            if is_dangerous_content_type(upload.content_type):
                lifecycle_logger.warning(
                    "upload_blocked_dangerous_content filename=%s content_type=%s",
                    sanitize_log_value(filename),
                    upload.content_type,
                )
                preflight_failures.append(
                    {
                        "filename": filename,
                        "reason": "dangerous_content_type",
                        "detail": f"Executable content type '{upload.content_type}' is not allowed",
                    }
                )
                continue
            if max_bytes and upload.content_length and upload.content_length > max_bytes:
                preflight_failures.append(
                    {
                        "filename": filename,
                        "reason": "too_large",
                    }
                )
                continue
            valid_uploads.append((upload, filename))

        if not valid_uploads:
            if preflight_failures:
                status_code = (
                    413
                    if any(entry.get("reason") == "too_large" for entry in preflight_failures)
                    else 400
                )
                return (
                    jsonify(
                        {"message": "Failed to upload files.", "errors": preflight_failures}
                    ),
                    status_code,
                )
            app.logger.warning("upload_failed reason=no_file_selected")
            return jsonify({"error": "No file selected"}), 400

        config = get_config()
        quota_limit_bytes = storage_quota_limit_bytes()
        if quota_limit_bytes is not None:
            with quota_lock:
                current_usage = int(
                    get_storage_statistics().get("total_bytes", 0)
                )
                if current_usage >= quota_limit_bytes:
                    lifecycle_logger.warning(
                        "upload_quota_exceeded usage=%d limit=%d",
                        current_usage,
                        quota_limit_bytes,
                    )
                    return jsonify({"error": "Storage quota exceeded"}), 507
        payload = request.get_json(silent=True) if request.is_json else None

        permanent = False
        permanent_candidates = [
            request.form.get("permanent"),
            request.args.get("permanent"),
            (payload or {}).get("permanent") if isinstance(payload, dict) else None,
        ]
        for candidate in permanent_candidates:
            if candidate is None:
                continue
            if isinstance(candidate, str):
                permanent = candidate.lower() in {"1", "true", "yes", "on"}
            else:
                permanent = bool(candidate)
            break

        if not permanent:
            try:
                retention_hours = resolve_retention(
                    config,
                    request.form.get("retention_hours"),
                    request.args.get("retention_hours"),
                    (payload or {}).get("retention_hours") if isinstance(payload, dict) else None,
                )
            except RetentionValidationError as error:
                allowed_range = error.allowed_range or [
                    config["retention_min_hours"],
                    config["retention_max_hours"],
                ]
                app.logger.warning(
                    "upload_failed reason=retention_invalid value=%s min=%.2f max=%.2f",
                    request.form.get("retention_hours")
                    or request.args.get("retention_hours")
                    or (payload or {}).get("retention_hours"),
                    allowed_range[0],
                    allowed_range[1],
                )
                return jsonify(error.to_payload()), 400
        else:
            retention_hours = 0

        results = []
        failures: List[Dict[str, str]] = []
        successful_uploads: List[Tuple[str, str]] = []
        for upload_storage, filename in valid_uploads:
            upload_path = None
            temp_path = None
            file_id = str(uuid.uuid4())
            stored_name = f"{int(time.time())}_{uuid.uuid4().hex}_{filename}"
            with upload_stream_handler(upload_storage) as upload:
                try:
                    # Pre-check quota if Content-Length is available (prevents wasted I/O)
                    if quota_limit_bytes is not None and upload.content_length:
                        try:
                            with quota_lock:
                                enforce_storage_quota_for_size(upload.content_length)
                        except StorageQuotaExceededError as quota_error:
                            failures.append(
                                {
                                    "filename": filename,
                                    "reason": "quota_exceeded",
                                    "detail": "Storage quota exceeded",
                                }
                            )
                            lifecycle_logger.warning(
                                "upload_quota_precheck_failed filename=%s size=%d usage=%d limit=%d",
                                sanitize_log_value(filename),
                                upload.content_length,
                                quota_error.current_usage,
                                quota_error.quota_limit,
                            )
                            continue

                    upload_path = get_storage_path(file_id, stored_name, ensure_parent=True)
                    temp_path = upload_path.with_name(f"{upload_path.name}.tmp")
                    if hasattr(upload.stream, "seek"):
                        try:
                            upload.stream.seek(0)
                        except (OSError, IOError):
                            pass
                    written = 0
                    too_large = False
                    # Set restrictive umask for temp file creation
                    old_umask = os.umask(0o077)
                    try:
                        with temp_path.open("wb") as destination:
                            # Set file permissions to be read/write for owner only
                            try:
                                temp_path.chmod(0o600)
                            except OSError:
                                pass

                            while True:
                                chunk = upload.stream.read(CHUNK_SIZE_BYTES)
                                if not chunk:
                                    break
                                if max_bytes and written + len(chunk) > max_bytes:
                                    too_large = True
                                    break
                                destination.write(chunk)
                                written += len(chunk)
                    finally:
                        os.umask(old_umask)

                    if too_large:
                        if temp_path and temp_path.exists():
                            parent = temp_path.parent
                            temp_path.unlink(missing_ok=True)
                            prune_empty_upload_dirs(parent)
                        failures.append(
                            {
                                "filename": filename,
                                "reason": "too_large",
                            }
                        )
                        continue

                    temp_path.replace(upload_path)
                    size = written if written else upload_path.stat().st_size

                    try:
                        with quota_lock:
                            enforce_storage_quota_for_size(size)
                            file_id = register_file(
                                original_name=filename,
                                stored_name=stored_name,
                                content_type=upload.content_type,
                                size=size,
                                retention_hours=retention_hours,
                                file_id=file_id,
                                permanent=permanent,
                            )
                    except StorageQuotaExceededError as quota_error:
                        if upload_path.exists():
                            upload_path.unlink(missing_ok=True)
                            prune_empty_upload_dirs(upload_path.parent)
                        failures.append(
                            {
                                "filename": filename,
                                "reason": "quota_exceeded",
                                "detail": "Storage quota exceeded",
                            }
                        )
                        lifecycle_logger.warning(
                            "upload_quota_exceeded file_id=%s filename=%s usage=%d limit=%d",
                            file_id,
                            sanitize_log_value(filename),
                            quota_error.current_usage,
                            quota_error.quota_limit,
                        )
                        continue
                except Exception as error:
                    lifecycle_logger.exception(
                        "file_upload_failed file_id=%s filename=%s",
                        file_id,
                        sanitize_log_value(filename),
                    )
                    if temp_path and temp_path.exists():
                        temp_path.unlink(missing_ok=True)
                    if upload_path and upload_path.exists():
                        upload_path.unlink(missing_ok=True)
                        prune_empty_upload_dirs(upload_path.parent)
                    # Rollback all successful uploads on any failure
                    failed_rollbacks = rollback_successful_uploads(successful_uploads)
                    if failed_rollbacks:
                        lifecycle_logger.error(
                            "rollback_incomplete file_ids=%s",
                            [sanitize_log_value(value) for value in failed_rollbacks],
                        )
                    failures.append(
                        {
                            "filename": filename,
                            "reason": "internal_error",
                            "detail": str(error),
                        }
                    )
                    # Add all previous successes to failures since we rolled them back
                    for success_file_id, _ in successful_uploads:
                        success_record = get_file(success_file_id)
                        if success_record:
                            failures.append(
                                {
                                    "filename": success_record["original_name"],
                                    "reason": "rolled_back",
                                    "detail": "Rolled back due to subsequent upload failure",
                                }
                            )
                    # Clear results since we rolled everything back
                    results = []
                    successful_uploads = []
                    # Stop processing more files
                    break

            record = get_file(file_id)
            if not record:
                lifecycle_logger.error(
                    "file_registration_failed file_id=%s filename=%s",
                    file_id,
                    sanitize_log_value(filename),
                )
                if upload_path and upload_path.exists():
                    upload_path.unlink(missing_ok=True)
                    prune_empty_upload_dirs(upload_path.parent)
                remove_orphaned_record(file_id)
                failures.append(
                    {
                        "filename": filename,
                        "reason": "registration_failed",
                    }
                )
                continue

            expires_at = record["expires_at"]
            uploaded_at = record["uploaded_at"]
            raw_download_url = (
                url_for("serve_raw_file", direct_path=record["direct_path"], _external=True)
                if record["direct_path"]
                else ""
            )

            download_url = url_for("download", file_id=file_id, _external=True)
            direct_download_url = url_for(
                "direct_download", file_id=file_id, filename=filename, _external=True
            )
            lifecycle_logger.info(
                "file_uploaded file_id=%s filename=%s size=%d retention_hours=%.2f",
                file_id,
                sanitize_log_value(filename),
                size,
                retention_hours,
            )
            results.append(
                {
                    "id": file_id,
                    "filename": filename,
                    "size": size,
                    "download_url": download_url,
                    "retention_hours": retention_hours if not permanent else None,
                    "permanent": permanent,
                    "uploaded_at": uploaded_at,
                    "expires_at": expires_at,
                    "expires_at_iso": isoformat_utc(expires_at)
                    if not permanent
                    else None,
                    "direct_download_url": direct_download_url,
                    "raw_download_url": raw_download_url,
                    "raw_download_path": record["direct_path"],
                    "message": "File uploaded successfully.",
                }
            )
            successful_uploads.append((file_id, stored_name))

        if failures and not results:
            # All uploads failed
            if any(entry.get("reason") == "quota_exceeded" for entry in failures):
                status = 507
            elif any(entry.get("reason") == "too_large" for entry in failures):
                status = 413
            else:
                status = 400
            return jsonify({
                "message": "All file uploads failed.",
                "errors": failures,
            }), status

        if failures:
            # Partial success: some uploads succeeded, some failed
            status = 207  # Multi-Status
            payload: Dict[str, Any] = {
                "message": f"Partial success: {len(results)} file(s) uploaded, {len(failures)} failed.",
                "errors": failures,
                "successful": len(results),
                "files": results,
            }
            return jsonify(payload), status

        if not results:
            return jsonify({"message": "No files were uploaded.", "errors": []}), 400

        if len(results) == 1:
            return jsonify(results[0]), 201

        response_payload: Dict[str, object] = {
            "message": f"Uploaded {len(results)} files successfully.",
            "files": results,
            "retention_hours": retention_hours if not permanent else None,
            "permanent": permanent,
        }
        return jsonify(response_payload), 201


@app.route("/download/<file_id>")
@limiter.limit(lambda: download_rate_limit_string())
def download(file_id: str):
    record = get_file(file_id)
    if not record:
        lifecycle_logger.warning("file_download_missing file_id=%s", file_id)
        abort(404)
    file_path = get_storage_path(file_id, record["stored_name"])
    if not file_path.exists():
        lifecycle_logger.warning(
            "file_download_missing_path file_id=%s stored_name=%s",
            file_id,
            sanitize_log_value(record["stored_name"]),
        )
        abort(404)
    if record["expires_at"] < time.time():
        lifecycle_logger.info("file_download_blocked_expired file_id=%s", file_id)
        # Let the cleanup job handle deletion to avoid race conditions
        abort(404)
    lifecycle_logger.info("file_downloaded file_id=%s", file_id)
    try:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=record["original_name"],
        )
    except FileNotFoundError:
        lifecycle_logger.warning(
            "file_download_missing_race file_id=%s stored_name=%s",
            file_id,
            sanitize_log_value(record["stored_name"]),
        )
        abort(404)
    except (OSError, IOError) as e:
        lifecycle_logger.exception(
            "file_download_error file_id=%s stored_name=%s error=%s",
            file_id,
            sanitize_log_value(record["stored_name"]),
            str(e),
        )
        abort(500)


@app.route("/files/<file_id>/<path:filename>")
@limiter.limit(lambda: download_rate_limit_string())
def direct_download(file_id: str, filename: str):
    record = get_file(file_id)
    if not record:
        lifecycle_logger.warning("file_direct_missing file_id=%s", file_id)
        abort(404)
    if not compare_digest(filename, record["original_name"]):
        lifecycle_logger.warning(
            "file_direct_name_mismatch file_id=%s requested=%s stored=%s",
            file_id,
            sanitize_log_value(filename),
            sanitize_log_value(record["original_name"]),
        )
        abort(404)
    file_path = get_storage_path(file_id, record["stored_name"])
    if not file_path.exists():
        lifecycle_logger.warning(
            "file_direct_missing_path file_id=%s stored_name=%s",
            file_id,
            sanitize_log_value(record["stored_name"]),
        )
        abort(404)
    if record["expires_at"] < time.time():
        lifecycle_logger.info("file_direct_blocked_expired file_id=%s", file_id)
        # Let the cleanup job handle deletion to avoid race conditions
        abort(404)
    lifecycle_logger.info("file_direct_downloaded file_id=%s", file_id)
    try:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=record["original_name"],
        )
    except FileNotFoundError:
        lifecycle_logger.warning(
            "file_direct_missing_race file_id=%s stored_name=%s",
            file_id,
            sanitize_log_value(record["stored_name"]),
        )
        abort(404)


@csrf.exempt
@app.route("/2.0/files/content", methods=["POST"])
@require_api_auth("box")
@limiter.limit(lambda: upload_rate_limit_string())
def box_upload_files():
    with upload_slot() as acquired:
        if not acquired:
            return _box_error(
                "service_busy", "Too many concurrent uploads. Try again shortly.", status=503
            )

        origin_error = ensure_same_origin("box")
        if origin_error is not None:
            return origin_error

        config = get_config()
        uploads = request.files.getlist("file")
        if not uploads:
            lifecycle_logger.warning("box_upload_failed reason=no_file_part")
            return _box_error("no_file", "No file part found in the request.")

        max_bytes = app.config.get("MAX_CONTENT_LENGTH")
        if max_bytes and request.content_length and request.content_length > max_bytes:
            return _box_error(
                "file_too_large",
                "The uploaded file exceeds the allowed size.",
                status=413,
            )

        attributes_raw = request.form.get("attributes")
        attributes: Dict[str, object] = {}
        if attributes_raw:
            try:
                attributes = json.loads(attributes_raw)
            except json.JSONDecodeError:
                lifecycle_logger.warning("box_upload_failed reason=invalid_attributes")
                return _box_error(
                    "invalid_attributes",
                    "The provided attributes payload could not be parsed as JSON.",
                )

        retention_candidates = (
            request.headers.get("X-Localhosting-Retention-Hours"),
            request.form.get("retention_hours"),
            request.args.get("retention_hours"),
            (
                str(attributes.get("retention_hours"))
                if isinstance(attributes, dict)
                and attributes.get("retention_hours") is not None
                else None
            ),
        )

        permanent_header = request.headers.get("X-Localhosting-Permanent")
        permanent = (
            permanent_header.lower() in {"1", "true", "yes", "on"}
            if isinstance(permanent_header, str) and permanent_header
            else False
        )

        if not permanent:
            try:
                retention_hours = resolve_retention(config, *retention_candidates)
            except RetentionValidationError as error:
                allowed_range = error.allowed_range or [
                    config["retention_min_hours"],
                    config["retention_max_hours"],
                ]
                lifecycle_logger.warning(
                    "box_upload_failed reason=retention_invalid min=%.2f max=%.2f",
                    allowed_range[0],
                    allowed_range[1],
                )
                context = {
                    "allowed_range": f"{allowed_range[0]:.2f}-{allowed_range[1]:.2f}",
                }
                return _box_error("retention_invalid", str(error), context=context)
        else:
            retention_hours = 0

        quota_limit_bytes = storage_quota_limit_bytes()
        if quota_limit_bytes is not None:
            with quota_lock:
                current_usage = int(
                    get_storage_statistics().get("total_bytes", 0)
                )
                if current_usage >= quota_limit_bytes:
                    return _box_error(
                        "storage_quota_exceeded",
                        "Storage quota exceeded.",
                        status=507,
                    )

        entries = []
        successful_uploads: List[Tuple[str, str]] = []
        for upload in uploads:
            if (
                not isinstance(upload, FileStorage)
                or not upload
                or upload.filename == ""
            ):
                continue

            if max_bytes and upload.content_length and upload.content_length > max_bytes:
                return _box_error(
                    "file_too_large",
                    "The uploaded file exceeds the allowed size.",
                    status=413,
                )

            requested_name = None
            if isinstance(attributes, dict):
                requested_name = attributes.get("name")

            original_name = requested_name or upload.filename or f"upload-{uuid.uuid4().hex}"
            filename = secure_filename(original_name)
            if not filename:
                filename = (
                    secure_filename(upload.filename or "upload")
                    or f"upload-{uuid.uuid4().hex}"
                )

            is_valid_name, name_error = validate_filename(filename)
            if not is_valid_name:
                lifecycle_logger.warning(
                    "box_upload_invalid_filename filename=%s error=%s",
                    sanitize_log_value(filename),
                    sanitize_log_value(name_error or "invalid"),
                )
                continue

            file_id = str(uuid.uuid4())
            stored_name = f"{int(time.time())}_{uuid.uuid4().hex}_{filename}"
            upload_path = get_storage_path(file_id, stored_name, ensure_parent=True)
            temp_path = upload_path.with_name(f"{upload_path.name}.tmp")

            hash_sha1 = hashlib.sha1()
            written = 0
            if hasattr(upload.stream, "seek"):
                try:
                    upload.stream.seek(0)
                except (OSError, IOError):
                    pass

            if not validate_upload_mimetype(filename, upload.content_type):
                lifecycle_logger.warning(
                    "box_upload_suspicious_mimetype filename=%s declared=%s",
                    sanitize_log_value(filename),
                    upload.content_type,
                )

            content_type: Optional[str] = None
            with upload_stream_handler(upload) as managed_upload:
                try:
                    with temp_path.open("wb") as destination:
                        while True:
                            chunk = managed_upload.stream.read(CHUNK_SIZE_BYTES)
                            if not chunk:
                                break
                            destination.write(chunk)
                            hash_sha1.update(chunk)
                            written += len(chunk)
                            if max_bytes and written > max_bytes:
                                raise ValueError("file too large")

                    temp_path.replace(upload_path)
                    size = written if written else upload_path.stat().st_size
                    if max_bytes and size > max_bytes:
                        raise ValueError("file too large")
                    content_type = managed_upload.content_type
                except ValueError:
                    if temp_path.exists():
                        temp_path.unlink(missing_ok=True)
                    if upload_path.exists():
                        upload_path.unlink(missing_ok=True)
                        prune_empty_upload_dirs(upload_path.parent)
                    failed_rollbacks = rollback_successful_uploads(successful_uploads)
                    if failed_rollbacks:
                        lifecycle_logger.error(
                            "rollback_incomplete file_ids=%s",
                            [sanitize_log_value(value) for value in failed_rollbacks],
                        )
                    return _box_error(
                        "file_too_large",
                        "The uploaded file exceeds the allowed size.",
                        status=413,
                        context={"rollback_failed_ids": failed_rollbacks}
                        if failed_rollbacks
                        else None,
                    )
                except Exception as error:
                    lifecycle_logger.exception(
                        "box_upload_failed reason=internal_error filename=%s",
                        sanitize_log_value(filename),
                    )
                    if temp_path.exists():
                        temp_path.unlink(missing_ok=True)
                    if upload_path.exists():
                        upload_path.unlink(missing_ok=True)
                        prune_empty_upload_dirs(upload_path.parent)
                    failed_rollbacks = rollback_successful_uploads(successful_uploads)
                    if failed_rollbacks:
                        lifecycle_logger.error(
                            "rollback_incomplete file_ids=%s",
                            [sanitize_log_value(value) for value in failed_rollbacks],
                        )
                    return _box_error(
                        "internal_error",
                        "Failed to store uploaded file.",
                        status=500,
                        context={"rollback_failed_ids": failed_rollbacks}
                        if failed_rollbacks
                        else None,
                    )

            content_type = content_type or upload.content_type

            try:
                with quota_lock:
                    enforce_storage_quota_for_size(size)
                    file_id = register_file(
                        original_name=filename,
                        stored_name=stored_name,
                        content_type=content_type,
                        size=size,
                        retention_hours=retention_hours,
                        file_id=file_id,
                        permanent=permanent,
                    )
            except StorageQuotaExceededError as quota_error:
                if upload_path.exists():
                    upload_path.unlink(missing_ok=True)
                    prune_empty_upload_dirs(upload_path.parent)
                lifecycle_logger.warning(
                    "box_upload_quota_exceeded file_id=%s filename=%s usage=%d limit=%d",
                    file_id,
                    sanitize_log_value(filename),
                    quota_error.current_usage,
                    quota_error.quota_limit,
                )
                failed_rollbacks = rollback_successful_uploads(successful_uploads)
                if failed_rollbacks:
                    lifecycle_logger.error(
                        "rollback_incomplete file_ids=%s",
                        [sanitize_log_value(value) for value in failed_rollbacks],
                    )
                return _box_error(
                    "storage_quota_exceeded",
                    "Storage quota exceeded.",
                    status=507,
                    context={"rollback_failed_ids": failed_rollbacks}
                    if failed_rollbacks
                    else None,
                )
            successful_uploads.append((file_id, stored_name))
            record = get_file(file_id)
            if not record:
                if upload_path.exists():
                    upload_path.unlink(missing_ok=True)
                    prune_empty_upload_dirs(upload_path.parent)
                remove_orphaned_record(file_id)
                lifecycle_logger.error(
                    "box_upload_failed reason=registration_missing file_id=%s",
                    file_id,
                )
                failed_rollbacks = rollback_successful_uploads(successful_uploads)
                if failed_rollbacks:
                    lifecycle_logger.error(
                        "rollback_incomplete file_ids=%s",
                        [sanitize_log_value(value) for value in failed_rollbacks],
                    )
                return _box_error(
                    "internal_error",
                    f"Failed to register file {original_name}",
                    status=500,
                    context={"rollback_failed_ids": failed_rollbacks} if failed_rollbacks else None,
                )

            download_url = url_for("download", file_id=file_id, _external=True)
            direct_download_url = url_for(
                "direct_download", file_id=file_id, filename=record["original_name"], _external=True
            )
            raw_path_value = record["direct_path"] if record["direct_path"] else None
            raw_download_url = (
                url_for("serve_raw_file", direct_path=raw_path_value, _external=True)
                if raw_path_value
                else None
            )

            iso_timestamp = isoformat_utc(record["uploaded_at"])
            entry = {
                "type": "file",
                "id": file_id,
                "name": record["original_name"],
                "size": size,
                "sha1": hash_sha1.hexdigest(),
                "etag": file_id,
                "sequence_id": "0",
                "created_at": iso_timestamp,
                "modified_at": iso_timestamp,
                "content_modified_at": iso_timestamp,
                "file_version": {
                    "type": "file_version",
                    "id": f"{file_id}_v1",
                    "sha1": hash_sha1.hexdigest(),
                },
                "path_collection": {
                    "total_count": 1,
                    "entries": [
                        {
                            "type": "folder",
                            "id": "0",
                            "name": "Uploads",
                        }
                    ],
                },
                "shared_link": {
                    "download_url": download_url,
                    "direct_download_url": direct_download_url,
                    "raw_download_url": raw_download_url,
                },
                "expires_at": record["expires_at"],
                "expires_at_iso": isoformat_utc(record["expires_at"]),
            }
            entries.append(entry)
            lifecycle_logger.info(
                "file_uploaded_box file_id=%s filename=%s size=%d retention_hours=%.2f",
                file_id,
                sanitize_log_value(record["original_name"]),
                size,
                retention_hours,
            )

        if not entries:
            return _box_error("no_valid_files", "No valid files were provided.")

        # Always return entries array with total_count for consistency
        response = jsonify({"entries": entries, "total_count": len(entries)})
        response.status_code = 201
        return response


@app.route("/2.0/files/<file_id>/content", methods=["GET"])
@require_api_auth("box")
@limiter.limit(lambda: download_rate_limit_string())
def box_download_file(file_id: str):
    record = get_file(file_id)
    if not record:
        lifecycle_logger.warning("box_download_missing file_id=%s", file_id)
        return _box_error("not_found", "File not found.", status=404)
    file_path = get_storage_path(record["id"], record["stored_name"])
    if not file_path.exists():
        lifecycle_logger.warning(
            "box_download_missing_path file_id=%s stored_name=%s",
            file_id,
            sanitize_log_value(record["stored_name"]),
        )
        return _box_error("not_found", "File content is unavailable.", status=404)

    if record["expires_at"] < time.time():
        lifecycle_logger.info("box_download_blocked_expired file_id=%s", file_id)
        # Don't delete here - let cleanup job handle it to avoid race conditions
        return _box_error("expired", "The requested file has expired.", status=404)

    lifecycle_logger.info("file_downloaded_box file_id=%s", file_id)
    mimetype = record["content_type"]
    try:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=record["original_name"],
            mimetype=mimetype or None,
        )
    except FileNotFoundError:
        lifecycle_logger.warning(
            "box_download_missing_race file_id=%s stored_name=%s",
            file_id,
            sanitize_log_value(record["stored_name"]),
        )
        return _box_error("not_found", "File not found.", status=404)


@app.route("/2.0/file_requests/<file_id>", methods=["GET"])
@require_api_auth("box")
def box_file_request(file_id: str):
    record = get_file(file_id)
    if not record:
        lifecycle_logger.warning("box_file_request_missing file_id=%s", file_id)
        return _box_error("not_found", "File request not found.", status=404)

    if record["expires_at"] < time.time():
        lifecycle_logger.info("box_file_request_expired file_id=%s", file_id)
        # Don't delete here - let cleanup job handle it to avoid race conditions
        return _box_error("expired", "The requested file has expired.", status=404)

    download_url = url_for("box_download_file", file_id=file_id, _external=True)
    upload_url = url_for("box_upload_files", _external=True)
    response_payload = {
        "type": "file_request",
        "id": file_id,
        "title": record["original_name"],
        "description": "Local Hosting API generated file request.",
        "status": "active",
        "is_enabled": True,
        "folder": {
            "type": "folder",
            "id": "0",
            "name": "Uploads",
        },
        "url": download_url,
        "upload_url": upload_url,
        "created_at": isoformat_utc(record["uploaded_at"]),
        "updated_at": isoformat_utc(record["uploaded_at"]),
        "expires_at": isoformat_utc(record["expires_at"]),
    }
    lifecycle_logger.info("box_file_request_retrieved file_id=%s", file_id)
    return jsonify(response_payload)


@app.route("/<path:direct_path>")
@limiter.limit(lambda: download_rate_limit_string())
def serve_raw_file(direct_path: str):
    normalized = direct_path.strip("/")
    if not normalized:
        abort(404)

    try:
        decoded = unquote(normalized)
        # Double decode to catch double-encoded attempts like %252e%252e
        decoded = unquote(decoded)
    except Exception:
        abort(400)

    normalized = decoded.strip("/")
    if not normalized:
        abort(404)

    # Check for path traversal patterns (including encoded variations)
    dangerous_patterns = ['..', '%2e%2e', '%252e%252e', '..\\', '%2e%2e%5c', '%2e%2e%2f', '.%2e']
    normalized_lower = normalized.lower()
    if any(pattern in normalized_lower for pattern in dangerous_patterns):
        lifecycle_logger.warning(
            "path_traversal_attempt path=%s ip=%s",
            sanitize_log_value(direct_path),
            request.remote_addr or "unknown",
        )
        abort(404)

    if "\\" in normalized:
        lifecycle_logger.warning(
            "path_traversal_attempt path=%s ip=%s",
            sanitize_log_value(direct_path),
            request.remote_addr or "unknown",
        )
        abort(404)

    path_candidate = PurePosixPath(normalized)
    if path_candidate.is_absolute() or any(part in {"..", ""} for part in path_candidate.parts):
        lifecycle_logger.warning(
            "path_traversal_attempt path=%s ip=%s",
            sanitize_log_value(direct_path),
            request.remote_addr or "unknown",
        )
        abort(404)

    normalized = path_candidate.as_posix()

    first_segment = normalized.split("/", 1)[0]
    first_segment_lower = first_segment.lower()

    if "/" not in normalized:
        endpoint = RESERVED_ROUTE_ENDPOINTS.get(first_segment_lower)
        if endpoint:
            canonical = url_for(endpoint)
            if request.path != canonical:
                return redirect(canonical, code=308)

    if first_segment_lower in RESERVED_DIRECT_PATHS:
        abort(404)

    record = get_file_by_direct_path(normalized)
    if not record:
        lifecycle_logger.warning(
            "file_raw_missing direct_path=%s", sanitize_log_value(normalized)
        )
        abort(404)
    file_path = get_storage_path(record["id"], record["stored_name"])
    if not file_path.exists():
        lifecycle_logger.warning(
            "file_raw_missing_path file_id=%s stored_name=%s",
            record["id"],
            sanitize_log_value(record["stored_name"]),
        )
        abort(404)

    try:
        resolved_path = file_path.resolve()
        uploads_root = UPLOADS_DIR.resolve()
        if uploads_root not in resolved_path.parents and resolved_path != uploads_root:
            lifecycle_logger.error(
                "path_traversal_detected file_id=%s path=%s",
                record["id"],
                resolved_path,
            )
            abort(404)
    except Exception:
        abort(404)
    if record["expires_at"] < time.time():
        lifecycle_logger.info(
            "file_raw_blocked_expired file_id=%s direct_path=%s",
            record["id"],
            sanitize_log_value(normalized),
        )
        # Let the cleanup job handle deletion to avoid race conditions
        abort(404)

    lifecycle_logger.info(
        "file_raw_downloaded file_id=%s direct_path=%s",
        record["id"],
        sanitize_log_value(normalized),
    )
    mimetype = record["content_type"] or None
    try:
        # Use resolved_path to prevent TOCTOU symlink attacks
        return send_file(
            resolved_path,
            as_attachment=False,
            download_name=record["original_name"],
            mimetype=mimetype,
        )
    except FileNotFoundError:
        lifecycle_logger.warning(
            "file_raw_missing_race file_id=%s stored_name=%s",
            record["id"],
            sanitize_log_value(record["stored_name"]),
        )
        abort(404)


@csrf.exempt
@app.route("/s3/<bucket>", methods=["POST"])
@require_api_auth("s3")
@limiter.limit(lambda: upload_rate_limit_string())
def s3_multipart_upload(bucket: str):
    with upload_slot() as acquired:
        if not acquired:
            return _s3_error_response(
                "ServiceUnavailable",
                "Too many concurrent uploads.",
                bucket=bucket,
                status_code=503,
            )

        origin_error = ensure_same_origin("s3")
        if origin_error is not None:
            return origin_error

        config = get_config()
        upload = request.files.get("file")
        if not isinstance(upload, FileStorage):
            return _s3_error_response(
                "InvalidArgument",
                "Missing file field 'file'.",
                bucket=bucket,
            )

        if upload.filename is None:
            return _s3_error_response(
                "InvalidArgument",
                "Missing filename for uploaded file.",
                bucket=bucket,
            )

        max_bytes = app.config.get("MAX_CONTENT_LENGTH")
        if max_bytes and request.content_length and request.content_length > max_bytes:
            return _s3_error_response(
                "EntityTooLarge",
                "The uploaded file exceeds the allowed size.",
                bucket=bucket,
                status_code=413,
            )

        key = (
            request.form.get("key")
            or request.form.get("Key")
            or upload.filename
            or f"upload-{uuid.uuid4().hex}"
        )
        if "${filename}" in key and upload.filename:
            substitution = secure_filename(upload.filename)
            if not substitution:
                return _s3_error_response(
                    "InvalidArgument",
                    "Filename contains only invalid characters",
                    bucket=bucket,
                    status_code=400,
                )
            key = key.replace("${filename}", substitution)

        # Path validation to prevent traversal attacks
        # Allow forward slashes for S3 hierarchical keys, but block path traversal attempts
        if (
            ".." in key
            or "\\" in key
            or key.startswith("/")
            or "//" in key
            or "\x00" in key
            or key.endswith("/")
        ):
            return _s3_error_response(
                "InvalidArgument",
                "Key contains invalid path components (no path traversal, backslashes, null bytes, or multiple slashes allowed)",
                bucket=bucket,
                status_code=400,
            )

        original_name = (
            request.form.get("x-amz-meta-original-filename")
            or request.form.get("X-Amz-Meta-Original-Filename")
            or os.path.basename(key)
            or upload.filename
            or f"upload-{uuid.uuid4().hex}"
        )
        filename = secure_filename(original_name)
        if not filename:
            filename = (
                secure_filename(upload.filename or "upload")
                or f"upload-{uuid.uuid4().hex}"
            )

        is_valid_name, name_error = validate_filename(filename)
        if not is_valid_name:
            lifecycle_logger.warning(
                "s3_upload_invalid_filename bucket=%s key=%s filename=%s error=%s",
                bucket,
                sanitize_log_value(key),
                sanitize_log_value(filename),
                sanitize_log_value(name_error or "invalid"),
            )
            return _s3_error_response(
                "InvalidArgument",
                name_error or "Invalid filename",
                bucket=bucket,
                key=key,
                status_code=400,
            )

        quota_limit_bytes = storage_quota_limit_bytes()
        if quota_limit_bytes is not None:
            with quota_lock:
                current_usage = int(
                    get_storage_statistics().get("total_bytes", 0)
                )
                if current_usage >= quota_limit_bytes:
                    lifecycle_logger.warning(
                        "s3_upload_quota_exceeded bucket=%s key=%s",
                        bucket,
                        sanitize_log_value(key),
                    )
                    return _s3_error_response(
                        "InsufficientStorage",
                        "Storage quota exceeded.",
                        bucket=bucket,
                        key=key,
                        status_code=507,
                    )

        if not validate_upload_mimetype(filename, upload.content_type):
            lifecycle_logger.warning(
                "s3_upload_suspicious_mimetype bucket=%s key=%s filename=%s declared=%s",
                bucket,
                sanitize_log_value(key),
                sanitize_log_value(filename),
                upload.content_type,
            )

        file_id = str(uuid.uuid4())
        stored_name = f"{int(time.time())}_{uuid.uuid4().hex}_{filename}"
        upload_path = get_storage_path(file_id, stored_name, ensure_parent=True)
        temp_path = upload_path.with_name(f"{upload_path.name}.tmp")

        hash_md5 = hashlib.md5()
        written = 0
        if hasattr(upload.stream, "seek"):
            try:
                upload.stream.seek(0)
            except (OSError, IOError):
                pass

        size = 0
        content_type: Optional[str] = None
        with upload_stream_handler(upload) as managed_upload:
            try:
                with temp_path.open("wb") as destination:
                    while True:
                        chunk = managed_upload.stream.read(1024 * 1024)
                        if not chunk:
                            break
                        destination.write(chunk)
                        hash_md5.update(chunk)
                        written += len(chunk)
                        if max_bytes and written > max_bytes:
                            raise ValueError("file too large")

                temp_path.replace(upload_path)
                size = written if written else upload_path.stat().st_size
                if max_bytes and size > max_bytes:
                    raise ValueError("file too large")
                content_type = managed_upload.content_type
            except ValueError:
                if temp_path.exists():
                    temp_path.unlink(missing_ok=True)
                if upload_path.exists():
                    upload_path.unlink(missing_ok=True)
                    prune_empty_upload_dirs(upload_path.parent)
                return _s3_error_response(
                    "EntityTooLarge",
                    "The uploaded file exceeds the allowed size.",
                    bucket=bucket,
                    key=key,
                    status_code=413,
                )
            except Exception as error:
                lifecycle_logger.exception(
                    "s3_upload_failed reason=write_error bucket=%s key=%s",
                    bucket,
                    sanitize_log_value(key),
                )
                if temp_path.exists():
                    temp_path.unlink(missing_ok=True)
                if upload_path.exists():
                    upload_path.unlink(missing_ok=True)
                    prune_empty_upload_dirs(upload_path.parent)
                return _s3_error_response(
                    "InternalError",
                    "Failed to store uploaded file.",
                    bucket=bucket,
                    key=key,
                    status_code=500,
                )

        content_type = content_type or upload.content_type

        permanent_header = request.form.get("x-amz-meta-permanent") or request.headers.get(
            "x-amz-meta-permanent"
        )
        permanent = (
            permanent_header.lower() in {"1", "true", "yes", "on"}
            if isinstance(permanent_header, str) and permanent_header
            else False
        )

        if not permanent:
            try:
                retention_hours = resolve_retention(
                    config,
                    request.form.get("x-amz-meta-retention-hours"),
                    request.headers.get("x-amz-meta-retention-hours"),
                    request.args.get("retentionHours"),
                )
            except RetentionValidationError as error:
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
                lifecycle_logger.warning(
                    "s3_upload_retention_invalid bucket=%s key=%s",
                    bucket,
                    sanitize_log_value(key),
                )
                return _s3_error_response(
                    "InvalidRequest",
                    str(error),
                    bucket=bucket,
                    key=key,
                )
        else:
            retention_hours = 0

        try:
            with quota_lock:
                enforce_storage_quota_for_size(size)
                file_id = register_file(
                    original_name=filename,
                    stored_name=stored_name,
                    content_type=content_type,
                    size=size,
                    retention_hours=retention_hours,
                    file_id=file_id,
                    permanent=permanent,
                )
        except StorageQuotaExceededError as quota_error:
            if upload_path.exists():
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
            lifecycle_logger.warning(
                "s3_upload_quota_exceeded bucket=%s key=%s usage=%d limit=%d",
                bucket,
                sanitize_log_value(key),
                quota_error.current_usage,
                quota_error.quota_limit,
            )
            return _s3_error_response(
                "InsufficientStorage",
                "Storage quota exceeded.",
                bucket=bucket,
                key=key,
                status_code=507,
            )
        except Exception:
            lifecycle_logger.exception(
                "s3_upload_failed reason=registration_error bucket=%s key=%s",
                bucket,
                sanitize_log_value(key),
            )
            if upload_path.exists():
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
            return _s3_error_response(
                "InternalError",
                "Failed to register uploaded file.",
                bucket=bucket,
                key=key,
                status_code=500,
            )

        record = get_file(file_id)
        if not record:
            if upload_path.exists():
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
            remove_orphaned_record(file_id)
            lifecycle_logger.error(
                "s3_upload_failed reason=registration_missing bucket=%s key=%s file_id=%s",
                bucket,
                sanitize_log_value(key),
                file_id,
            )
            return _s3_error_response(
                "InternalError",
                "Failed to load uploaded file metadata.",
                bucket=bucket,
                key=key,
                status_code=500,
            )

    direct_path = record["direct_path"] if record["direct_path"] else None
    if direct_path:
        location = url_for(
            "serve_raw_file",
            direct_path=direct_path,
            _external=True,
        )
    else:
        location = url_for("download", file_id=file_id, _external=True)

    lifecycle_logger.info(
        "file_uploaded_s3_post file_id=%s bucket=%s key=%s size=%d retention_hours=%.2f",
        file_id,
        bucket,
        sanitize_log_value(key),
        size,
        retention_hours,
    )

    response = _build_s3_post_success(
        bucket,
        key,
        location,
        hash_md5.hexdigest(),
    )
    response.headers["x-localhosting-file-id"] = file_id
    return response


@csrf.exempt
@app.route("/s3/<bucket>/<path:key>", methods=["PUT"])
@require_api_auth("s3")
@limiter.limit(lambda: upload_rate_limit_string())
def s3_put_object(bucket: str, key: str):
    with upload_slot() as acquired:
        if not acquired:
            return _s3_error_response(
                "ServiceUnavailable",
                "Too many concurrent uploads.",
                bucket=bucket,
                key=key,
                status_code=503,
            )

        origin_error = ensure_same_origin("s3")
        if origin_error is not None:
            return origin_error

        config = get_config()
        stream = request.stream
        max_bytes = app.config.get("MAX_CONTENT_LENGTH")
        if max_bytes and request.content_length and request.content_length > max_bytes:
            return _s3_error_response(
                "EntityTooLarge",
                "The uploaded file exceeds the allowed size.",
                bucket=bucket,
                key=key,
                status_code=413,
            )

        hash_md5 = hashlib.md5()
        stored_filename = (
            secure_filename(os.path.basename(key)) or f"upload-{uuid.uuid4().hex}"
        )
        is_valid_stored, stored_error = validate_filename(stored_filename)
        if not is_valid_stored:
            lifecycle_logger.warning(
                "s3_upload_invalid_filename bucket=%s key=%s filename=%s error=%s",
                bucket,
                sanitize_log_value(key),
                sanitize_log_value(stored_filename),
                sanitize_log_value(stored_error or "invalid"),
            )
            return _s3_error_response(
                "InvalidArgument",
                stored_error or "Invalid filename",
                bucket=bucket,
                key=key,
                status_code=400,
            )
        quota_limit_bytes = storage_quota_limit_bytes()
        if quota_limit_bytes is not None:
            with quota_lock:
                current_usage = int(
                    get_storage_statistics().get("total_bytes", 0)
                )
                if current_usage >= quota_limit_bytes:
                    lifecycle_logger.warning(
                        "s3_upload_quota_exceeded bucket=%s key=%s",
                        bucket,
                        sanitize_log_value(key),
                    )
                    return _s3_error_response(
                        "InsufficientStorage",
                        "Storage quota exceeded.",
                        bucket=bucket,
                        key=key,
                        status_code=507,
                    )
        file_id = str(uuid.uuid4())
        stored_name = f"{int(time.time())}_{uuid.uuid4().hex}_{stored_filename}"
        upload_path = get_storage_path(file_id, stored_name, ensure_parent=True)
        temp_path = upload_path.with_name(f"{upload_path.name}.tmp")

        written = 0
        try:
            try:
                with temp_path.open("wb") as destination:
                    while True:
                        chunk = stream.read(CHUNK_SIZE_BYTES)
                        if not chunk:
                            break
                        destination.write(chunk)
                        hash_md5.update(chunk)
                        written += len(chunk)
                        if max_bytes and written > max_bytes:
                            raise ValueError("file too large")
            finally:
                _close_stream_safely(stream, f"s3-put file_id={file_id}")

            temp_path.replace(upload_path)
            size = written if written else upload_path.stat().st_size
            if max_bytes and size > max_bytes:
                raise ValueError("file too large")
        except ValueError:
            if temp_path.exists():
                temp_path.unlink(missing_ok=True)
            if upload_path.exists():
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
            return _s3_error_response(
                "EntityTooLarge",
                "The uploaded file exceeds the allowed size.",
                bucket=bucket,
                key=key,
                status_code=413,
            )
        except Exception:
            lifecycle_logger.exception(
                "s3_upload_failed reason=write_error bucket=%s key=%s",
                bucket,
                sanitize_log_value(key),
            )
            if temp_path.exists():
                temp_path.unlink(missing_ok=True)
            if upload_path.exists():
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
            return _s3_error_response(
                "InternalError",
                "Failed to store uploaded file.",
                bucket=bucket,
                key=key,
                status_code=500,
            )

        permanent_header = request.headers.get("x-amz-meta-permanent")
        permanent = (
            permanent_header.lower() in {"1", "true", "yes", "on"}
            if isinstance(permanent_header, str) and permanent_header
            else False
        )

        if not permanent:
            try:
                retention_hours = resolve_retention(
                    config,
                    request.headers.get("x-amz-meta-retention-hours"),
                    request.args.get("retentionHours"),
                )
            except RetentionValidationError as error:
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
                lifecycle_logger.warning(
                    "s3_upload_retention_invalid bucket=%s key=%s",
                    bucket,
                    sanitize_log_value(key),
                )
                return _s3_error_response(
                    "InvalidRequest",
                    str(error),
                    bucket=bucket,
                    key=key,
                )
        else:
            retention_hours = 0

        original_name = (
            request.headers.get("x-amz-meta-original-filename")
            or request.headers.get("x-amz-meta-filename")
            or os.path.basename(key)
            or stored_filename
        )
        filename = secure_filename(original_name) or stored_filename
        is_valid_name, name_error = validate_filename(filename)
        if not is_valid_name:
            lifecycle_logger.warning(
                "s3_upload_invalid_filename bucket=%s key=%s filename=%s error=%s",
                bucket,
                sanitize_log_value(key),
                sanitize_log_value(filename),
                sanitize_log_value(name_error or "invalid"),
            )
            return _s3_error_response(
                "InvalidArgument",
                name_error or "Invalid filename",
                bucket=bucket,
                key=key,
                status_code=400,
            )
        content_type = request.headers.get("Content-Type")

        if not validate_upload_mimetype(filename, content_type):
            lifecycle_logger.warning(
                "s3_upload_suspicious_mimetype bucket=%s key=%s filename=%s declared=%s",
                bucket,
                sanitize_log_value(key),
                sanitize_log_value(filename),
                content_type,
            )

        try:
            with quota_lock:
                enforce_storage_quota_for_size(size)
                file_id = register_file(
                    original_name=filename,
                    stored_name=stored_name,
                    content_type=content_type,
                    size=size,
                    retention_hours=retention_hours,
                    file_id=file_id,
                    permanent=permanent,
                )
        except StorageQuotaExceededError as quota_error:
            if upload_path.exists():
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
            lifecycle_logger.warning(
                "s3_upload_quota_exceeded bucket=%s key=%s usage=%d limit=%d",
                bucket,
                sanitize_log_value(key),
                quota_error.current_usage,
                quota_error.quota_limit,
            )
            return _s3_error_response(
                "InsufficientStorage",
                "Storage quota exceeded.",
                bucket=bucket,
                key=key,
                status_code=507,
            )
        except Exception:
            lifecycle_logger.exception(
                "s3_upload_failed reason=registration_error bucket=%s key=%s",
                bucket,
                sanitize_log_value(key),
            )
            if upload_path.exists():
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
            return _s3_error_response(
                "InternalError",
                "Failed to register uploaded file.",
                bucket=bucket,
                key=key,
                status_code=500,
            )

        record = get_file(file_id)
        if not record:
            if upload_path.exists():
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
            remove_orphaned_record(file_id)
            lifecycle_logger.error(
                "s3_upload_failed reason=registration_missing bucket=%s key=%s file_id=%s",
                bucket,
                sanitize_log_value(key),
                file_id,
            )
            return _s3_error_response(
                "InternalError",
                "Failed to load uploaded file metadata.",
                bucket=bucket,
                key=key,
                status_code=500,
            )

        direct_path = record["direct_path"] if record["direct_path"] else None
        if direct_path:
            location = url_for(
                "serve_raw_file",
                direct_path=direct_path,
                _external=True,
            )
        else:
            location = url_for("download", file_id=file_id, _external=True)

    lifecycle_logger.info(
        "file_uploaded_s3_put file_id=%s bucket=%s key=%s size=%d retention_hours=%.2f",
        file_id,
        bucket,
        sanitize_log_value(key),
        size,
        retention_hours,
    )

    response = _build_s3_put_success(
        bucket,
        key,
        location,
        hash_md5.hexdigest(),
    )
    response.headers["x-localhosting-file-id"] = file_id
    return response


@app.route("/metrics")
@limiter.limit(lambda: api_rate_limit_string())
@require_ui_auth
def metrics():
    """Display comprehensive system and usage metrics."""

    storage_stats = get_storage_statistics()

    health_checks: Dict[str, Dict[str, Any]] = {}
    try:
        with get_db() as conn:
            conn.execute("SELECT 1").fetchone()
            health_checks["database"] = {"status": "healthy", "message": "Connected"}
    except Exception as error:
        health_checks["database"] = {
            "status": "unhealthy",
            "message": str(error)[:100],
        }

    try:
        usage = shutil.disk_usage(UPLOADS_DIR)
        disk_free_gb = usage.free / (1024 ** 3)
        disk_total_gb = usage.total / (1024 ** 3)
        disk_used_gb = usage.used / (1024 ** 3)
        disk_percent = (usage.used / usage.total * 100) if usage.total > 0 else 0
        health_checks["disk"] = {
            "status": "healthy"
            if disk_free_gb >= 5
            else ("warning" if disk_free_gb >= 1 else "critical"),
            "free_gb": disk_free_gb,
            "total_gb": disk_total_gb,
            "used_gb": disk_used_gb,
            "percent_used": disk_percent,
        }
    except Exception as error:
        health_checks["disk"] = {
            "status": "unhealthy",
            "message": str(error)[:100],
        }

    health_checks["upload_limiter"] = {
        "status": "healthy",
        "current_limit": upload_limiter.current_limit,
        "available_slots": upload_limiter.available_slots(),
    }

    recent_uploads = list_files(
        limit=20, offset=0, sort_by="uploaded_at", sort_order="desc"
    )
    recent_files: List[Dict[str, Any]] = []
    now = time.time()
    for record in recent_uploads:
        is_permanent = bool(record["permanent"]) if "permanent" in record.keys() else False
        expires_at = float(record["expires_at"])
        remaining_seconds = float("inf") if is_permanent else max(expires_at - now, 0)
        recent_files.append(
            {
                "id": record["id"],
                "original_name": record["original_name"],
                "size": record["size"],
                "uploaded_at": record["uploaded_at"],
                "expires_at": expires_at,
                "permanent": is_permanent,
                "remaining_seconds": remaining_seconds,
            }
        )

    # Optimized retention breakdown query using SQL aggregation
    current_time = time.time()
    with get_db() as conn:
        cursor = conn.execute(
            """
            SELECT
                SUM(CASE WHEN permanent = 1 THEN 1 ELSE 0 END) as permanent,
                SUM(CASE WHEN permanent = 0 AND (expires_at - ?) / 3600 < 1 THEN 1 ELSE 0 END) as less_1h,
                SUM(CASE WHEN permanent = 0 AND (expires_at - ?) / 3600 >= 1 AND (expires_at - ?) / 3600 < 6 THEN 1 ELSE 0 END) as "1h_to_6h",
                SUM(CASE WHEN permanent = 0 AND (expires_at - ?) / 3600 >= 6 AND (expires_at - ?) / 3600 < 24 THEN 1 ELSE 0 END) as "6h_to_24h",
                SUM(CASE WHEN permanent = 0 AND (expires_at - ?) / 3600 >= 24 AND (expires_at - ?) / 3600 < 168 THEN 1 ELSE 0 END) as "1d_to_7d",
                SUM(CASE WHEN permanent = 0 AND (expires_at - ?) / 3600 >= 168 THEN 1 ELSE 0 END) as more_7d
            FROM files
            WHERE expires_at >= ?
            """,
            (current_time, current_time, current_time, current_time, current_time, current_time, current_time, current_time, current_time),
        )
        row = cursor.fetchone()

    retention_breakdown = {
        "permanent": int(row["permanent"] or 0),
        "less_1h": int(row["less_1h"] or 0),
        "1h_to_6h": int(row["1h_to_6h"] or 0),
        "6h_to_24h": int(row["6h_to_24h"] or 0),
        "1d_to_7d": int(row["1d_to_7d"] or 0),
        "more_7d": int(row["more_7d"] or 0),
    }

    config = get_config()
    config_snapshot = {
        "retention_hours": config.get("retention_hours", 24),
        "retention_min_hours": config.get("retention_min_hours", 0),
        "retention_max_hours": config.get("retention_max_hours", 168),
        "max_upload_size_mb": config.get("max_upload_size_mb", 500),
        "max_concurrent_uploads": int(config.get("max_concurrent_uploads", 10)),
        "cleanup_interval_minutes": int(config.get("cleanup_interval_minutes", 5)),
        "ui_auth_enabled": config.get("ui_auth_enabled", False),
        "api_auth_enabled": config.get("api_auth_enabled", False),
        "api_keys_count": len(config.get("api_keys", [])),
    }

    quota_limit_gb = _get_optional_float_env("LOCALHOSTING_STORAGE_QUOTA_GB")
    if quota_limit_gb and quota_limit_gb > 0:
        quota_used_percent = (
            storage_stats["total_bytes"] / (quota_limit_gb * 1024 ** 3) * 100
        )
    else:
        quota_used_percent = None

    # Check if client wants Prometheus format (text/plain)
    accept_header = request.headers.get("Accept", "")
    wants_prometheus = (
        "text/plain" in accept_header or
        "application/openmetrics-text" in accept_header or
        request.args.get("format") == "prometheus"
    )

    if wants_prometheus:
        # Return Prometheus-compatible metrics
        metrics_lines = []

        # File metrics
        metrics_lines.append("# HELP localhosting_files_total Total number of active files stored")
        metrics_lines.append("# TYPE localhosting_files_total gauge")
        metrics_lines.append(f'localhosting_files_total {storage_stats.get("active_count", 0)}')

        metrics_lines.append("# HELP localhosting_files_expired Total number of expired files")
        metrics_lines.append("# TYPE localhosting_files_expired gauge")
        metrics_lines.append(f'localhosting_files_expired {storage_stats.get("expired_count", 0)}')

        # Storage metrics
        metrics_lines.append("# HELP localhosting_storage_bytes Total storage used in bytes")
        metrics_lines.append("# TYPE localhosting_storage_bytes gauge")
        metrics_lines.append(f'localhosting_storage_bytes {storage_stats.get("total_bytes", 0)}')

        metrics_lines.append("# HELP localhosting_storage_active_bytes Storage used by active files in bytes")
        metrics_lines.append("# TYPE localhosting_storage_active_bytes gauge")
        metrics_lines.append(f'localhosting_storage_active_bytes {storage_stats.get("active_bytes", 0)}')

        metrics_lines.append("# HELP localhosting_storage_expired_bytes Storage used by expired files in bytes")
        metrics_lines.append("# TYPE localhosting_storage_expired_bytes gauge")
        metrics_lines.append(f'localhosting_storage_expired_bytes {storage_stats.get("expired_bytes", 0)}')

        # Directory metrics
        metrics_lines.append("# HELP localhosting_directories_total Total number of directories")
        metrics_lines.append("# TYPE localhosting_directories_total gauge")
        metrics_lines.append(f'localhosting_directories_total {storage_stats.get("directories", 0)}')

        # Retention breakdown metrics
        for category, count in retention_breakdown.items():
            safe_category = category.replace("-", "_")
            metrics_lines.append(f'localhosting_files_by_retention{{category="{category}"}} {count}')

        # Upload limiter metrics
        metrics_lines.append("# HELP localhosting_upload_slots_available Available upload slots")
        metrics_lines.append("# TYPE localhosting_upload_slots_available gauge")
        metrics_lines.append(f'localhosting_upload_slots_available {health_checks["upload_limiter"]["available_slots"]}')

        metrics_lines.append("# HELP localhosting_upload_limit_total Total upload slot limit")
        metrics_lines.append("# TYPE localhosting_upload_limit_total gauge")
        metrics_lines.append(f'localhosting_upload_limit_total {health_checks["upload_limiter"]["current_limit"]}')

        # Health status metrics (1 = healthy, 0 = unhealthy)
        db_status = 1 if health_checks.get("database", {}).get("status") == "healthy" else 0
        metrics_lines.append("# HELP localhosting_database_healthy Database health status")
        metrics_lines.append("# TYPE localhosting_database_healthy gauge")
        metrics_lines.append(f'localhosting_database_healthy {db_status}')

        disk_status = 1 if health_checks.get("disk", {}).get("status") == "healthy" else 0
        metrics_lines.append("# HELP localhosting_disk_healthy Disk health status")
        metrics_lines.append("# TYPE localhosting_disk_healthy gauge")
        metrics_lines.append(f'localhosting_disk_healthy {disk_status}')

        # Disk space metrics
        if "disk" in health_checks and "free_gb" in health_checks["disk"]:
            metrics_lines.append("# HELP localhosting_disk_free_gb Free disk space in GB")
            metrics_lines.append("# TYPE localhosting_disk_free_gb gauge")
            metrics_lines.append(f'localhosting_disk_free_gb {health_checks["disk"]["free_gb"]:.2f}')

            metrics_lines.append("# HELP localhosting_disk_used_gb Used disk space in GB")
            metrics_lines.append("# TYPE localhosting_disk_used_gb gauge")
            metrics_lines.append(f'localhosting_disk_used_gb {health_checks["disk"]["used_gb"]:.2f}')

            metrics_lines.append("# HELP localhosting_disk_total_gb Total disk space in GB")
            metrics_lines.append("# TYPE localhosting_disk_total_gb gauge")
            metrics_lines.append(f'localhosting_disk_total_gb {health_checks["disk"]["total_gb"]:.2f}')

        # Quota metrics
        if quota_limit_gb:
            metrics_lines.append("# HELP localhosting_quota_limit_gb Storage quota limit in GB")
            metrics_lines.append("# TYPE localhosting_quota_limit_gb gauge")
            metrics_lines.append(f'localhosting_quota_limit_gb {quota_limit_gb}')

            metrics_lines.append("# HELP localhosting_quota_used_percent Percentage of quota used")
            metrics_lines.append("# TYPE localhosting_quota_used_percent gauge")
            metrics_lines.append(f'localhosting_quota_used_percent {quota_used_percent:.2f}')

        response = make_response("\n".join(metrics_lines) + "\n", 200)
        response.headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
        return response

    # Return HTML dashboard
    return render_template(
        "metrics.html",
        storage_stats=storage_stats,
        health_checks=health_checks,
        recent_files=recent_files,
        retention_breakdown=retention_breakdown,
        config_snapshot=config_snapshot,
        quota_limit_gb=quota_limit_gb,
        quota_used_percent=quota_used_percent,
    )




@csrf.exempt
@app.route("/directories", methods=["POST"])
@require_api_auth()
def create_directory_endpoint():
    """Create a new directory for grouping uploads."""

    if request.method == "POST" and request.mimetype != "application/json" and not request.is_json:
        return directories()

    try:
        if request.is_json:
            data = request.get_json() or {}
        else:
            data = request.form.to_dict()

        name = data.get("name", "").strip()
        description = data.get("description", "").strip()

        if not name:
            name = f"Collection {uuid.uuid4().hex[:8]}"

        directory_id = create_directory(name, description)
        directory = get_directory(directory_id)

        lifecycle_logger.info(
            "directory_created directory_id=%s name=%s",
            directory_id,
            sanitize_log_value(name),
        )

        return (
            jsonify(
                {
                    "directory_id": directory_id,
                    "name": directory["name"],
                    "description": directory["description"],
                    "created_at": directory["created_at"],
                    "created_at_iso": isoformat_utc(directory["created_at"]),
                    "file_count": 0,
                    "message": "Directory created successfully.",
                }
            ),
            201,
        )

    except Exception as error:
        lifecycle_logger.exception("directory_creation_failed")
        return (
            jsonify(
                {
                    "error": "Failed to create directory",
                    "detail": str(error),
                }
            ),
            500,
        )


@csrf.exempt
@app.route("/directories/<directory_id>/files", methods=["POST"])
@require_api_auth()
@limiter.limit(lambda: upload_rate_limit_string())
def upload_to_directory(directory_id: str):
    """Upload files to a specific directory, optionally from URLs with renaming."""

    directory = get_directory(directory_id)
    if not directory:
        lifecycle_logger.warning("directory_not_found directory_id=%s", directory_id)
        return jsonify({"error": "Directory not found"}), 404

    rename_enabled = request.args.get("rename", "false").lower() in {
        "true",
        "1",
        "yes",
        "on",
    }

    config = get_config()

    if request.is_json:
        return _handle_url_uploads(directory_id, rename_enabled, config)
    return _handle_direct_uploads(directory_id, rename_enabled, config)


def _handle_url_uploads(directory_id: str, rename_enabled: bool, config: dict):
    """Handle uploads from URLs specified in JSON."""

    data = request.get_json() or {}
    files_data = data.get("files", [])

    if not files_data:
        return jsonify({"error": "No files provided in request"}), 400

    if not isinstance(files_data, list):
        return jsonify({"error": "files must be an array"}), 400

    permanent = data.get("permanent", False)
    if not permanent:
        try:
            retention_hours = resolve_retention(
                config,
                data.get("retention_hours"),
            )
        except RetentionValidationError as error:
            return jsonify(error.to_payload()), 400
    else:
        retention_hours = 0

    results = []
    failures = []
    successful_uploads = []

    for idx, file_entry in enumerate(files_data):
        if not isinstance(file_entry, dict):
            failures.append(
                {
                    "index": idx,
                    "reason": "invalid_format",
                    "detail": "Each file entry must be an object",
                }
            )
            continue

        url = file_entry.get("url", "").strip()
        title = file_entry.get("title", "").strip()

        if not url:
            failures.append(
                {
                    "index": idx,
                    "reason": "missing_url",
                    "detail": "URL is required for each file",
                }
            )
            continue

        if rename_enabled and title:
            parsed_url = urlparse(url)
            url_path = parsed_url.path
            _, ext = os.path.splitext(url_path)

            safe_title = secure_filename(title)
            if not safe_title:
                safe_title = f"file-{idx}"

            filename = f"{safe_title}{ext}" if ext else safe_title
        else:
            parsed_url = urlparse(url)
            filename = os.path.basename(parsed_url.path) or f"download-{idx}.bin"
            filename = secure_filename(filename) or f"download-{idx}.bin"

        is_valid, error_msg = validate_filename(filename)
        if not is_valid:
            failures.append(
                {
                    "index": idx,
                    "url": url,
                    "reason": "invalid_filename",
                    "detail": error_msg,
                }
            )
            continue

        file_id = str(uuid.uuid4())
        stored_name = f"{int(time.time())}_{uuid.uuid4().hex}_{filename}"
        upload_path = get_storage_path(file_id, stored_name, ensure_parent=True)

        try:
            lifecycle_logger.info(
                "downloading_from_url url=%s directory_id=%s",
                sanitize_log_value(url),
                directory_id,
            )
            max_bytes = app.config.get("MAX_CONTENT_LENGTH") or DEFAULT_MAX_UPLOAD_SIZE_MB * BYTES_PER_MB
            # Use streaming download to avoid memory exhaustion on large files
            size, content_type = download_file_from_url_to_path(
                url, upload_path, max_size_bytes=max_bytes
            )
        except ValueError as error:
            # File too large or validation error
            lifecycle_logger.warning(
                "url_download_size_exceeded url=%s error=%s",
                sanitize_log_value(url),
                str(error),
            )
            failures.append(
                {
                    "index": idx,
                    "url": url,
                    "filename": filename,
                    "reason": "too_large",
                    "detail": str(error),
                }
            )
            # Clean up any partial download
            upload_path.unlink(missing_ok=True)
            prune_empty_upload_dirs(upload_path.parent)
            continue
        except Exception as error:
            lifecycle_logger.exception(
                "url_download_failed url=%s", sanitize_log_value(url)
            )
            failures.append(
                {
                    "index": idx,
                    "url": url,
                    "reason": "download_failed",
                    "detail": str(error),
                }
            )
            # Clean up any partial download
            upload_path.unlink(missing_ok=True)
            prune_empty_upload_dirs(upload_path.parent)
            continue

        try:

            try:
                with quota_lock:
                    enforce_storage_quota_for_size(size)
                    file_id = register_file(
                        original_name=filename,
                        stored_name=stored_name,
                        content_type=content_type,
                        size=size,
                        retention_hours=retention_hours,
                        file_id=file_id,
                        permanent=permanent,
                    )

                    with get_db() as conn:
                        conn.execute(
                            "UPDATE files SET directory_id = ? WHERE id = ?",
                            (directory_id, file_id),
                        )
                        conn.commit()

            except StorageQuotaExceededError:
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
                failures.append(
                    {
                        "index": idx,
                        "url": url,
                        "filename": filename,
                        "reason": "quota_exceeded",
                    }
                )
                lifecycle_logger.warning(
                    "upload_quota_exceeded directory_id=%s url=%s",
                    directory_id,
                    sanitize_log_value(url),
                )
                continue

            record = get_file(file_id)
            if not record:
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
                failures.append(
                    {
                        "index": idx,
                        "url": url,
                        "filename": filename,
                        "reason": "registration_failed",
                    }
                )
                continue

            download_url = url_for("download", file_id=file_id, _external=True)
            direct_download_url = url_for(
                "direct_download", file_id=file_id, filename=filename, _external=True
            )
            raw_download_url = (
                url_for("serve_raw_file", direct_path=record["direct_path"], _external=True)
                if record["direct_path"]
                else ""
            )

            results.append(
                {
                    "id": file_id,
                    "filename": filename,
                    "size": size,
                    "original_url": url,
                    "title": title if title else None,
                    "download_url": download_url,
                    "direct_download_url": direct_download_url,
                    "raw_download_url": raw_download_url,
                    "retention_hours": retention_hours if not permanent else None,
                    "permanent": permanent,
                    "uploaded_at": record["uploaded_at"],
                    "expires_at": record["expires_at"],
                }
            )

            metadata_fields: Dict[str, object] = {}
            # Maximum size for metadata fields to prevent abuse (1000 characters per field)
            MAX_METADATA_FIELD_SIZE = 1000
            for key in [
                "title",
                "artist",
                "album",
                "duration",
                "genre",
                "year",
                "theme",
                "description",
            ]:
                if key in file_entry and file_entry[key]:
                    value = file_entry[key]
                    # Validate metadata field size
                    if isinstance(value, str) and len(value) > MAX_METADATA_FIELD_SIZE:
                        lifecycle_logger.warning(
                            "metadata_field_too_large file_id=%s key=%s size=%d",
                            file_id,
                            key,
                            len(value),
                        )
                        # Truncate to maximum size
                        value = value[:MAX_METADATA_FIELD_SIZE]
                    metadata_fields[key] = value

            if metadata_fields:
                update_file_metadata(file_id, metadata_fields)

            successful_uploads.append((file_id, stored_name))

            lifecycle_logger.info(
                "file_uploaded_to_directory file_id=%s directory_id=%s filename=%s url=%s",
                file_id,
                directory_id,
                sanitize_log_value(filename),
                sanitize_log_value(url),
            )

        except Exception as error:
            lifecycle_logger.exception(
                "file_store_failed directory_id=%s url=%s",
                directory_id,
                sanitize_log_value(url),
            )
            if upload_path.exists():
                upload_path.unlink(missing_ok=True)
                prune_empty_upload_dirs(upload_path.parent)
            failures.append(
                {
                    "index": idx,
                    "url": url,
                    "filename": filename,
                    "reason": "storage_failed",
                    "detail": str(error),
                }
            )

    update_directory_file_count(directory_id)

    if failures and not results:
        # All uploads failed
        return jsonify({
            "message": "All file uploads failed.",
            "errors": failures,
            "successful": 0,
        }), 400

    if failures:
        # Partial success: some uploads succeeded, some failed
        status = 207  # Multi-Status
        payload = {
            "message": f"Partial success: {len(results)} file(s) uploaded, {len(failures)} failed.",
            "errors": failures,
            "successful": len(results),
            "files": results,
        }
        return jsonify(payload), status

    if not results:
        return jsonify({"message": "No files were uploaded.", "errors": []}), 400

    return (
        jsonify(
            {
                "directory_id": directory_id,
                "message": f"Successfully uploaded {len(results)} file(s).",
                "files": results,
                "retention_hours": retention_hours if not permanent else None,
                "permanent": permanent,
            }
        ),
        201,
    )


def _handle_direct_uploads(directory_id: str, rename_enabled: bool, config: dict):
    """Handle direct multipart file uploads to a directory."""

    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    uploads = request.files.getlist("file")
    if not uploads:
        return jsonify({"error": "No files selected"}), 400

    title = request.form.get("title", "").strip()

    permanent = request.form.get("permanent", "").lower() in {
        "true",
        "1",
        "yes",
        "on",
    }
    if not permanent:
        try:
            retention_hours = resolve_retention(
                config,
                request.form.get("retention_hours"),
            )
        except RetentionValidationError as error:
            return jsonify(error.to_payload()), 400
    else:
        retention_hours = 0

    results = []
    failures = []
    successful_uploads = []

    for idx, upload in enumerate(uploads):
        if not isinstance(upload, FileStorage) or not upload or upload.filename == "":
            continue

        if rename_enabled and title:
            _, ext = os.path.splitext(upload.filename)
            safe_title = secure_filename(title)
            filename = f"{safe_title}{ext}" if ext else safe_title
        else:
            filename = secure_filename(upload.filename)

        if not filename:
            filename = f"upload-{idx}.bin"

        is_valid, error_msg = validate_filename(filename)
        if not is_valid:
            failures.append(
                {
                    "index": idx,
                    "filename": upload.filename,
                    "reason": "invalid_filename",
                    "detail": error_msg,
                }
            )
            continue

        file_id = str(uuid.uuid4())
        stored_name = f"{int(time.time())}_{uuid.uuid4().hex}_{filename}"
        upload_path = get_storage_path(file_id, stored_name, ensure_parent=True)
        temp_path = upload_path.with_name(f"{upload_path.name}.tmp")

        with upload_stream_handler(upload) as managed_upload:
            try:
                with temp_path.open("wb") as destination:
                    written = 0
                    max_bytes = app.config.get("MAX_CONTENT_LENGTH")
                    while True:
                        chunk = managed_upload.stream.read(1024 * 1024)
                        if not chunk:
                            break
                        if max_bytes and written + len(chunk) > max_bytes:
                            raise ValueError("file too large")
                        destination.write(chunk)
                        written += len(chunk)

                temp_path.replace(upload_path)
                size = written if written else upload_path.stat().st_size

                with quota_lock:
                    enforce_storage_quota_for_size(size)
                    file_id = register_file(
                        original_name=filename,
                        stored_name=stored_name,
                        content_type=managed_upload.content_type,
                        size=size,
                        retention_hours=retention_hours,
                        file_id=file_id,
                        permanent=permanent,
                    )

                    with get_db() as conn:
                        conn.execute(
                            "UPDATE files SET directory_id = ? WHERE id = ?",
                            (directory_id, file_id),
                        )
                        conn.commit()

            except (ValueError, StorageQuotaExceededError) as error:
                if temp_path.exists():
                    temp_path.unlink(missing_ok=True)
                if upload_path.exists():
                    upload_path.unlink(missing_ok=True)
                    prune_empty_upload_dirs(upload_path.parent)
                failures.append(
                    {
                        "index": idx,
                        "filename": filename,
                        "reason": "too_large"
                        if isinstance(error, ValueError)
                        else "quota_exceeded",
                    }
                )
                continue
            except Exception as error:
                lifecycle_logger.exception(
                    "file_upload_failed directory_id=%s filename=%s",
                    directory_id,
                    sanitize_log_value(filename),
                )
                if temp_path.exists():
                    temp_path.unlink(missing_ok=True)
                if upload_path.exists():
                    upload_path.unlink(missing_ok=True)
                    prune_empty_upload_dirs(upload_path.parent)
                failures.append(
                    {
                        "index": idx,
                        "filename": filename,
                        "reason": "storage_failed",
                        "detail": str(error),
                    }
                )
                continue

        record = get_file(file_id)
        if not record:
            upload_path.unlink(missing_ok=True)
            prune_empty_upload_dirs(upload_path.parent)
            failures.append(
                {
                    "index": idx,
                    "filename": filename,
                    "reason": "registration_failed",
                }
            )
            continue

        download_url = url_for("download", file_id=file_id, _external=True)
        direct_download_url = url_for(
            "direct_download", file_id=file_id, filename=filename, _external=True
        )
        raw_download_url = (
            url_for("serve_raw_file", direct_path=record["direct_path"], _external=True)
            if record["direct_path"]
            else ""
        )

        results.append(
            {
                "id": file_id,
                "filename": filename,
                "size": size,
                "download_url": download_url,
                "direct_download_url": direct_download_url,
                "raw_download_url": raw_download_url,
                "retention_hours": retention_hours if not permanent else None,
                "permanent": permanent,
            }
        )

        successful_uploads.append((file_id, stored_name))

    update_directory_file_count(directory_id)

    if failures:
        return (
            jsonify(
                {
                    "message": f"Failed to upload {len(failures)} file(s).",
                    "errors": failures,
                    "successful": len(results),
                }
            ),
            400,
        )

    if not results:
        return jsonify({"message": "No valid files uploaded."}), 400

    return (
        jsonify(
            {
                "directory_id": directory_id,
                "message": f"Successfully uploaded {len(results)} file(s).",
                "files": results,
                "retention_hours": retention_hours if not permanent else None,
                "permanent": permanent,
            }
        ),
        201,
    )


@app.route("/directories", methods=["GET"])
@limiter.limit(lambda: api_rate_limit_string())
@require_ui_auth
def directories():
    """List all directories."""

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()

        if not name:
            flash("Directory name is required.", "error")
            return redirect(url_for("directories"))

        try:
            directory_id = create_directory(name, description)
            lifecycle_logger.info(
                "directory_created_ui directory_id=%s name=%s",
                directory_id,
                sanitize_log_value(name),
            )
            flash(f"Directory '{name}' created successfully.", "success")
            return redirect(url_for("view_directory", directory_id=directory_id))
        except Exception as error:
            lifecycle_logger.exception("directory_creation_failed_ui")
            flash(f"Failed to create directory: {error}", "error")
            return redirect(url_for("directories"))

    page = max(request.args.get("page", 1, type=int), 1)
    per_page = request.args.get("per_page", 50, type=int)
    per_page = max(1, min(per_page, 200))
    sort_by = request.args.get("sort", "created_at")
    sort_order = request.args.get("order", "desc").lower()

    if sort_by not in {"name", "created_at", "file_count"}:
        sort_by = "created_at"
    sort_order = sort_order if sort_order in {"asc", "desc"} else "desc"

    total_directories = count_directories()
    total_pages = max(1, math.ceil(total_directories / per_page)) if total_directories else 1
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page

    directory_records = list_directories(
        limit=per_page,
        offset=offset,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    # Batch update file counts to avoid N+1 queries
    directory_ids = [record["id"] for record in directory_records]
    if directory_ids:
        # Validate directory_ids are strings (from database query, not user input)
        if not all(isinstance(id, str) for id in directory_ids):
            lifecycle_logger.error("Invalid directory_ids type in batch update")
            directory_ids = [str(id) for id in directory_ids if id]

        current_time = time.time()
        with get_db() as conn:
            # Get current file counts for all directories in one query
            # SAFE: placeholders only contains '?' characters, no user input
            placeholders = ",".join("?" * len(directory_ids))
            cursor = conn.execute(
                f"""
                SELECT directory_id, COUNT(*) as count
                FROM files
                WHERE directory_id IN ({placeholders}) AND expires_at >= ?
                GROUP BY directory_id
                """,
                (*directory_ids, current_time),
            )
            file_counts = {row["directory_id"]: row["count"] for row in cursor.fetchall()}

            # Update all directories in batch
            for dir_id, count in file_counts.items():
                conn.execute(
                    "UPDATE directories SET file_count = ? WHERE id = ?",
                    (count, dir_id),
                )
            # Set count to 0 for directories with no files
            for dir_id in directory_ids:
                if dir_id not in file_counts:
                    conn.execute(
                        "UPDATE directories SET file_count = 0 WHERE id = ?",
                        (dir_id,),
                    )
            conn.commit()

    # Use the already-fetched records instead of re-querying
    directories_list = []
    for record in directory_records:
        directories_list.append(
            {
                "id": record["id"],
                "name": record["name"],
                "description": record["description"],
                "created_at": record["created_at"],
                "file_count": record["file_count"],
            }
        )

    return render_template(
        "directories.html",
        directories=directories_list,
        page=page,
        per_page=per_page,
        total_directories=total_directories,
        total_pages=total_pages,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@app.route("/directories/<directory_id>", methods=["GET"])
@limiter.limit(lambda: api_rate_limit_string())
def view_directory(directory_id: str):
    """View a specific directory and its files (UI and API)."""

    directory = get_directory(directory_id)
    if not directory:
        # Check if request expects JSON (API) or HTML (UI)
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({"error": "Directory not found"}), 404
        flash("Directory not found.", "error")
        return redirect(url_for("directories"))

    files = list_directory_files(directory_id)
    file_list = list(iter_files(files))

    # If JSON is requested (API mode), return JSON response
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify(
            {
                "directory_id": directory["id"],
                "name": directory["name"],
                "description": directory["description"],
                "created_at": directory["created_at"],
                "created_at_iso": isoformat_utc(directory["created_at"]),
                "file_count": len(file_list),
                "files": file_list,
            }
        )

    # Otherwise, render HTML for UI
    # Check UI auth for HTML requests only
    from flask import session
    config = get_config()
    if config.get("ui_auth_enabled") and not session.get("ui_authenticated"):
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    sort_by = request.args.get("sort", "uploaded_at")
    sort_order = request.args.get("order", "desc").lower()

    if sort_by not in {"name", "size", "uploaded_at", "expires_at"}:
        sort_by = "uploaded_at"
    sort_order = sort_order if sort_order in {"asc", "desc"} else "desc"

    reverse = sort_order == "desc"
    if sort_by == "name":
        files = sorted(files, key=lambda x: x["original_name"], reverse=reverse)
    elif sort_by == "size":
        files = sorted(files, key=lambda x: x["size"], reverse=reverse)
    elif sort_by == "uploaded_at":
        files = sorted(files, key=lambda x: x["uploaded_at"], reverse=reverse)
    elif sort_by == "expires_at":
        files = sorted(files, key=lambda x: x["expires_at"], reverse=reverse)

    file_list = list(iter_files(files))

    for file in file_list:
        file["download_url"] = url_for("download", file_id=file["id"])
        file["direct_download_url"] = url_for(
            "direct_download", file_id=file["id"], filename=file["original_name"]
        )
        if file.get("raw_download_path"):
            file["raw_download_url"] = url_for(
                "serve_raw_file", direct_path=file["raw_download_path"]
            )

    return render_template(
        "directory_detail.html",
        directory={
            "id": directory["id"],
            "name": directory["name"],
            "description": directory["description"],
            "created_at": directory["created_at"],
            "file_count": len(file_list),
        },
        files=file_list,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@app.route("/directories/<directory_id>/delete", methods=["POST"])
@limiter.limit(lambda: api_rate_limit_string())
@require_ui_auth
def delete_directory_route(directory_id: str):
    """Delete a directory and all its files."""

    directory = get_directory(directory_id)
    if not directory:
        flash("Directory not found.", "error")
        return redirect(url_for("directories"))

    try:
        delete_directory(directory_id)
        lifecycle_logger.info(
            "directory_deleted_ui directory_id=%s name=%s",
            directory_id,
            sanitize_log_value(directory["name"]),
        )
        flash(
            f"Directory '{directory['name']}' and all its files have been deleted.",
            "success",
        )
    except Exception as error:
        lifecycle_logger.exception("directory_deletion_failed_ui")
        flash(f"Failed to delete directory: {error}", "error")

    return redirect(url_for("directories"))


@app.route("/directories/<directory_id>/upload", methods=["GET", "POST"])
@require_ui_auth
def upload_to_directory_ui(directory_id: str):
    """UI for uploading files to a directory."""

    directory = get_directory(directory_id)
    if not directory:
        flash("Directory not found.", "error")
        return redirect(url_for("directories"))

    config = get_config()

    return render_template(
        "upload_to_directory.html",
        directory={
            "id": directory["id"],
            "name": directory["name"],
            "description": directory["description"],
        },
        config=config,
        api_auth_enabled=bool(config.get("api_auth_enabled")),
        api_ui_key=get_ui_api_key(config),
        max_upload_size=app.config.get("MAX_CONTENT_LENGTH", DEFAULT_MAX_UPLOAD_SIZE_MB * BYTES_PER_MB),
    )


@csrf.exempt
@app.route("/files/<file_id>/metadata", methods=["GET", "PUT", "PATCH"])
@limiter.limit(lambda: api_rate_limit_string())
@require_api_auth()
def file_metadata(file_id: str):
    """Get or update file metadata."""

    record = get_file(file_id)
    if not record:
        return jsonify({"error": "File not found"}), 404

    if request.method == "GET":
        metadata = get_file_metadata(file_id)
        return jsonify(
            {
                "file_id": file_id,
                "filename": record["original_name"],
                "metadata": metadata,
            }
        )

    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json() or {}
    metadata_payload = data.get("metadata", {})

    if not isinstance(metadata_payload, dict):
        return jsonify({"error": "metadata must be an object"}), 400

    invalid_keys = [
        key
        for key in metadata_payload.keys()
        if not isinstance(key, str) or len(key) > 100
    ]
    if invalid_keys:
        return jsonify({"error": "Invalid metadata keys"}), 400

    # Validate metadata value sizes (max 1000 bytes per field, 10KB total)
    MAX_METADATA_FIELD_SIZE = 1000
    MAX_METADATA_TOTAL_SIZE = 10000
    validated_metadata = {}

    for key, value in metadata_payload.items():
        # Check size of each field (handles strings, dicts, lists, etc.)
        value_size = _get_object_size(value)
        if value_size > MAX_METADATA_FIELD_SIZE:
            return jsonify({
                "error": f"Metadata field '{key}' is too large ({value_size} bytes, max {MAX_METADATA_FIELD_SIZE} bytes)"
            }), 400
        validated_metadata[key] = value

    # Check total metadata size
    total_size = _get_object_size(validated_metadata)
    if total_size > MAX_METADATA_TOTAL_SIZE:
        return jsonify({
            "error": f"Total metadata size ({total_size} bytes) exceeds limit of {MAX_METADATA_TOTAL_SIZE} bytes"
        }), 400

    success = update_file_metadata(file_id, validated_metadata)
    if not success:
        return jsonify({"error": "Failed to update metadata"}), 500

    updated_metadata = get_file_metadata(file_id)

    lifecycle_logger.info(
        "metadata_updated file_id=%s keys=%s",
        file_id,
        sanitize_log_value(list(metadata_payload.keys())),
    )

    return jsonify(
        {
            "file_id": file_id,
            "filename": record["original_name"],
            "metadata": updated_metadata,
            "message": "Metadata updated successfully.",
        }
    )


@csrf.exempt
@app.route("/files/metadata/batch", methods=["PUT"])
@require_api_auth()
def batch_update_file_metadata():
    """Update metadata for multiple files at once."""

    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json() or {}
    file_ids = data.get("file_ids", [])
    metadata_payload = data.get("metadata", {})

    if not isinstance(file_ids, list) or not file_ids:
        return jsonify({"error": "file_ids must be a non-empty array"}), 400

    if not isinstance(metadata_payload, dict):
        return jsonify({"error": "metadata must be an object"}), 400

    invalid_keys = [
        key
        for key in metadata_payload.keys()
        if not isinstance(key, str) or len(key) > 100
    ]
    if invalid_keys:
        return jsonify({"error": "Invalid metadata keys"}), 400

    normalized_ids: List[str] = []
    for item in file_ids:
        if isinstance(item, str):
            stripped = item.strip()
        else:
            stripped = str(item).strip()
        if stripped:
            normalized_ids.append(stripped)

    if not normalized_ids:
        return jsonify({"error": "file_ids must contain at least one valid identifier"}), 400

    updated = batch_update_metadata(normalized_ids, metadata_payload)

    lifecycle_logger.info(
        "metadata_batch_updated count=%d total=%d keys=%s",
        updated,
        len(normalized_ids),
        sanitize_log_value(list(metadata_payload.keys())),
    )

    return jsonify(
        {
            "message": f"Updated metadata for {updated} file(s).",
            "updated_count": updated,
            "total_requested": len(normalized_ids),
        }
    )


@app.route("/files/<file_id>/metadata/edit")
@require_ui_auth
def edit_metadata_ui(file_id: str):
    """UI for editing file metadata."""

    record = get_file(file_id)
    if not record:
        flash("File not found.", "error")
        return redirect(url_for("hosting"))

    metadata = get_file_metadata(file_id)

    directory_id = None
    if "directory_id" in record.keys():
        directory_id = record["directory_id"]

    return render_template(
        "edit_metadata.html",
        file={
            "id": record["id"],
            "original_name": record["original_name"],
            "metadata": metadata,
            "directory_id": directory_id,
        },
    )


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=False)
