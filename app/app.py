import atexit
import hashlib
import json
import logging
import os
import secrets
import threading
import time
import uuid
from copy import deepcopy
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from secrets import compare_digest
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional
from xml.etree.ElementTree import Element, SubElement, tostring
from logging.handlers import RotatingFileHandler

try:
    from apscheduler.schedulers.background import BackgroundScheduler
except ModuleNotFoundError:  # pragma: no cover - fallback for offline environments
    BackgroundScheduler = None  # type: ignore[assignment]
from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
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

from .storage import (
    DATA_DIR,
    LOGS_DIR,
    RESERVED_DIRECT_PATHS,
    cleanup_expired_files,
    delete_file,
    ensure_directories,
    get_db,
    get_file,
    get_file_by_direct_path,
    get_storage_path,
    iter_files,
    list_files,
    load_config,
    prune_empty_upload_dirs,
    register_file,
    save_config,
)

from threading import Semaphore

RESERVED_ROUTE_ENDPOINTS = {
    "hosting": "hosting",
    "upload-a-file": "upload_file_page",
    "logs": "logs_page",
    "api-docs": "api_docs",
    "settings": "settings",
}

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
numeric_level = getattr(logging, LOG_LEVEL, logging.INFO)
logging.basicConfig(
    level=numeric_level,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


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
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
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
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                buffer = deque(handle, maxlen=max_lines)
        except OSError:
            available = False
            buffer = deque()
        else:
            line_count = len(buffer)
            text = "".join(buffer)

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


def get_config(refresh: bool = False) -> Dict[str, Any]:
    config = getattr(g, "_app_config", None)
    if refresh or config is None:
        config = load_config()
        g._app_config = config
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
        if isinstance(entry, dict) and entry.get("key") and entry.get("id"):
            yield entry


def get_ui_api_key(config: Optional[Dict[str, Any]] = None) -> Optional[dict]:
    config = config or get_config()
    key_id = config.get("api_ui_key_id") or ""
    if not key_id:
        return None
    for entry in _iter_api_keys(config):
        if entry.get("id") == key_id:
            return entry
    return None


def _extract_api_key_from_request() -> Optional[str]:
    header_key = request.headers.get("X-API-Key")
    if header_key:
        return header_key.strip()

    authorization = request.headers.get("Authorization", "").strip()
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    if authorization.lower().startswith("token "):
        return authorization[6:].strip()

    query_key = request.args.get("api_key")
    if query_key:
        return query_key.strip()

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        if isinstance(payload, dict):
            json_key = payload.get("api_key")
            if isinstance(json_key, str):
                return json_key.strip()
    return None


def _api_auth_error(response_format: str = "json") -> Response:
    message = "API authentication required."
    if response_format == "box":
        return _box_error("access_denied", message, status=401)
    if response_format == "s3":
        return _s3_error_response("AccessDenied", message, status_code=403)
    return make_response(jsonify({"error": message}), 401)


def _api_key_matches(provided: Optional[str]) -> bool:
    if not provided:
        return False
    for entry in _iter_api_keys():
        if compare_digest(entry.get("key", ""), provided):
            return True
    return False


def require_api_auth(response_format: str = "json"):
    def decorator(view: Callable):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not api_auth_enabled():
                return view(*args, **kwargs)

            if ui_auth_enabled() and ui_user_authenticated():
                return view(*args, **kwargs)

            provided = _extract_api_key_from_request()
            if _api_key_matches(provided):
                return view(*args, **kwargs)

            lifecycle_logger.warning(
                "api_auth_failed endpoint=%s method=%s", request.endpoint, request.method
            )
            return _api_auth_error(response_format)

        return wrapped

    return decorator


def _generate_api_key_entry(label: str = "") -> dict:
    return {
        "id": uuid.uuid4().hex,
        "key": secrets.token_urlsafe(32),
        "label": (label or "").strip(),
        "created_at": time.time(),
    }


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

    def _run(self) -> None:
        while not self._stop_event.wait(self.interval_seconds):
            try:
                self.func()
            except Exception:  # pragma: no cover - defensive logging
                self._logger.exception("Cleanup job failed")

app = Flask(__name__)

try:
    max_upload_size_mb = int(os.environ.get("MAX_UPLOAD_SIZE_MB", "500"))
except ValueError:
    max_upload_size_mb = 500
app.config["MAX_CONTENT_LENGTH"] = max(1, max_upload_size_mb) * 1024 * 1024

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    secret_path = DATA_DIR / ".secret_key"
    try:
        if secret_path.exists():
            secret_key = secret_path.read_text(encoding="utf-8").strip()
        else:
            ensure_directories()
            secret_key = secrets.token_hex(32)
            secret_path.write_text(secret_key, encoding="utf-8")
            try:
                secret_path.chmod(0o600)
            except OSError:
                logging.getLogger("localhosting.config").warning(
                    "Unable to set secret key permissions for %s", secret_path
                )
            logging.warning("Generated new secret key - stored in %s", secret_path)
    except OSError as error:
        logging.getLogger("localhosting.config").warning(
            "Falling back to in-memory secret key: %s", error
        )
        secret_key = secrets.token_hex(32)

app.config["SECRET_KEY"] = secret_key
csrf = CSRFProtect(app)
app.logger.setLevel(numeric_level)

lifecycle_logger = logging.getLogger("localhosting.lifecycle")

if not HAS_FLASK_WTF:

    @app.context_processor
    def _inject_csrf_stub():  # pragma: no cover - used when Flask-WTF missing
        return {"csrf_token": lambda: ""}

try:
    max_concurrent_uploads = max(
        1, int(os.environ.get("LOCALHOSTING_MAX_CONCURRENT_UPLOADS", "10"))
    )
except ValueError:
    max_concurrent_uploads = 10

upload_semaphore = Semaphore(max_concurrent_uploads)


@contextmanager
def upload_slot() -> Iterator[bool]:
    acquired = upload_semaphore.acquire(blocking=False)
    try:
        yield acquired
    finally:
        if acquired:
            upload_semaphore.release()


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
try:
    cleanup_interval = int(os.environ.get("LOCALHOSTING_CLEANUP_INTERVAL_MINUTES", "5"))
except ValueError:
    cleanup_interval = 5

if BackgroundScheduler is not None:
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=cleanup_expired_files,
        trigger="interval",
        minutes=max(1, cleanup_interval),
        id="cleanup_expired_files",
        name="Clean up expired files",
        replace_existing=True,
    )
else:  # pragma: no cover - exercised in environments without APScheduler
    scheduler = _FallbackCleanupScheduler(
        cleanup_expired_files,
        minutes=max(1, cleanup_interval),
    )

scheduler.start()
atexit.register(lambda: scheduler.shutdown(wait=False))

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


@app.route("/hosting")
@require_ui_auth
def hosting():
    files = list(iter_files(list_files()))
    for file in files:
        file["download_url"] = url_for("download", file_id=file["id"])
        file["direct_download_url"] = url_for(
            "direct_download", file_id=file["id"], filename=file["original_name"]
        )
        if file.get("raw_download_path"):
            file["raw_download_url"] = url_for(
                "serve_raw_file", direct_path=file["raw_download_path"]
            )
    return render_template("hosting.html", files=files)


@app.route("/upload-a-file")
@require_ui_auth
def upload_file_page():
    config = get_config()
    return render_template(
        "upload_file.html",
        config=config,
        api_auth_enabled=bool(config.get("api_auth_enabled")),
        api_ui_key=get_ui_api_key(config),
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
    if delete_file(file_id):
        flash("File deleted successfully.", "success")
        lifecycle_logger.info("file_deleted file_id=%s", file_id)
    else:
        flash("File not found.", "error")
        lifecycle_logger.warning("file_delete_missing file_id=%s", file_id)
    return redirect(url_for("hosting"))


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
                return render_template("settings.html", config=config, api_ui_key=get_ui_api_key(config))

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
                return render_template("settings.html", config=proposed, api_ui_key=get_ui_api_key(proposed))
            if retention_max < retention_min:
                flash(
                    "Maximum retention must be greater than or equal to the minimum.",
                    "error",
                )
                return render_template("settings.html", config=proposed, api_ui_key=get_ui_api_key(proposed))
            if not (retention_min <= retention_hours <= retention_max):
                flash(
                    "Default retention must fall within the configured bounds.",
                    "error",
                )
                return render_template("settings.html", config=proposed, api_ui_key=get_ui_api_key(proposed))

            save_config(proposed)
            get_config(refresh=True)
            refreshed = True
            lifecycle_logger.info(
                "settings_updated retention_min=%.2f retention_max=%.2f retention_default=%.2f",
                retention_min,
                retention_max,
                retention_hours,
            )
            flash("Retention settings updated.", "success")

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
                return render_template("settings.html", config=proposed, api_ui_key=get_ui_api_key(proposed))

            if password or confirm:
                if password != confirm:
                    flash("Password confirmation does not match.", "error")
                    return render_template("settings.html", config=proposed, api_ui_key=get_ui_api_key(proposed))
                proposed["ui_password_hash"] = generate_password_hash(password)

            save_config(proposed)
            get_config(refresh=True)
            refreshed = True

            if auth_enabled:
                session["ui_authenticated"] = True
                session["ui_username"] = proposed["ui_username"]
            else:
                session.pop("ui_authenticated", None)
                session.pop("ui_username", None)

            lifecycle_logger.info(
                "ui_auth_updated enabled=%s username=%s",
                auth_enabled,
                proposed["ui_username"],
            )
            flash("UI authentication settings updated.", "success")

        elif action == "update_api_auth":
            enable_api_auth = request.form.get("api_auth_enabled") == "on"
            proposed = deepcopy(config)
            proposed["api_auth_enabled"] = enable_api_auth

            auto_key = None
            if enable_api_auth and not list(_iter_api_keys(proposed)):
                auto_key = _generate_api_key_entry()
                proposed.setdefault("api_keys", []).append(auto_key)
                proposed["api_ui_key_id"] = auto_key["id"]

            save_config(proposed)
            get_config(refresh=True)
            refreshed = True

            lifecycle_logger.info("api_auth_updated enabled=%s", enable_api_auth)
            if auto_key:
                lifecycle_logger.info("api_key_generated id=%s", auto_key["id"])
                flash(
                    "API authentication enabled. A new key was generated automatically.",
                    "info",
                )
            flash("API authentication settings updated.", "success")

        elif action == "generate_api_key":
            label = request.form.get("api_key_label", "").strip()
            new_key = _generate_api_key_entry(label)
            proposed = deepcopy(config)
            proposed.setdefault("api_keys", []).append(new_key)
            if not proposed.get("api_ui_key_id"):
                proposed["api_ui_key_id"] = new_key["id"]

            save_config(proposed)
            get_config(refresh=True)
            refreshed = True

            lifecycle_logger.info("api_key_generated id=%s label=%s", new_key["id"], label or "")
            flash(f"Generated new API key: {new_key['key']}", "success")

        elif action == "delete_api_key":
            key_id = request.form.get("api_key_id", "").strip()
            proposed = deepcopy(config)
            before = list(_iter_api_keys(proposed))
            remaining = [entry for entry in before if entry.get("id") != key_id]

            if len(remaining) == len(before):
                flash("API key not found.", "error")
                return redirect(url_for("settings"))

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
                return redirect(url_for("settings"))

            proposed["api_ui_key_id"] = key_id
            save_config(proposed)
            get_config(refresh=True)
            refreshed = True

            lifecycle_logger.info("api_key_promoted id=%s", key_id)
            flash("Dashboard uploads will use the selected API key.", "success")

        else:
            flash("Unsupported settings action.", "error")

        if refreshed:
            config = get_config()
        return redirect(url_for("settings"))

    return render_template("settings.html", config=config, api_ui_key=get_ui_api_key(config))


@app.route("/login", methods=["GET", "POST"])
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
            session["ui_authenticated"] = True
            session["ui_username"] = expected_username
            flash("Logged in successfully.", "success")
            next_url = session.pop("ui_next", None)
            return redirect(next_url or url_for("hosting"))

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
def fileupload():
    with upload_slot() as acquired:
        if not acquired:
            return jsonify({"error": "Too many concurrent uploads"}), 503

        if "file" not in request.files:
            app.logger.warning("upload_failed reason=no_file_part")
            return jsonify({"error": "No file part"}), 400

        max_bytes = app.config.get("MAX_CONTENT_LENGTH")
        if max_bytes and request.content_length and request.content_length > max_bytes:
            return jsonify({"error": "File too large"}), 413

        uploads = request.files.getlist("file")
        size_failures: List[Dict[str, str]] = []
        valid_uploads = []
        for upload in uploads:
            if not isinstance(upload, FileStorage) or not upload or upload.filename == "":
                continue
            filename = secure_filename(upload.filename)
            if not filename:
                app.logger.warning(
                    "upload_failed reason=invalid_filename original=%s", upload.filename
                )
                return jsonify({"error": "Invalid filename"}), 400
            if max_bytes and upload.content_length and upload.content_length > max_bytes:
                size_failures.append(
                    {
                        "filename": filename,
                        "reason": "too_large",
                    }
                )
                continue
            valid_uploads.append((upload, filename))

        if not valid_uploads:
            if size_failures:
                return jsonify(
                    {"message": "Failed to upload files.", "errors": size_failures}
                ), 413
            app.logger.warning("upload_failed reason=no_file_selected")
            return jsonify({"error": "No file selected"}), 400

        config = get_config()
        payload = request.get_json(silent=True) if request.is_json else None
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

        results = []
        failures: List[Dict[str, str]] = list(size_failures)
        for upload, filename in valid_uploads:
            upload_path = None
            temp_path = None
            file_id = str(uuid.uuid4())
            stored_name = f"{int(time.time())}_{uuid.uuid4().hex}_{filename}"
            try:
                upload_path = get_storage_path(file_id, stored_name, ensure_parent=True)
                temp_path = upload_path.with_name(f"{upload_path.name}.tmp")
                if hasattr(upload.stream, "seek"):
                    try:
                        upload.stream.seek(0)
                    except (OSError, IOError):
                        pass
                upload.save(str(temp_path))
                temp_path.replace(upload_path)
                size = upload_path.stat().st_size
                if max_bytes and size > max_bytes:
                    upload_path.unlink(missing_ok=True)
                    prune_empty_upload_dirs(upload_path.parent)
                    failures.append(
                        {
                            "filename": filename,
                            "reason": "too_large",
                        }
                    )
                    continue

                file_id = register_file(
                    original_name=filename,
                    stored_name=stored_name,
                    content_type=upload.content_type,
                    size=size,
                    retention_hours=retention_hours,
                    file_id=file_id,
                )
            except Exception as error:
                lifecycle_logger.exception(
                    "file_upload_failed file_id=%s filename=%s", file_id, filename
                )
                if temp_path and temp_path.exists():
                    temp_path.unlink(missing_ok=True)
                if upload_path and upload_path.exists():
                    upload_path.unlink(missing_ok=True)
                    prune_empty_upload_dirs(upload_path.parent)
                failures.append(
                    {
                        "filename": filename,
                        "reason": "internal_error",
                        "detail": str(error),
                    }
                )
                continue

            record = get_file(file_id)
            if not record:
                lifecycle_logger.error(
                    "file_registration_failed file_id=%s filename=%s", file_id, filename
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
                filename,
                size,
                retention_hours,
            )
            results.append(
                {
                    "id": file_id,
                    "filename": filename,
                    "size": size,
                    "download_url": download_url,
                    "retention_hours": retention_hours,
                    "uploaded_at": uploaded_at,
                    "expires_at": expires_at,
                    "expires_at_iso": isoformat_utc(expires_at),
                    "direct_download_url": direct_download_url,
                    "raw_download_url": raw_download_url,
                    "raw_download_path": record["direct_path"],
                    "message": "File uploaded successfully.",
                }
            )

        if not results:
            status = 413 if any(entry.get("reason") == "too_large" for entry in failures) else 500
            message = {
                "message": "Failed to upload files.",
                "errors": failures,
            }
            return jsonify(message), status

        if len(results) == 1 and not failures:
            return jsonify(results[0]), 201

        response_payload: Dict[str, object] = {
            "message": f"Uploaded {len(results)} files successfully.",
            "files": results,
            "retention_hours": retention_hours,
        }
        if failures:
            response_payload["message"] = (
                f"Uploaded {len(results)} files successfully; {len(failures)} failed."
            )
            response_payload["failed_files"] = failures
        return jsonify(response_payload), 201


@app.route("/download/<file_id>")
def download(file_id: str):
    record = get_file(file_id)
    if not record:
        lifecycle_logger.warning("file_download_missing file_id=%s", file_id)
        abort(404)
    if record["expires_at"] < time.time():
        lifecycle_logger.info("file_download_blocked_expired file_id=%s", file_id)
        cleanup_expired_files()
        abort(404)
    lifecycle_logger.info("file_downloaded file_id=%s", file_id)
    file_path = get_storage_path(file_id, record["stored_name"])
    if not file_path.exists():
        lifecycle_logger.warning(
            "file_download_missing_path file_id=%s stored_name=%s", file_id, record["stored_name"]
        )
        abort(404)
    try:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=record["original_name"],
        )
    except FileNotFoundError:
        lifecycle_logger.warning(
            "file_download_missing_race file_id=%s stored_name=%s", file_id, record["stored_name"]
        )
        abort(404)


@app.route("/files/<file_id>/<path:filename>")
def direct_download(file_id: str, filename: str):
    record = get_file(file_id)
    if not record:
        lifecycle_logger.warning("file_direct_missing file_id=%s", file_id)
        abort(404)
    if record["expires_at"] < time.time():
        lifecycle_logger.info("file_direct_blocked_expired file_id=%s", file_id)
        cleanup_expired_files()
        abort(404)
    if not compare_digest(filename, record["original_name"]):
        lifecycle_logger.warning(
            "file_direct_name_mismatch file_id=%s requested=%s stored=%s",
            file_id,
            filename,
            record["original_name"],
        )
        abort(404)

    lifecycle_logger.info("file_direct_downloaded file_id=%s", file_id)
    file_path = get_storage_path(file_id, record["stored_name"])
    if not file_path.exists():
        lifecycle_logger.warning(
            "file_direct_missing_path file_id=%s stored_name=%s",
            file_id,
            record["stored_name"],
        )
        abort(404)
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
            record["stored_name"],
        )
        abort(404)


@csrf.exempt
@app.route("/2.0/files/content", methods=["POST"])
@require_api_auth("box")
def box_upload_files():
    with upload_slot() as acquired:
        if not acquired:
            return _box_error(
                "service_busy", "Too many concurrent uploads. Try again shortly.", status=503
            )

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

        entries = []
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

            try:
                with temp_path.open("wb") as destination:
                    while True:
                        chunk = upload.stream.read(1024 * 1024)
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
                content_type = upload.content_type

                file_id = register_file(
                    original_name=filename,
                    stored_name=stored_name,
                    content_type=content_type,
                    size=size,
                    retention_hours=retention_hours,
                    file_id=file_id,
                )
            except ValueError:
                if temp_path.exists():
                    temp_path.unlink(missing_ok=True)
                if upload_path.exists():
                    upload_path.unlink(missing_ok=True)
                    prune_empty_upload_dirs(upload_path.parent)
                return _box_error(
                    "file_too_large",
                    "The uploaded file exceeds the allowed size.",
                    status=413,
                )
            except Exception as error:
                lifecycle_logger.exception(
                    "box_upload_failed reason=internal_error filename=%s", filename
                )
                if temp_path.exists():
                    temp_path.unlink(missing_ok=True)
                if upload_path.exists():
                    upload_path.unlink(missing_ok=True)
                    prune_empty_upload_dirs(upload_path.parent)
                return _box_error(
                    "internal_error",
                    "Failed to store uploaded file.",
                    status=500,
                )

            record = get_file(file_id)
            if not record:
                if upload_path.exists():
                    upload_path.unlink(missing_ok=True)
                    prune_empty_upload_dirs(upload_path.parent)
                remove_orphaned_record(file_id)
                lifecycle_logger.error(
                    "box_upload_failed reason=registration_missing file_id=%s", file_id
                )
                return _box_error(
                    "internal_error",
                    f"Failed to register file {original_name}",
                    status=500,
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
                record["original_name"],
                size,
                retention_hours,
            )

        if not entries:
            return _box_error("no_valid_files", "No valid files were provided.")

        response = jsonify({"entries": entries, "total_count": len(entries)})
        response.status_code = 201
        return response


@app.route("/2.0/files/<file_id>/content", methods=["GET"])
@require_api_auth("box")
def box_download_file(file_id: str):
    record = get_file(file_id)
    if not record:
        lifecycle_logger.warning("box_download_missing file_id=%s", file_id)
        return _box_error("not_found", "File not found.", status=404)

    if record["expires_at"] < time.time():
        lifecycle_logger.info("box_download_blocked_expired file_id=%s", file_id)
        cleanup_expired_files()
        return _box_error("expired", "The requested file has expired.", status=404)

    file_path = get_storage_path(record["id"], record["stored_name"])
    if not file_path.exists():
        lifecycle_logger.warning(
            "box_download_missing_path file_id=%s stored_name=%s",
            file_id,
            record["stored_name"],
        )
        return _box_error("not_found", "File content is unavailable.", status=404)

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
            "box_download_missing_race file_id=%s stored_name=%s", file_id, record["stored_name"]
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
        cleanup_expired_files()
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
def serve_raw_file(direct_path: str):
    normalized = direct_path.strip("/")
    if not normalized:
        abort(404)

    if ".." in normalized:
        abort(404)

    first_segment = normalized.split("/", 1)[0]
    first_segment_lower = first_segment.lower()

    if "/" not in normalized and first_segment_lower in RESERVED_ROUTE_ENDPOINTS:
        endpoint = RESERVED_ROUTE_ENDPOINTS[first_segment_lower]
        canonical = url_for(endpoint)
        if request.path != canonical:
            return redirect(canonical, code=308)
        abort(404)

    if first_segment_lower in RESERVED_DIRECT_PATHS:
        abort(404)

    record = get_file_by_direct_path(normalized)
    if not record:
        if first_segment_lower in RESERVED_ROUTE_ENDPOINTS:
            abort(404)
        lifecycle_logger.warning("file_raw_missing direct_path=%s", normalized)
        abort(404)
    if record["expires_at"] < time.time():
        lifecycle_logger.info(
            "file_raw_blocked_expired file_id=%s direct_path=%s",
            record["id"],
            normalized,
        )
        cleanup_expired_files()
        abort(404)

    lifecycle_logger.info(
        "file_raw_downloaded file_id=%s direct_path=%s", record["id"], normalized
    )
    file_path = get_storage_path(record["id"], record["stored_name"])
    if not file_path.exists():
        lifecycle_logger.warning(
            "file_raw_missing_path file_id=%s stored_name=%s", record["id"], record["stored_name"]
        )
        abort(404)
    try:
        return send_file(
            file_path,
            as_attachment=False,
            download_name=record["original_name"],
        )
    except FileNotFoundError:
        lifecycle_logger.warning(
            "file_raw_missing_race file_id=%s stored_name=%s",
            record["id"],
            record["stored_name"],
        )
        abort(404)


@csrf.exempt
@app.route("/s3/<bucket>", methods=["POST"])
@require_api_auth("s3")
def s3_multipart_upload(bucket: str):
    with upload_slot() as acquired:
        if not acquired:
            return _s3_error_response(
                "ServiceUnavailable",
                "Too many concurrent uploads.",
                bucket=bucket,
                status_code=503,
            )

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
            key = key.replace("${filename}", upload.filename)

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

        try:
            with temp_path.open("wb") as destination:
                while True:
                    chunk = upload.stream.read(1024 * 1024)
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
                "s3_upload_failed reason=write_error bucket=%s key=%s", bucket, key
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
                "s3_upload_retention_invalid bucket=%s key=%s", bucket, key
            )
            return _s3_error_response(
                "InvalidRequest",
                str(error),
                bucket=bucket,
                key=key,
            )

        try:
            file_id = register_file(
                original_name=filename,
                stored_name=stored_name,
                content_type=upload.content_type,
                size=size,
                retention_hours=retention_hours,
                file_id=file_id,
            )
        except Exception:
            lifecycle_logger.exception(
                "s3_upload_failed reason=registration_error bucket=%s key=%s", bucket, key
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
                key,
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
        key,
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
        file_id = str(uuid.uuid4())
        stored_name = f"{int(time.time())}_{uuid.uuid4().hex}_{stored_filename}"
        upload_path = get_storage_path(file_id, stored_name, ensure_parent=True)
        temp_path = upload_path.with_name(f"{upload_path.name}.tmp")

        written = 0
        try:
            with temp_path.open("wb") as destination:
                while True:
                    chunk = stream.read(1024 * 1024)
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
                "s3_upload_failed reason=write_error bucket=%s key=%s", bucket, key
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
                "s3_upload_retention_invalid bucket=%s key=%s", bucket, key
            )
            return _s3_error_response(
                "InvalidRequest",
                str(error),
                bucket=bucket,
                key=key,
            )

        original_name = (
            request.headers.get("x-amz-meta-original-filename")
            or request.headers.get("x-amz-meta-filename")
            or os.path.basename(key)
            or stored_filename
        )
        filename = secure_filename(original_name) or stored_filename
        content_type = request.headers.get("Content-Type")

        try:
            file_id = register_file(
                original_name=filename,
                stored_name=stored_name,
                content_type=content_type,
                size=size,
                retention_hours=retention_hours,
                file_id=file_id,
            )
        except Exception:
            lifecycle_logger.exception(
                "s3_upload_failed reason=registration_error bucket=%s key=%s", bucket, key
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
                key,
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
            key,
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


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=False)
