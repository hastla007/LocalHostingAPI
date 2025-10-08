import json
import logging
import os
import sqlite3
import time
import hashlib
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Generator
from urllib.parse import quote

from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent


def _resolve_env_path(env_key: str, default: Path) -> Path:
    """Resolve an environment-provided path or fall back to *default*."""

    value = os.environ.get(env_key)
    if value:
        return Path(value).expanduser().resolve()
    return default.resolve()


STORAGE_ROOT = _resolve_env_path("LOCALHOSTING_STORAGE_ROOT", BASE_DIR)
DATA_DIR = _resolve_env_path("LOCALHOSTING_DATA_DIR", STORAGE_ROOT / "data")
UPLOADS_DIR = _resolve_env_path("LOCALHOSTING_UPLOADS_DIR", STORAGE_ROOT / "uploads")
LOGS_DIR = _resolve_env_path("LOCALHOSTING_LOGS_DIR", STORAGE_ROOT / "logs")
DB_PATH = DATA_DIR / "files.db"
CONFIG_PATH = DATA_DIR / "config.json"

def _default_password_hash() -> str:
    return generate_password_hash("localhostingapi")


DEFAULT_MAX_UPLOAD_MB = max(1, int(os.environ.get("MAX_UPLOAD_SIZE_MB", "500")))
DEFAULT_MAX_CONCURRENT_UPLOADS = max(
    1, int(os.environ.get("LOCALHOSTING_MAX_CONCURRENT_UPLOADS", "10"))
)
DEFAULT_CLEANUP_INTERVAL_MINUTES = max(
    1, int(os.environ.get("LOCALHOSTING_CLEANUP_INTERVAL_MINUTES", "5"))
)
DEFAULT_UPLOAD_RATE_LIMIT_PER_HOUR = max(
    1, int(os.environ.get("LOCALHOSTING_RATE_LIMIT_UPLOADS_PER_HOUR", "100"))
)
DEFAULT_LOGIN_RATE_LIMIT_PER_MINUTE = max(
    1, int(os.environ.get("LOCALHOSTING_RATE_LIMIT_LOGINS_PER_MINUTE", "10"))
)
DEFAULT_DOWNLOAD_RATE_LIMIT_PER_MINUTE = max(
    1, int(os.environ.get("LOCALHOSTING_RATE_LIMIT_DOWNLOADS_PER_MINUTE", "120"))
)


DEFAULT_CONFIG = {
    "retention_hours": 24.0,
    "retention_min_hours": 0.0,
    "retention_max_hours": 168.0,
    "max_upload_size_mb": float(DEFAULT_MAX_UPLOAD_MB),
    "max_concurrent_uploads": float(DEFAULT_MAX_CONCURRENT_UPLOADS),
    "cleanup_interval_minutes": float(DEFAULT_CLEANUP_INTERVAL_MINUTES),
    "upload_rate_limit_per_hour": float(DEFAULT_UPLOAD_RATE_LIMIT_PER_HOUR),
    "login_rate_limit_per_minute": float(DEFAULT_LOGIN_RATE_LIMIT_PER_MINUTE),
    "download_rate_limit_per_minute": float(DEFAULT_DOWNLOAD_RATE_LIMIT_PER_MINUTE),
    "ui_auth_enabled": False,
    "ui_username": "admin",
    "ui_password_hash": _default_password_hash(),
    "api_auth_enabled": False,
    "api_keys": [],
    "api_ui_key_id": "",
}

CONFIG_NUMERIC_KEYS = {
    "retention_hours",
    "retention_min_hours",
    "retention_max_hours",
    "max_upload_size_mb",
    "max_concurrent_uploads",
    "cleanup_interval_minutes",
    "upload_rate_limit_per_hour",
    "login_rate_limit_per_minute",
    "download_rate_limit_per_minute",
}

CONFIG_BOOLEAN_KEYS = {"ui_auth_enabled", "api_auth_enabled"}

CONFIG_STRING_KEYS = {"ui_username", "ui_password_hash", "api_ui_key_id"}

CONFIG_LIST_KEYS = {"api_keys"}


def _coerce_numeric(value, default):
    try:
        coerced = float(value)
    except (TypeError, ValueError):
        return float(default)
    return float(coerced)


def _normalize_config(raw_config: Dict[str, float]) -> Dict[str, float]:
    if not isinstance(raw_config, dict):
        raw_config = {}

    config = DEFAULT_CONFIG.copy()
    for key in CONFIG_NUMERIC_KEYS:
        if key in raw_config:
            config[key] = _coerce_numeric(raw_config.get(key), config[key])

    # Ensure boundaries make sense before clamping the default retention.
    if config["retention_min_hours"] < 0:
        config["retention_min_hours"] = 0.0
    if config["retention_max_hours"] < config["retention_min_hours"]:
        config["retention_max_hours"] = config["retention_min_hours"]

    config["retention_hours"] = min(
        max(config["retention_hours"], config["retention_min_hours"]),
        config["retention_max_hours"],
    )

    if config.get("max_upload_size_mb", 0) < 1:
        config["max_upload_size_mb"] = float(DEFAULT_MAX_UPLOAD_MB)

    if config.get("max_concurrent_uploads", 0) < 1:
        config["max_concurrent_uploads"] = float(DEFAULT_MAX_CONCURRENT_UPLOADS)

    if config.get("cleanup_interval_minutes", 0) < 1:
        config["cleanup_interval_minutes"] = float(DEFAULT_CLEANUP_INTERVAL_MINUTES)

    if config.get("upload_rate_limit_per_hour", 0) < 1:
        config["upload_rate_limit_per_hour"] = float(
            DEFAULT_UPLOAD_RATE_LIMIT_PER_HOUR
        )

    if config.get("login_rate_limit_per_minute", 0) < 1:
        config["login_rate_limit_per_minute"] = float(
            DEFAULT_LOGIN_RATE_LIMIT_PER_MINUTE
        )

    if config.get("download_rate_limit_per_minute", 0) < 1:
        config["download_rate_limit_per_minute"] = float(
            DEFAULT_DOWNLOAD_RATE_LIMIT_PER_MINUTE
        )

    for key in CONFIG_BOOLEAN_KEYS:
        if key in raw_config:
            value = raw_config.get(key)
            if isinstance(value, str):
                config[key] = value.strip().lower() in {"1", "true", "yes", "on"}
            else:
                config[key] = bool(value)

    for key in CONFIG_STRING_KEYS:
        if key in raw_config and isinstance(raw_config.get(key), str):
            value = raw_config.get(key).strip()
            if key == "ui_password_hash" and not value:
                continue
            if key == "ui_username" and not value:
                continue
            config[key] = value or config[key]

    for key in CONFIG_LIST_KEYS:
        if key in raw_config and isinstance(raw_config.get(key), list):
            cleaned_items = []
            for entry in raw_config.get(key):
                if not isinstance(entry, dict):
                    continue
                key_hash = entry.get("key_hash")
                if not key_hash and entry.get("key"):
                    key_hash = hash_api_key(str(entry.get("key")))
                if not key_hash or not isinstance(key_hash, str):
                    continue
                entry_id = str(entry.get("id") or uuid.uuid4().hex)
                try:
                    created_at = float(entry.get("created_at", time.time()))
                except (TypeError, ValueError):
                    created_at = time.time()
                label = entry.get("label") if isinstance(entry.get("label"), str) else ""
                encrypted_value = ""
                if isinstance(entry.get("key_encrypted"), str):
                    encrypted_value = entry.get("key_encrypted").strip()
                cleaned_items.append(
                    {
                        "id": entry_id,
                        "key_hash": key_hash,
                        "key_encrypted": encrypted_value,
                        "label": label.strip(),
                        "created_at": created_at,
                    }
                )
            unique_items = []
            seen_ids = set()
            for entry in cleaned_items:
                if entry["id"] in seen_ids:
                    continue
                seen_ids.add(entry["id"])
                unique_items.append(entry)
            config[key] = unique_items

    if not isinstance(config["ui_username"], str) or not config["ui_username"].strip():
        config["ui_username"] = DEFAULT_CONFIG["ui_username"]

    if not isinstance(config["ui_password_hash"], str) or not config["ui_password_hash"].strip():
        config["ui_password_hash"] = DEFAULT_CONFIG["ui_password_hash"]

    config["ui_username"] = config["ui_username"].strip()

    if not isinstance(config.get("api_ui_key_id"), str):
        config["api_ui_key_id"] = ""

    if config.get("api_ui_key_id"):
        valid_ids = {entry["id"] for entry in config.get("api_keys", [])}
        if config["api_ui_key_id"] not in valid_ids:
            config["api_ui_key_id"] = ""

    return config


def hash_api_key(key: str) -> str:
    """Hash an API key using SHA-256 for persistent storage."""

    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def ensure_directories() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def _storage_prefix(file_id: str) -> str:
    sanitized = (file_id or "").replace("-", "")
    if len(sanitized) < 2:
        sanitized = (sanitized + "00")[:2]
    return sanitized[:2]


def get_storage_path(file_id: str, stored_name: str, ensure_parent: bool = False) -> Path:
    """Return the storage path for *stored_name* within a sharded directory."""

    directory = UPLOADS_DIR / _storage_prefix(file_id)
    if ensure_parent:
        directory.mkdir(parents=True, exist_ok=True)
    candidate = directory / stored_name
    if candidate.exists() or ensure_parent:
        return candidate
    # Fall back to the legacy flat layout when upgrading existing entries.
    return UPLOADS_DIR / stored_name


def prune_empty_upload_dirs(path: Path) -> None:
    """Remove empty shard directories after file deletion."""

    current = path
    try:
        current = current.resolve()
    except FileNotFoundError:
        return

    uploads_root = UPLOADS_DIR.resolve()
    while current != uploads_root and uploads_root in current.parents:
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    ensure_directories()
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        if conn.in_transaction:
            conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()


RESERVED_DIRECT_PATHS = {
    "hosting",
    "settings",
    "api-docs",
    "download",
    "fileupload",
    "static",
    "files",
    "logs",
    "uploads",
    "data",
    "favicon.ico",
    "health",
    "upload-a-file",
    "apikeys",
    "login",
    "logout",
    "2.0",
    "s3",
}


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                content_type TEXT,
                size INTEGER NOT NULL,
                uploaded_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                direct_path TEXT
            )
            """
        )
        conn.commit()
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(files)")
        }
        if "direct_path" not in columns:
            conn.execute("ALTER TABLE files ADD COLUMN direct_path TEXT")
            conn.commit()
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_files_direct_path ON files(direct_path)"
        )
        conn.commit()
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_files_expires_at ON files(expires_at)"
        )
        conn.commit()


def _direct_path_in_use(conn: sqlite3.Connection, direct_path: str) -> bool:
    if not direct_path:
        return True
    cursor = conn.execute(
        "SELECT 1 FROM files WHERE direct_path = ? LIMIT 1", (direct_path,)
    )
    return cursor.fetchone() is not None


def _generate_unique_direct_path(
    conn: sqlite3.Connection,
    original_name: str,
    file_id: str,
    taken_paths: Optional[Set[str]] = None,
) -> str:
    base_name = (original_name or f"file-{file_id}").strip()
    base_name = base_name.replace("\\", "/")
    base_name = os.path.basename(base_name)
    sanitized = secure_filename(base_name)
    if not sanitized:
        sanitized = secure_filename(f"file-{file_id}")
    if not sanitized:
        sanitized = f"file-{file_id}"

    name, ext = os.path.splitext(sanitized)
    if not name:
        name = sanitized or f"file-{file_id}"
        sanitized = name

    candidate = sanitized
    counter = 1
    while (
        candidate.lower() in RESERVED_DIRECT_PATHS
        or _direct_path_in_use(conn, candidate)
        or (taken_paths is not None and candidate in taken_paths)
    ):
        suffix = f"-{counter}"
        candidate = f"{name}{suffix}{ext}"
        counter += 1
    if taken_paths is not None:
        taken_paths.add(candidate)
    return candidate


def backfill_direct_paths() -> None:
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT id, original_name, direct_path FROM files ORDER BY uploaded_at"
        )
        rows = cursor.fetchall()

        taken_paths: Set[str] = {
            row["direct_path"]
            for row in rows
            if row["direct_path"]
            and row["direct_path"].lower() not in RESERVED_DIRECT_PATHS
        }

        for row in rows:
            current_path = row["direct_path"]
            needs_regeneration = not current_path or (
                current_path.lower() in RESERVED_DIRECT_PATHS
            )

            if not needs_regeneration:
                continue

            direct_path = _generate_unique_direct_path(
                conn,
                row["original_name"],
                row["id"],
                taken_paths,
            )
            conn.execute(
                "UPDATE files SET direct_path = ? WHERE id = ?",
                (direct_path, row["id"]),
            )

        conn.commit()


def load_config() -> Dict[str, float]:
    ensure_directories()
    data: Dict[str, float]
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open("r", encoding="utf-8") as config_file:
            try:
                raw = json.load(config_file)
            except json.JSONDecodeError:
                raw = DEFAULT_CONFIG.copy()
    else:
        raw = DEFAULT_CONFIG.copy()
        save_config(raw)

    data = _normalize_config(raw)
    if raw != data:
        save_config(data)
    return data


def save_config(config: Dict[str, float]) -> None:
    ensure_directories()
    normalized = _normalize_config(config)
    with CONFIG_PATH.open("w", encoding="utf-8") as config_file:
        json.dump(normalized, config_file, indent=2)


def calculate_expiration(retention_hours: float) -> float:
    retention_seconds = max(retention_hours, 0) * 3600
    return time.time() + retention_seconds


def register_file(
    original_name: str,
    stored_name: str,
    content_type: Optional[str],
    size: int,
    retention_hours: float,
    file_id: Optional[str] = None,
) -> str:
    file_id = file_id or str(uuid.uuid4())
    uploaded_at = time.time()
    expires_at = calculate_expiration(retention_hours)
    direct_path: Optional[str] = None
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            with get_db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                direct_path = _generate_unique_direct_path(
                    conn, original_name, file_id
                )
                conn.execute(
                    """
                    INSERT INTO files (id, original_name, stored_name, content_type, size, uploaded_at, expires_at, direct_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        file_id,
                        original_name,
                        stored_name,
                        content_type,
                        size,
                        uploaded_at,
                        expires_at,
                        direct_path,
                    ),
                )
            break
        except sqlite3.IntegrityError as error:
            if "direct_path" not in str(error):
                raise
            if attempt == max_attempts - 1:
                fallback_base = secure_filename(original_name) or "file"
                fallback_candidate = f"{file_id}-{fallback_base[:50]}"
                with get_db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute(
                        """
                        INSERT INTO files (id, original_name, stored_name, content_type, size, uploaded_at, expires_at, direct_path)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            file_id,
                            original_name,
                            stored_name,
                            content_type,
                            size,
                            uploaded_at,
                            expires_at,
                            fallback_candidate,
                        ),
                    )
                direct_path = fallback_candidate
                logger.warning(
                    "direct_path_collision_max_attempts file_id=%s original=%s fallback=%s",
                    file_id,
                    original_name,
                    fallback_candidate,
                )
                break
            time.sleep(0.05 * (attempt + 1))
        except Exception:
            raise

    logger.info(
        "upload_registered file_id=%s original_name=%s size=%d retention_hours=%.2f expires_at=%f direct_path=%s",
        file_id,
        original_name,
        size,
        retention_hours,
        expires_at,
        direct_path,
    )
    return file_id


def list_files(include_expired: bool = False) -> List[sqlite3.Row]:
    with get_db() as conn:
        if include_expired:
            cursor = conn.execute("SELECT * FROM files ORDER BY uploaded_at DESC")
        else:
            cursor = conn.execute(
                "SELECT * FROM files WHERE expires_at >= ? ORDER BY uploaded_at DESC",
                (time.time(),),
            )
        return cursor.fetchall()


def get_file(file_id: str) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,))
        return cursor.fetchone()


def delete_file(file_id: str) -> bool:
    record = get_file(file_id)
    if not record:
        return False
    stored_name = record["stored_name"]
    file_path = get_storage_path(file_id, stored_name)
    try:
        with get_db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
            if cursor.rowcount == 0:
                conn.rollback()
                return False
            if file_path.exists():
                try:
                    file_path.unlink()
                    prune_empty_upload_dirs(file_path.parent)
                except OSError as error:
                    logger.warning(
                        "file_delete_disk_failed file_id=%s path=%s error=%s",
                        file_id,
                        file_path,
                        error,
                    )
                    raise RuntimeError("disk_delete_failed") from error
    except RuntimeError:
        return False
    logger.info(
        "file_deleted file_id=%s stored_name=%s original_name=%s",
        file_id,
        stored_name,
        record["original_name"],
    )
    return True


def cleanup_expired_files() -> int:
    now = time.time()
    removed = 0
    with get_db() as conn:
        cursor = conn.execute("SELECT id, stored_name FROM files WHERE expires_at < ?", (now,))
        expired_files = cursor.fetchall()
        for record in expired_files:
            file_path = get_storage_path(record["id"], record["stored_name"])

            deletion_failed = False
            if file_path.exists():
                try:
                    file_path.unlink()
                    prune_empty_upload_dirs(file_path.parent)
                except OSError as error:
                    logger.warning(
                        "cleanup_file_delete_failed file_id=%s path=%s error=%s",
                        record["id"],
                        file_path,
                        error,
                    )
                    deletion_failed = True

            if deletion_failed:
                continue

            conn.execute("DELETE FROM files WHERE id = ?", (record["id"],))
            removed += 1
        conn.commit()
    if removed:
        logger.info("cleanup_completed removed=%d", removed)
    return removed


def cleanup_orphaned_files() -> int:
    """Remove files on disk that have no corresponding database record."""

    ensure_directories()
    removed = 0

    with get_db() as conn:
        cursor = conn.execute("SELECT stored_name FROM files")
        valid_names = {row["stored_name"] for row in cursor.fetchall()}

    for entry in UPLOADS_DIR.iterdir():
        if entry.is_file():
            stored_name = entry.name
            if stored_name.endswith(".tmp"):
                continue

            if stored_name not in valid_names:
                try:
                    entry.unlink()
                    removed += 1
                    logger.info("orphan_file_removed path=%s", entry)
                except OSError as error:
                    logger.warning(
                        "orphan_cleanup_failed path=%s error=%s",
                        entry,
                        error,
                    )
            continue

        if not entry.is_dir():
            continue

        for file_path in entry.iterdir():
            if not file_path.is_file():
                continue

            stored_name = file_path.name
            if stored_name.endswith(".tmp"):
                continue

            if stored_name not in valid_names:
                try:
                    file_path.unlink()
                    removed += 1
                    logger.info("orphan_file_removed path=%s", file_path)
                except OSError as error:
                    logger.warning(
                        "orphan_cleanup_failed path=%s error=%s",
                        file_path,
                        error,
                    )

        prune_empty_upload_dirs(entry)

    if removed:
        logger.info("orphan_cleanup_completed removed=%d", removed)
    return removed


def cleanup_temp_files() -> int:
    """Remove lingering temporary upload files."""

    ensure_directories()
    removed = 0
    cutoff = time.time() - 3600

    for shard_dir in UPLOADS_DIR.rglob("*"):
        if not shard_dir.is_dir():
            continue

        for temp_file in shard_dir.glob("*.tmp"):
            try:
                if temp_file.stat().st_mtime < cutoff:
                    temp_file.unlink()
                    removed += 1
                    logger.info("temp_file_removed path=%s", temp_file)
            except OSError as error:
                logger.warning(
                    "temp_cleanup_failed path=%s error=%s",
                    temp_file,
                    error,
                )

    return removed


def get_storage_statistics() -> Dict[str, int]:
    """Return aggregate metrics about stored files."""

    now = time.time()
    with get_db() as conn:
        active_row = conn.execute(
            """
            SELECT
                COUNT(*) AS count,
                COALESCE(SUM(size), 0) AS total_size
            FROM files
            WHERE expires_at >= ?
            """,
            (now,),
        ).fetchone()

        expired_row = conn.execute(
            "SELECT COUNT(*) AS count, COALESCE(SUM(size), 0) AS total_size FROM files WHERE expires_at < ?",
            (now,),
        ).fetchone()

        total_row = conn.execute(
            "SELECT COALESCE(SUM(size), 0) AS total_size FROM files"
        ).fetchone()

    active_count = int(active_row["count"] if active_row and active_row["count"] is not None else 0)
    active_bytes = int(
        active_row["total_size"] if active_row and active_row["total_size"] is not None else 0
    )
    expired_count = int(
        expired_row["count"] if expired_row and expired_row["count"] is not None else 0
    )
    expired_bytes = int(
        expired_row["total_size"] if expired_row and expired_row["total_size"] is not None else 0
    )
    total_bytes = int(
        total_row["total_size"] if total_row and total_row["total_size"] is not None else 0
    )

    return {
        "active_count": active_count,
        "active_bytes": active_bytes,
        "expired_count": expired_count,
        "expired_bytes": expired_bytes,
        "total_bytes": total_bytes,
    }


def iter_files(records: Iterable[sqlite3.Row]) -> Iterable[Dict[str, object]]:
    for row in records:
        remaining_seconds = max(row["expires_at"] - time.time(), 0)
        yield {
            "id": row["id"],
            "original_name": row["original_name"],
            "stored_name": row["stored_name"],
            "content_type": row["content_type"],
            "size": row["size"],
            "uploaded_at": row["uploaded_at"],
            "expires_at": row["expires_at"],
            "remaining_seconds": remaining_seconds,
            "download_url": f"/download/{row['id']}",
            "direct_download_url": f"/files/{row['id']}/{quote(row['original_name'])}",
            "raw_download_path": row["direct_path"],
        }


def get_file_by_direct_path(direct_path: str) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT * FROM files WHERE direct_path = ?", (direct_path,)
        )
        return cursor.fetchone()


logger = logging.getLogger("localhosting.storage")

ensure_directories()
init_db()
backfill_direct_paths()
