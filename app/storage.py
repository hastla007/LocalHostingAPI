import json
import logging
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import quote

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

DEFAULT_CONFIG = {
    "retention_hours": 24.0,
    "retention_min_hours": 0.0,
    "retention_max_hours": 168.0,
}

CONFIG_NUMERIC_KEYS = {
    "retention_hours",
    "retention_min_hours",
    "retention_max_hours",
}


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
    return config


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


def get_db() -> sqlite3.Connection:
    ensure_directories()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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
    with get_db() as conn:
        direct_path = _generate_unique_direct_path(conn, original_name, file_id)
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
        conn.commit()
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
    if file_path.exists():
        file_path.unlink()
        prune_empty_upload_dirs(file_path.parent)
    with get_db() as conn:
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()
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
            if file_path.exists():
                try:
                    file_path.unlink()
                except OSError:
                    pass
                prune_empty_upload_dirs(file_path.parent)
            conn.execute("DELETE FROM files WHERE id = ?", (record["id"],))
            removed += 1
        conn.commit()
    if removed:
        logger.info("cleanup_completed removed=%d", removed)
    return removed


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
