import json
import logging
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Optional

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOADS_DIR = BASE_DIR / "uploads"
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


def get_db() -> sqlite3.Connection:
    ensure_directories()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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
                expires_at REAL NOT NULL
            )
            """
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
) -> str:
    file_id = str(uuid.uuid4())
    uploaded_at = time.time()
    expires_at = calculate_expiration(retention_hours)
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO files (id, original_name, stored_name, content_type, size, uploaded_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (file_id, original_name, stored_name, content_type, size, uploaded_at, expires_at),
        )
        conn.commit()
    logger.info(
        "upload_registered file_id=%s original_name=%s size=%d retention_hours=%.2f expires_at=%f",
        file_id,
        original_name,
        size,
        retention_hours,
        expires_at,
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
    file_path = UPLOADS_DIR / stored_name
    if file_path.exists():
        file_path.unlink()
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
            file_path = UPLOADS_DIR / record["stored_name"]
            if file_path.exists():
                try:
                    file_path.unlink()
                except OSError:
                    pass
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
        }


logger = logging.getLogger("localhosting.storage")

ensure_directories()
init_db()
