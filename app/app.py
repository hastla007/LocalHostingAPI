import hashlib
import logging
import os
import time
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path
from secrets import compare_digest
from typing import Iterable, List, Optional
from xml.etree.ElementTree import Element, SubElement, tostring
from logging.handlers import RotatingFileHandler

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    make_response,
    Response,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from werkzeug.utils import secure_filename

from .storage import (
    UPLOADS_DIR,
    LOGS_DIR,
    cleanup_expired_files,
    delete_file,
    get_file,
    get_file_by_direct_path,
    iter_files,
    list_files,
    load_config,
    register_file,
    RESERVED_DIRECT_PATHS,
    save_config,
    ensure_directories,
)

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
                "last_modified_iso": datetime.fromtimestamp(stat.st_mtime).isoformat(),
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
            "generated_at_iso": datetime.utcfromtimestamp(generated_at).isoformat() + "Z",
            "max_lines": MAX_LOG_LINES,
        }
    )
    return payload

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "localhostingapi-secret")
app.logger.setLevel(numeric_level)

lifecycle_logger = logging.getLogger("localhosting.lifecycle")


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


@app.before_request
def purge_old_files():
    cleanup_expired_files()


@app.context_processor
def inject_utilities():
    return {"now": datetime.now, "current_year": datetime.now().year}


@app.template_filter("human_datetime")
def human_datetime(value: float) -> str:
    dt = datetime.fromtimestamp(value)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


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
def index():
    return redirect(url_for("hosting"))


@app.route("/hosting")
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
def upload_file_page():
    config = load_config()
    return render_template("upload_file.html", config=config)


@app.route("/api-docs")
def api_docs():
    config = load_config()
    return render_template("api_docs.html", config=config)


@app.route("/logs")
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
def logs_data():
    source_id = request.args.get("source")
    selected, _ = _select_log_source(source_id)
    payload = _build_log_response(selected)
    return jsonify(payload)


@app.route("/hosting/delete/<file_id>", methods=["POST"])
def hosting_delete(file_id: str):
    if delete_file(file_id):
        flash("File deleted successfully.", "success")
        lifecycle_logger.info("file_deleted file_id=%s", file_id)
    else:
        flash("File not found.", "error")
        lifecycle_logger.warning("file_delete_missing file_id=%s", file_id)
    return redirect(url_for("hosting"))


@app.route("/settings", methods=["GET", "POST"])
def settings():
    config = load_config()
    if request.method == "POST":
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
            return render_template("settings.html", config=config)

        proposed_config = config.copy()
        proposed_config.update(
            {
                "retention_min_hours": retention_min,
                "retention_max_hours": retention_max,
                "retention_hours": retention_hours,
            }
        )

        if retention_min < 0:
            flash("Minimum retention cannot be negative.", "error")
            return render_template("settings.html", config=proposed_config)
        if retention_max < retention_min:
            flash("Maximum retention must be greater than or equal to the minimum.", "error")
            return render_template("settings.html", config=proposed_config)
        if not (retention_min <= retention_hours <= retention_max):
            flash("Default retention must fall within the configured bounds.", "error")
            return render_template("settings.html", config=proposed_config)

        save_config(proposed_config)
        lifecycle_logger.info(
            "settings_updated retention_min=%.2f retention_max=%.2f retention_default=%.2f",
            retention_min,
            retention_max,
            retention_hours,
        )
        flash("Settings updated successfully.", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html", config=config)


@app.route("/fileupload", methods=["POST"])
def fileupload():
    if "file" not in request.files:
        app.logger.warning("upload_failed reason=no_file_part")
        return jsonify({"error": "No file part"}), 400

    uploads = request.files.getlist("file")
    valid_uploads = []
    for upload in uploads:
        if not upload or upload.filename == "":
            continue
        filename = secure_filename(upload.filename)
        if not filename:
            app.logger.warning(
                "upload_failed reason=invalid_filename original=%s", upload.filename
            )
            return jsonify({"error": "Invalid filename"}), 400
        valid_uploads.append((upload, filename))

    if not valid_uploads:
        app.logger.warning("upload_failed reason=no_file_selected")
        return jsonify({"error": "No file selected"}), 400

    config = load_config()
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
    for upload, filename in valid_uploads:
        stored_name = f"{int(time.time())}_{uuid.uuid4().hex}_{filename}"
        upload_path = UPLOADS_DIR / stored_name
        upload.save(upload_path)
        size = upload_path.stat().st_size

        file_id = register_file(
            original_name=filename,
            stored_name=stored_name,
            content_type=upload.content_type,
            size=size,
            retention_hours=retention_hours,
        )

        record = get_file(file_id)
        if record:
            expires_at = record["expires_at"]
            uploaded_at = record["uploaded_at"]
            raw_download_url = url_for(
                "serve_raw_file", direct_path=record["direct_path"], _external=True
            )
        else:
            expires_at = time.time()
            uploaded_at = expires_at
            raw_download_url = ""

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
                "expires_at_iso": datetime.fromtimestamp(expires_at).isoformat(),
                "direct_download_url": direct_download_url,
                "raw_download_url": raw_download_url,
                "raw_download_path": record["direct_path"] if record else "",
                "message": "File uploaded successfully.",
            }
        )

    if len(results) == 1:
        return jsonify(results[0]), 201

    return (
        jsonify(
            {
                "message": f"Uploaded {len(results)} files successfully.",
                "files": results,
                "retention_hours": retention_hours,
            }
        ),
        201,
    )


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
    return send_from_directory(
        directory=str(UPLOADS_DIR),
        path=record["stored_name"],
        as_attachment=True,
        download_name=record["original_name"],
    )


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
    return send_from_directory(
        directory=str(UPLOADS_DIR),
        path=record["stored_name"],
        as_attachment=True,
        download_name=record["original_name"],
    )


@app.route("/<path:direct_path>")
def serve_raw_file(direct_path: str):
    normalized = direct_path.strip("/")
    if not normalized:
        abort(404)
    first_segment = normalized.split("/", 1)[0]
    if first_segment.lower() in RESERVED_DIRECT_PATHS:
        abort(404)

    record = get_file_by_direct_path(normalized)
    if not record:
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
    return send_from_directory(
        directory=str(UPLOADS_DIR),
        path=record["stored_name"],
        as_attachment=False,
        download_name=record["original_name"],
    )


@app.route("/s3/<bucket>", methods=["POST"])
def s3_multipart_upload(bucket: str):
    config = load_config()
    upload = request.files.get("file")
    if upload is None:
        return _s3_error_response(
            "InvalidArgument",
            "Missing file field 'file'.",
            bucket=bucket,
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
        filename = secure_filename(upload.filename or "upload") or f"upload-{uuid.uuid4().hex}"

    stored_name = f"{int(time.time())}_{uuid.uuid4().hex}_{filename}"
    upload_path = UPLOADS_DIR / stored_name

    hash_md5 = hashlib.md5()
    if hasattr(upload.stream, "seek"):
        upload.stream.seek(0)
    with upload_path.open("wb") as destination:
        while True:
            chunk = upload.stream.read(1024 * 1024)
            if not chunk:
                break
            destination.write(chunk)
            hash_md5.update(chunk)

    try:
        retention_hours = resolve_retention(
            config,
            request.form.get("x-amz-meta-retention-hours"),
            request.headers.get("x-amz-meta-retention-hours"),
            request.args.get("retentionHours"),
        )
    except RetentionValidationError as error:
        upload_path.unlink(missing_ok=True)
        lifecycle_logger.warning(
            "s3_upload_retention_invalid bucket=%s key=%s", bucket, key
        )
        return _s3_error_response(
            "InvalidRequest",
            str(error),
            bucket=bucket,
            key=key,
        )

    size = upload_path.stat().st_size
    file_id = register_file(
        original_name=filename,
        stored_name=stored_name,
        content_type=upload.content_type,
        size=size,
        retention_hours=retention_hours,
    )

    record = get_file(file_id)
    direct_path = record["direct_path"] if record and record["direct_path"] else None
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


@app.route("/s3/<bucket>/<path:key>", methods=["PUT"])
def s3_put_object(bucket: str, key: str):
    config = load_config()
    stream = request.stream

    hash_md5 = hashlib.md5()
    stored_filename = secure_filename(os.path.basename(key)) or f"upload-{uuid.uuid4().hex}"
    stored_name = f"{int(time.time())}_{uuid.uuid4().hex}_{stored_filename}"
    upload_path = UPLOADS_DIR / stored_name

    with upload_path.open("wb") as destination:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            destination.write(chunk)
            hash_md5.update(chunk)

    try:
        retention_hours = resolve_retention(
            config,
            request.headers.get("x-amz-meta-retention-hours"),
            request.args.get("retentionHours"),
        )
    except RetentionValidationError as error:
        upload_path.unlink(missing_ok=True)
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

    size = upload_path.stat().st_size
    content_type = request.headers.get("Content-Type")

    file_id = register_file(
        original_name=filename,
        stored_name=stored_name,
        content_type=content_type,
        size=size,
        retention_hours=retention_hours,
    )

    record = get_file(file_id)
    direct_path = record["direct_path"] if record and record["direct_path"] else None
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
