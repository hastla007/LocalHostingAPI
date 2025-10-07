import logging
import os
import time
import uuid
from datetime import datetime

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from werkzeug.utils import secure_filename

from .storage import (
    UPLOADS_DIR,
    cleanup_expired_files,
    delete_file,
    get_file,
    iter_files,
    list_files,
    load_config,
    register_file,
    save_config,
)

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
numeric_level = getattr(logging, LOG_LEVEL, logging.INFO)
logging.basicConfig(
    level=numeric_level,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "localhostingapi-secret")
app.logger.setLevel(numeric_level)

lifecycle_logger = logging.getLogger("localhosting.lifecycle")


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
    config = load_config()
    return render_template("hosting.html", files=files, config=config)


@app.route("/api-docs")
def api_docs():
    config = load_config()
    return render_template("api_docs.html", config=config)


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
    upload = request.files["file"]
    if upload.filename == "":
        app.logger.warning("upload_failed reason=no_file_selected")
        return jsonify({"error": "No file selected"}), 400
    filename = secure_filename(upload.filename)
    if not filename:
        app.logger.warning("upload_failed reason=invalid_filename original=%s", upload.filename)
        return jsonify({"error": "Invalid filename"}), 400

    config = load_config()
    requested_retention = request.form.get("retention_hours")
    if requested_retention in ("", None):
        requested_retention = request.args.get("retention_hours")
    if requested_retention in ("", None) and request.is_json:
        payload = request.get_json(silent=True) or {}
        requested_retention = payload.get("retention_hours")

    if requested_retention in ("", None):
        retention_hours = config.get("retention_hours", 24)
    else:
        try:
            retention_hours = float(requested_retention)
        except (TypeError, ValueError):
            app.logger.warning("upload_failed reason=invalid_retention value=%s", requested_retention)
            return (
                jsonify(
                    {
                        "error": "Invalid retention_hours value",
                        "allowed_range": [
                            config["retention_min_hours"],
                            config["retention_max_hours"],
                        ],
                    }
                ),
                400,
            )
        if not (config["retention_min_hours"] <= retention_hours <= config["retention_max_hours"]):
            app.logger.warning(
                "upload_failed reason=retention_out_of_bounds value=%.2f min=%.2f max=%.2f",
                retention_hours,
                config["retention_min_hours"],
                config["retention_max_hours"],
            )
            return (
                jsonify(
                    {
                        "error": "Retention must be within the configured range.",
                        "allowed_range": [
                            config["retention_min_hours"],
                            config["retention_max_hours"],
                        ],
                    }
                ),
                400,
            )

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
    else:
        expires_at = time.time()
        uploaded_at = expires_at

    download_url = url_for("download", file_id=file_id, _external=True)
    lifecycle_logger.info(
        "file_uploaded file_id=%s filename=%s size=%d retention_hours=%.2f",
        file_id,
        filename,
        size,
        retention_hours,
    )
    return (
        jsonify(
            {
                "id": file_id,
                "filename": filename,
                "size": size,
                "download_url": download_url,
                "retention_hours": retention_hours,
                "uploaded_at": uploaded_at,
                "expires_at": expires_at,
                "expires_at_iso": datetime.fromtimestamp(expires_at).isoformat(),
                "message": "File uploaded successfully.",
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


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=False)
