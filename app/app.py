import os
import time
from datetime import datetime
import uuid

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

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "localhostingapi-secret")


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


@app.route("/")
def index():
    return redirect(url_for("hosting"))


@app.route("/hosting")
def hosting():
    files = list(iter_files(list_files()))
    config = load_config()
    return render_template("hosting.html", files=files, config=config)


@app.route("/hosting/delete/<file_id>", methods=["POST"])
def hosting_delete(file_id: str):
    if delete_file(file_id):
        flash("File deleted successfully.", "success")
    else:
        flash("File not found.", "error")
    return redirect(url_for("hosting"))


@app.route("/settings", methods=["GET", "POST"])
def settings():
    config = load_config()
    if request.method == "POST":
        try:
            retention_hours = float(request.form.get("retention_hours", config["retention_hours"]))
            if retention_hours < 0:
                raise ValueError
        except (TypeError, ValueError):
            flash("Please provide a valid non-negative number for retention hours.", "error")
            return render_template("settings.html", config=config)
        config["retention_hours"] = retention_hours
        save_config(config)
        flash("Settings updated successfully.", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html", config=config)


@app.route("/fileupload", methods=["POST"])
def fileupload():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    upload = request.files["file"]
    if upload.filename == "":
        return jsonify({"error": "No file selected"}), 400
    filename = secure_filename(upload.filename)
    if not filename:
        return jsonify({"error": "Invalid filename"}), 400

    config = load_config()
    retention_hours = config.get("retention_hours", 24)

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

    download_url = url_for("download", file_id=file_id, _external=True)
    return (
        jsonify(
            {
                "id": file_id,
                "filename": filename,
                "size": size,
                "download_url": download_url,
                "retention_hours": retention_hours,
            }
        ),
        201,
    )


@app.route("/download/<file_id>")
def download(file_id: str):
    record = get_file(file_id)
    if not record:
        abort(404)
    if record["expires_at"] < time.time():
        cleanup_expired_files()
        abort(404)
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
