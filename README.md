# Local Hosting API

Local Hosting API is a lightweight self-hosted file upload service designed for local networks. It exposes a REST API for uploads, a dashboard to browse and download files, and a settings page to manage automatic cleanup.

## Features

- **Upload API** – Send single or multiple files to `/fileupload` using multipart form data.
- **S3-compatible uploads** – Target `/s3/<bucket>` (POST) or `/s3/<bucket>/<key>` (PUT) using clients that speak the Amazon S3 object API.
- **Web dashboard** – Browse uploads at `/hosting`, download files, remove them manually, and track expiration details. Use `/upload-a-file` for the drag-and-drop uploader with retention controls.
- **Shareable download links** – Retrieve classic ID-based URLs, direct links that embed the original filename, or raw filename-only URLs for inline streaming.
- **API documentation** – Review example requests and responses at `/api-docs`.
- **Live log viewer** – Monitor container output and upload lifecycle events from `/logs`, including manual refresh and automatic polling controls.
- **Configurable retention** – Adjust how long files stay available via the `/settings` page, including minimum/maximum bounds that callers must respect. Expired files are cleaned up automatically.
- **Lifecycle logging** – Every upload, download, deletion, and cleanup task is logged for easier auditing and troubleshooting.
- **Durable storage** – Files and metadata persist across restarts using Docker volumes.

## Getting Started

### Requirements

- Docker
- Docker Compose

### Run with Docker Compose

```bash
docker compose up --build
```

The service will be available at <http://localhost:8000>.

### API Documentation

Navigate to <http://localhost:8000/api-docs> for detailed examples covering file uploads and downloads, including ready-to-use
`curl` commands, sample responses, Amazon S3-compatible object uploads, and notes about the ID-based, direct, and raw filename
download URLs returned by the API.

### Configuring Retention

Visit <http://localhost:8000/settings> to update the retention policy. You can define minimum and maximum retention windows (in hours) plus the default applied to new uploads. API clients and the dashboard uploader may request any value within that range. Existing files keep their originally assigned expiration times.

## Project Structure

```
.
├── Dockerfile
├── app
│   ├── app.py
│   ├── data/
│   ├── static/
│   └── templates/
├── docker-compose.yml
├── requirements.txt
└── README.md
```

Uploads are stored in `app/uploads`, metadata/configuration lives in `app/data`, and rolling log files are written to `app/logs`. All directories are mapped to Docker volumes to survive container restarts.

### Customising storage locations

If you need to relocate persisted data (for example when running the test suite or developing on a read-only filesystem), set the following environment variables before starting the app:

| Variable | Purpose |
| --- | --- |
| `LOCALHOSTING_STORAGE_ROOT` | Base directory used for derived paths when the more specific variables below are not provided. |
| `LOCALHOSTING_DATA_DIR` | Folder that stores the SQLite database and configuration file. |
| `LOCALHOSTING_UPLOADS_DIR` | Folder where uploaded files are written. |
| `LOCALHOSTING_LOGS_DIR` | Folder where application log files are persisted. |
| `LOCALHOSTING_DOCKER_LOG_PATH` | Optional path to an external Docker log file to expose in the `/logs` viewer. |

Each variable accepts absolute or relative paths. When unset, the application defaults to the in-repo `app/data` and `app/uploads` directories.

## Development

To run locally without Docker, create a virtual environment and start the Flask app:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app.app:app
flask run --host 0.0.0.0 --port 8000
```

## Resubmitting the entire app to Git

If you need to publish the full project again—such as after regenerating the source or resolving merge conflicts—you can
stage and recommit everything with the following workflow:

1. Ensure you are on the branch you want to update (`git status -sb`).
2. Stage every tracked and untracked change so the repository reflects the latest app state:

   ```bash
   git add -A
   ```

3. Create a commit describing the resubmission:

   ```bash
   git commit -m "Resubmit full application"
   ```

4. Push the branch to your remote:

   ```bash
   git push origin <branch-name>
   ```

If you must replace the remote history entirely, perform a force push (`git push --force-with-lease origin <branch-name>`)
after double-checking that collaborators are aware of the overwrite.

## License

This project is provided as-is for local network usage.
