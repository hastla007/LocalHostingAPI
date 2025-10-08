# Local Hosting API

Local Hosting API is a lightweight self-hosted file upload service designed for local networks. It exposes a REST API for uploads, a dashboard to browse and download files, and a settings page to manage automatic cleanup.

## Features

- **Upload API** – Send single or multiple files to `/fileupload` using multipart form data.
- **S3-compatible uploads** – Target `/s3/<bucket>` (POST) or `/s3/<bucket>/<key>` (PUT) using clients that speak the Amazon S3 object API.
- **Box-compatible uploads** – Use `/2.0/files/content`, `/2.0/files/<id>/content`, and `/2.0/file_requests/<id>` with Box SDKs or integrations that expect the Box Files APIs.
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

### Box-Compatible Endpoints

Integrations built against Box.com&rsquo;s files API can point at Local Hosting API using the following routes:

- `POST /2.0/files/content` &mdash; Accepts multipart uploads with an optional `attributes` JSON part and returns Box-style metadata (including SHA-1 hashes) for each stored file.
- `GET /2.0/files/<id>/content` &mdash; Streams the stored file back using the original filename and reported content type.
- `GET /2.0/file_requests/<id>` &mdash; Provides request metadata plus the canonical upload and download URLs for the stored file.

Uploads handled through these endpoints respect the configured retention bounds, emit lifecycle logs, and appear in the `/hosting` dashboard alongside native and S3-compatible uploads.

### Configuring Retention

Visit <http://localhost:8000/settings> to update the retention policy. You can define minimum and maximum retention windows (in hours) plus the default applied to new uploads. API clients and the dashboard uploader may request any value within that range. Existing files keep their originally assigned expiration times.

### Optional UI Authentication

Authentication for the HTML dashboard is disabled by default so anyone on the local network can browse uploads. Enable it from the settings page by ticking **Require login for dashboard pages** and providing a username and password. The initial credentials are `admin` / `localhostingapi` and can be replaced at any time.

Once UI auth is turned on, visits to `/hosting`, `/upload-a-file`, `/logs`, `/api-docs`, and `/settings` will redirect to the `/login` page until valid credentials are supplied. API endpoints remain unauthenticated so existing integrations continue to work. Use the **Log out** control in the navigation bar to end the session.

### Optional API Authentication

REST endpoints (`/fileupload`, the S3-compatible routes, and the Box-compatible routes) accept requests without credentials by default. You can require API keys from the **API Keys** page (`/apikeys`) by toggling **Require API keys for upload endpoints**. The dashboard lets you generate, delete, and label keys, and you can designate one key as the “Dashboard Default” so browser uploads continue to work without manual input.

Keys are stored as SHA-256 hashes and are displayed only once—immediately after creation. The API Keys page surfaces the newly generated value with a copy-to-clipboard control; existing keys show masked placeholders so the raw secret is never exposed again.

When API authentication is enabled, clients must send the key in an `X-API-Key` header (or `Authorization: Bearer <key>`). The same header works across the native, S3, and Box endpoints; you can also supply a simple `api_key` query parameter for tooling that cannot set headers. Rotate or revoke keys at any time—changes take effect immediately.

### Operational endpoints and safeguards

- A lightweight health check is available at `GET /health`. It verifies the SQLite connection and reports free disk space (in gigabytes) so container orchestrators can probe the service and alert on unhealthy states.
- Rate limiting is enabled by default through [Flask-Limiter](https://flask-limiter.readthedocs.io/) with conservative caps (`10/min` for the login page and `100/hour` for upload APIs). Adjust `LOCALHOSTING_RATE_LIMIT_STORAGE` if you need a persistent backend for rate limit counters.

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

Additional runtime tunables include:

| Variable | Purpose |
| --- | --- |
| `MAX_UPLOAD_SIZE_MB` | Maximum request payload size accepted by the upload endpoints (defaults to 500 MB). |
| `LOCALHOSTING_MAX_CONCURRENT_UPLOADS` | Upper bound on simultaneous uploads processed across the UI, native API, Box, and S3-compatible endpoints (defaults to 10). |
| `SECRET_KEY` | Optional Flask secret key override; when unset a random key is generated and stored in `data/.secret_key` on first launch. |
| `LOCALHOSTING_RATE_LIMIT_STORAGE` | Optional Flask-Limiter storage URI (defaults to in-memory `memory://`). |

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
