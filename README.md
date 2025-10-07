# Local Hosting API

Local Hosting API is a lightweight self-hosted file upload service designed for local networks. It exposes a REST API for uploads, a dashboard to browse and download files, and a settings page to manage automatic cleanup.

## Features

- **Upload API** – Send files to `/fileupload` using multipart form data.
- **Web dashboard** – Browse uploads at `/hosting`, download files, remove them manually, and upload new items with progress feedback.
- **API documentation** – Review example requests and responses at `/api-docs`.
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
`curl` commands and sample responses.

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

Uploads are stored in `app/uploads` and metadata/configuration lives in `app/data`. Both directories are mapped to Docker volumes to survive container restarts.

## Development

To run locally without Docker, create a virtual environment and start the Flask app:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app.app:app
flask run --host 0.0.0.0 --port 8000
```

## License

This project is provided as-is for local network usage.
