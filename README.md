# Local Hosting API

Local Hosting API is a lightweight self-hosted file upload service designed for local networks. It exposes a REST API for uploads, a dashboard to browse and download files, and a settings page to manage automatic cleanup.

## Features

- **Upload API** – Send files to `/fileupload` using multipart form data.
- **Web dashboard** – Browse uploads at `/hosting`, download files, and remove them manually.
- **Configurable retention** – Adjust how long files stay available via the `/settings` page. Expired files are cleaned up automatically.
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

### Uploading Files

Use `curl` or any HTTP client capable of multipart uploads:

```bash
curl -F "file=@/path/to/your/file" http://localhost:8000/fileupload
```

The response includes a direct download URL that you can share on your local network.

### Configuring Retention

Visit <http://localhost:8000/settings> to update the retention period (in hours). The new value is stored persistently and applied to future uploads. Existing files keep their originally assigned expiration times.

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
