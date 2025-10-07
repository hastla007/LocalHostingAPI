FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000

VOLUME ["/app/app/uploads", "/app/app/data"]

CMD ["gunicorn", "app.app:app", "--bind", "0.0.0.0:8000", "--workers", "2"]
