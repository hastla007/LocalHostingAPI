# LocalHostingAPI - Future Enhancement Plan

**Date:** 2025-11-16
**Planning Horizon:** 12 months
**Version:** 1.0

---

## Table of Contents

1. [Enhancement Philosophy](#enhancement-philosophy)
2. [Quick Wins (Sprint 1)](#quick-wins-sprint-1)
3. [Short-term Enhancements (Months 1-3)](#short-term-enhancements-months-1-3)
4. [Medium-term Enhancements (Months 4-6)](#medium-term-enhancements-months-4-6)
5. [Long-term Enhancements (Months 7-12)](#long-term-enhancements-months-7-12)
6. [Feature Backlog](#feature-backlog)
7. [Technical Debt Tracking](#technical-debt-tracking)
8. [Success Metrics](#success-metrics)

---

## Enhancement Philosophy

### Guiding Principles

1. **Stability First** - Never compromise existing functionality
2. **Backward Compatibility** - Support existing integrations and APIs
3. **Security by Default** - All features secure out of the box
4. **Performance Conscious** - Measure impact before deploying
5. **User-Centric** - Solve real problems for actual users
6. **Maintainability** - Code quality over quick hacks

### Release Strategy

- **Patch Releases (x.x.X)** - Bug fixes, security updates (weekly)
- **Minor Releases (x.X.0)** - New features, improvements (monthly)
- **Major Releases (X.0.0)** - Breaking changes, architecture shifts (quarterly)

---

## Quick Wins (Sprint 1)
**Duration:** 1-2 weeks | **Effort:** 40-60 hours | **Impact:** High

### QW-1: Storage Quota Caching
**Priority:** 🔴 CRITICAL | **Effort:** 2h | **Impact:** High

**Problem:** Storage quota calculated on every upload by walking entire directory tree (O(n) complexity).

**Solution:**
```python
# app/services/quota.py (NEW FILE)

import time
from typing import Dict, Tuple
import threading

class QuotaCache:
    def __init__(self, ttl: int = 60):
        self._cache: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.RLock()
        self._ttl = ttl

    def get_cached_size(self) -> float:
        """Get cached storage size with TTL expiration."""
        with self._lock:
            if "total_size" in self._cache:
                size, timestamp = self._cache["total_size"]
                if time.time() - timestamp < self._ttl:
                    return size

            # Recalculate if expired or missing
            size = self._calculate_total_size()
            self._cache["total_size"] = (size, time.time())
            return size

    def invalidate(self):
        """Force recalculation on next request."""
        with self._lock:
            self._cache.clear()

quota_cache = QuotaCache(ttl=60)  # 1-minute cache
```

**Benefits:**
- Reduces upload latency by ~200ms per request
- Prevents I/O bottleneck under high load
- Simple implementation, low risk

**Testing:**
```python
def test_quota_cache_performance():
    """Verify cache reduces calculation time."""
    start = time.time()
    size1 = quota_cache.get_cached_size()
    duration1 = time.time() - start

    start = time.time()
    size2 = quota_cache.get_cached_size()
    duration2 = time.time() - start

    assert size1 == size2
    assert duration2 < duration1 * 0.1  # 10x faster
```

---

### QW-2: Multi-Worker Cleanup Coordination
**Priority:** 🔴 CRITICAL | **Effort:** 4h | **Impact:** High

**Problem:** APScheduler runs on each Gunicorn worker, causing duplicate cleanup tasks.

**Solution 1: Leader Election (Simple)**
```python
# app/services/cleanup.py (NEW FILE)

import os

def is_cleanup_leader() -> bool:
    """
    Determine if this worker should run scheduled tasks.
    Only worker 0 runs cleanup to avoid duplication.
    """
    # Gunicorn sets GUNICORN_WORKER_ID for each worker
    worker_id = os.getenv("GUNICORN_WORKER_ID", "0")
    return worker_id == "0"

# app/app.py
if is_cleanup_leader():
    scheduler.add_job(
        func=cleanup_expired_files,
        trigger="interval",
        minutes=cleanup_interval_minutes,
        id="cleanup_expired_files",
    )
    logger.info("Cleanup scheduler initialized (leader worker)")
else:
    logger.info("Cleanup scheduler skipped (follower worker)")
```

**Solution 2: File-based Lock (Robust)**
```python
import fcntl

def acquire_cleanup_lock() -> bool:
    """Try to acquire exclusive cleanup lock."""
    lock_path = os.path.join(DATA_DIR, ".cleanup.lock")
    try:
        lock_file = open(lock_path, "w")
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except IOError:
        return False  # Another worker has the lock

@scheduler.scheduled_job("interval", minutes=5)
def cleanup_with_lock():
    """Run cleanup only if lock acquired."""
    if acquire_cleanup_lock():
        try:
            cleanup_expired_files()
        finally:
            release_cleanup_lock()
```

**Benefits:**
- Eliminates duplicate cleanup operations
- Reduces database contention
- Prevents race conditions

---

### QW-3: Dependency Updates
**Priority:** 🟡 IMPORTANT | **Effort:** 2h | **Impact:** Medium

**Problem:** Several dependencies are outdated with security patches available.

**Solution:**
```txt
# requirements.txt (UPDATED)

Flask==3.1.0           # Security updates, performance improvements
gunicorn==23.0.0       # Better worker management
APScheduler==3.11.0    # Bug fixes
Flask-WTF==1.2.2       # CSRF improvements
Flask-Limiter==3.8.0   # New storage backends
requests==2.32.3       # Security fixes
itsdangerous==2.2.0    # Updated serialization
markupsafe==2.1.5      # Security patches
```

**Testing Strategy:**
1. Update in development environment
2. Run full test suite
3. Manual smoke testing of all endpoints
4. Monitor error logs for 24 hours
5. Deploy to production

**Rollback Plan:**
- Git tag before update
- Quick revert if critical issues found
- Communicate with users about maintenance window

---

### QW-4: Structured Logging
**Priority:** 🟡 IMPORTANT | **Effort:** 3h | **Impact:** Medium

**Problem:** Current plain-text logging difficult to parse and aggregate.

**Solution:**
```python
# app/logging_config.py (NEW FILE)

import json
import logging
from typing import Any, Dict

class StructuredFormatter(logging.Formatter):
    """Format logs as JSON for aggregation tools."""

    def format(self, record: logging.LogRecord) -> str:
        log_data: Dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add custom fields if present
        if hasattr(record, "request_id"):
            log_data["request_id"] = record.request_id
        if hasattr(record, "user"):
            log_data["user"] = record.user
        if hasattr(record, "file_id"):
            log_data["file_id"] = record.file_id
        if hasattr(record, "extra"):
            log_data["extra"] = record.extra

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)

# Configuration
def configure_logging(log_format: str = "text"):
    """
    Configure application logging.

    Args:
        log_format: "text" for human-readable, "json" for structured
    """
    if log_format == "json":
        formatter = StructuredFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

    # Apply to handlers...
```

**Environment Variable:**
```bash
# Enable JSON logging in production
LOCALHOSTING_LOG_FORMAT=json

# Keep text logging for development
LOCALHOSTING_LOG_FORMAT=text
```

**Benefits:**
- Integration with log aggregation (ELK, Splunk, Datadog)
- Better filtering and searching
- Structured metrics extraction
- Request tracing support

---

## Short-term Enhancements (Months 1-3)
**Focus:** Code Quality, Testing, Architecture

### ST-1: Modularize app.py
**Priority:** 🔴 CRITICAL | **Effort:** 40h | **Impact:** High

**Problem:** 4,893-line monolithic file difficult to navigate, test, and maintain.

**Solution: Layered Architecture**
```
app/
├── __init__.py                 # Flask app factory
├── routes/
│   ├── __init__.py
│   ├── api_routes.py          # /fileupload, API endpoints
│   ├── ui_routes.py           # /hosting, /settings, /logs
│   ├── download_routes.py     # /download, /files/*, direct paths
│   ├── directory_routes.py    # /directories/*
│   ├── s3_routes.py           # /s3/* endpoints
│   └── box_routes.py          # /2.0/* Box-compatible
├── services/
│   ├── __init__.py
│   ├── auth.py                # Authentication logic
│   ├── validation.py          # Input validation
│   ├── upload_handler.py      # Upload processing
│   ├── cleanup.py             # File cleanup
│   ├── quota.py               # Storage quota management
│   └── link_generator.py      # Download URL generation
├── models/
│   ├── __init__.py
│   └── file.py                # File model and operations
├── middleware/
│   ├── __init__.py
│   ├── rate_limit.py          # Rate limiting config
│   ├── security.py            # Security headers
│   └── error_handler.py       # Global error handling
├── storage.py                 # (existing, minimal changes)
├── config.py                  # Configuration management
└── app_factory.py             # Application initialization
```

**Migration Strategy:**
1. **Week 1:** Create new structure, move routes (API first)
2. **Week 2:** Extract services, update imports
3. **Week 3:** Move remaining logic, test integration
4. **Week 4:** Update tests, documentation, deploy

**Testing Approach:**
- Create parallel structure alongside existing code
- Gradual migration with feature flags
- Comprehensive integration tests
- A/B testing in staging

**Benefits:**
- Easier to navigate and understand
- Better test isolation
- Parallel development on features
- Clearer responsibilities

---

### ST-2: Comprehensive Test Suite
**Priority:** 🔴 CRITICAL | **Effort:** 50h | **Impact:** High

**Goal:** Achieve 80%+ test coverage with pytest

**Test Organization:**
```
tests/
├── conftest.py                # Pytest fixtures and configuration
├── unit/
│   ├── test_validation.py     # Input validation logic
│   ├── test_auth.py           # Authentication functions
│   ├── test_quota.py          # Storage quota calculations
│   ├── test_link_generator.py # URL generation
│   └── test_sanitization.py   # Filename sanitization
├── integration/
│   ├── test_upload_flow.py    # End-to-end upload tests
│   ├── test_download_flow.py  # Download scenarios
│   ├── test_directories.py    # Directory management
│   ├── test_s3_compat.py      # S3 API compatibility
│   ├── test_box_compat.py     # Box API compatibility
│   └── test_retention.py      # Expiration and cleanup
├── security/
│   ├── test_path_traversal.py # Path traversal prevention
│   ├── test_sql_injection.py  # SQL injection prevention
│   ├── test_csrf.py           # CSRF protection
│   ├── test_rate_limiting.py  # Rate limit enforcement
│   └── test_auth_bypass.py    # Authentication bypass attempts
├── performance/
│   ├── test_concurrent_uploads.py   # Concurrency limits
│   ├── test_quota_performance.py    # Quota calculation speed
│   └── test_cleanup_performance.py  # Cleanup efficiency
└── e2e/
    └── test_user_workflows.py       # Full user scenarios
```

**Key Test Categories:**

**1. Security Tests (HIGH PRIORITY)**
```python
# tests/security/test_path_traversal.py

def test_path_traversal_in_filename():
    """Ensure ../../../etc/passwd is sanitized."""
    response = client.post("/fileupload", data={
        "file": (io.BytesIO(b"content"), "../../../etc/passwd")
    })
    assert response.status_code == 201
    file_info = response.json
    assert "etc" not in file_info["original_name"]
    assert ".." not in file_info["original_name"]

def test_path_traversal_in_direct_path():
    """Ensure direct paths don't escape upload directory."""
    # Attempt to craft malicious direct path
    response = client.get("/../../etc/passwd")
    assert response.status_code == 404

def test_null_byte_injection():
    """Ensure null bytes in filenames are rejected."""
    response = client.post("/fileupload", data={
        "file": (io.BytesIO(b"content"), "file\x00.txt")
    })
    # Should either reject or sanitize
    assert response.status_code in [201, 400]
    if response.status_code == 201:
        assert "\x00" not in response.json["original_name"]
```

**2. Concurrency Tests**
```python
# tests/performance/test_concurrent_uploads.py

import concurrent.futures
import pytest

def test_upload_semaphore_limit():
    """Verify max concurrent uploads is enforced."""
    max_concurrent = 10  # From config

    def upload_file(i):
        return client.post("/fileupload", data={
            "file": (io.BytesIO(b"x" * 1000000), f"file{i}.bin")
        })

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(upload_file, i) for i in range(20)]
        results = [f.result() for f in futures]

    # All should succeed eventually
    assert all(r.status_code in [201, 429] for r in results)

    # But not more than 10 running at once
    # (This requires instrumentation in the upload handler)
```

**3. API Compatibility Tests**
```python
# tests/integration/test_s3_compat.py

import boto3
from moto import mock_s3  # For client-side testing

def test_s3_put_object():
    """Test S3 PUT object compatibility."""
    response = client.put(
        "/s3/test-bucket/my-file.txt",
        data=b"Hello S3",
        headers={"Content-Type": "text/plain"}
    )
    assert response.status_code == 200
    assert "ETag" in response.json

def test_s3_client_compatibility():
    """Test with actual boto3 S3 client."""
    s3 = boto3.client(
        "s3",
        endpoint_url="http://localhost:8000",
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy",
    )

    # This should work with LocalHostingAPI
    s3.put_object(
        Bucket="test-bucket",
        Key="test-file.txt",
        Body=b"Hello from boto3"
    )
```

**Testing Tools:**
```txt
# requirements-dev.txt

pytest==8.3.0
pytest-cov==6.0.0
pytest-flask==1.3.0
pytest-benchmark==5.1.0
pytest-xdist==3.6.1          # Parallel test execution
pytest-timeout==2.3.1         # Timeout protection
pytest-mock==3.14.0           # Mocking utilities
faker==33.1.0                 # Test data generation
factory-boy==3.3.1            # Model factories
freezegun==1.5.1              # Time manipulation
responses==0.25.3             # HTTP mocking
```

**Coverage Goals:**
- Overall: 80%+
- Critical paths (upload/download): 95%+
- Security functions: 100%
- Error handling: 90%+

---

### ST-3: Type Hints & Static Analysis
**Priority:** 🟡 IMPORTANT | **Effort:** 30h | **Impact:** Medium

**Goal:** Add comprehensive type hints and enable mypy checking.

**Example Transformations:**
```python
# BEFORE
def sanitize_filename(name, max_length=None):
    if not name:
        raise ValueError("Filename cannot be empty")
    # ...
    return cleaned

# AFTER
from typing import Optional

def sanitize_filename(
    name: str,
    max_length: Optional[int] = None
) -> str:
    """
    Sanitize a filename for safe storage.

    Args:
        name: Original filename to sanitize
        max_length: Maximum filename length (default: 255)

    Returns:
        Sanitized filename safe for filesystem

    Raises:
        ValueError: If filename is empty after sanitization
    """
    if not name:
        raise ValueError("Filename cannot be empty")
    # ...
    return cleaned
```

**Mypy Configuration:**
```ini
# mypy.ini

[mypy]
python_version = 3.11
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = True
disallow_incomplete_defs = True
check_untyped_defs = True
no_implicit_optional = True
warn_redundant_casts = True
warn_unused_ignores = True
warn_no_return = True
warn_unreachable = True
strict_equality = True

# Start strict in new code
[mypy-app.routes.*]
disallow_untyped_defs = True

# Gradually enable for existing code
[mypy-app.storage]
disallow_untyped_defs = False  # TODO: Enable after refactoring
```

**Benefits:**
- Catch type errors before runtime
- Better IDE autocomplete
- Self-documenting code
- Easier refactoring

---

### ST-4: Database Migration System
**Priority:** 🟡 IMPORTANT | **Effort:** 20h | **Impact:** Medium

**Problem:** Schema changes handled with ad-hoc migration functions, no versioning.

**Solution: Alembic Integration**
```bash
pip install alembic==1.14.0
alembic init migrations
```

**Configuration:**
```python
# migrations/env.py

from app.storage import get_db
from alembic import context

def run_migrations_online():
    """Run migrations in 'online' mode."""
    with get_db() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # Required for SQLite
        )

        with context.begin_transaction():
            context.run_migrations()
```

**Migration Example:**
```python
# migrations/versions/001_add_file_metadata.py

from alembic import op
import sqlalchemy as sa

def upgrade():
    """Add metadata column to files table."""
    op.add_column('files', sa.Column('metadata', sa.Text, nullable=True))

def downgrade():
    """Remove metadata column from files table."""
    op.drop_column('files', 'metadata')
```

**Commands:**
```bash
# Create new migration
alembic revision -m "Add user_id to files"

# Apply migrations
alembic upgrade head

# Rollback last migration
alembic downgrade -1

# Show current version
alembic current
```

**Benefits:**
- Version-controlled schema changes
- Rollback capability
- Reproducible deployments
- Clear upgrade path

---

### ST-5: API Documentation (OpenAPI)
**Priority:** 🟡 IMPORTANT | **Effort:** 15h | **Impact:** Medium

**Solution: Flask-RESTX or Flasgger**
```python
# Using Flask-RESTX for OpenAPI 3.0

from flask_restx import Api, Resource, fields

api = Api(
    app,
    version="1.0",
    title="LocalHostingAPI",
    description="Self-hosted file upload service",
    doc="/api-docs",
)

# Define models
upload_model = api.model("Upload", {
    "file_id": fields.String(description="Unique file identifier"),
    "original_name": fields.String(description="Original filename"),
    "size": fields.Integer(description="File size in bytes"),
    "content_type": fields.String(description="MIME type"),
    "uploaded_at": fields.Float(description="Upload timestamp"),
    "expires_at": fields.Float(description="Expiration timestamp"),
    "download_url": fields.String(description="ID-based download URL"),
    "direct_download_url": fields.String(description="Filename-based URL"),
})

# Document endpoints
@api.route("/fileupload")
class FileUpload(Resource):
    @api.doc("upload_file")
    @api.expect(upload_parser)
    @api.marshal_with(upload_model, code=201)
    @api.response(400, "Invalid request")
    @api.response(507, "Storage quota exceeded")
    def post(self):
        """Upload a new file."""
        # Implementation...
```

**Generated Documentation:**
- Interactive Swagger UI at `/api-docs`
- OpenAPI 3.0 JSON spec at `/swagger.json`
- Automatic request/response validation
- Example requests with curl/Python/JavaScript

---

## Medium-term Enhancements (Months 4-6)
**Focus:** Performance, Scalability, Features

### MT-1: Redis-backed Rate Limiting
**Priority:** 🔴 CRITICAL | **Effort:** 8h | **Impact:** High

**Problem:** In-memory rate limiting doesn't persist across restarts or workers.

**Solution:**
```python
# requirements.txt
redis==5.2.1
Flask-Limiter[redis]==3.8.0

# app/middleware/rate_limit.py

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

redis_client = redis.from_url(
    os.getenv("LOCALHOSTING_RATE_LIMIT_STORAGE", "redis://localhost:6379/0")
)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=os.getenv("LOCALHOSTING_RATE_LIMIT_STORAGE"),
    default_limits=["1000/day", "100/hour"],
)

# Per-endpoint limits
@limiter.limit("10/minute")
@app.route("/login", methods=["POST"])
def login():
    # ...
```

**Docker Compose:**
```yaml
# docker-compose.yml

services:
  app:
    # ... existing config ...
    environment:
      - LOCALHOSTING_RATE_LIMIT_STORAGE=redis://redis:6379/0
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    command: redis-server --save 60 1 --loglevel warning

volumes:
  redis_data:
```

**Benefits:**
- Persistent rate limiting across restarts
- Shared limits across workers
- Better DDoS protection
- Foundation for future caching

---

### MT-2: Database Connection Pooling
**Priority:** 🟡 IMPORTANT | **Effort:** 10h | **Impact:** Medium

**Problem:** Each request creates new database connection, inefficient under load.

**Solution: SQLAlchemy Integration**
```python
# app/database.py (NEW FILE)

from sqlalchemy import create_engine, event
from sqlalchemy.pool import QueuePool

DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,           # Max connections
    max_overflow=20,        # Extra connections under load
    pool_timeout=30,        # Wait time for connection
    pool_recycle=3600,      # Recycle after 1 hour
    connect_args={
        "timeout": 30,
        "check_same_thread": False,  # Allow multi-threading
    },
)

# Enable WAL mode on connection
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()

# Context manager
@contextmanager
def get_db_session():
    """Get database connection from pool."""
    connection = engine.connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
```

**Benefits:**
- Reduced connection overhead
- Better performance under load
- Automatic connection lifecycle
- Prepared for PostgreSQL migration

---

### MT-3: Query Optimization & Caching
**Priority:** 🟡 IMPORTANT | **Effort:** 15h | **Impact:** Medium

**Problem:** File listings and directory queries regenerated on every request.

**Solution 1: Query Optimization**
```python
# Add indexes for common queries
CREATE INDEX idx_files_uploaded_at_desc ON files(uploaded_at DESC);
CREATE INDEX idx_files_size ON files(size);
CREATE INDEX idx_directories_created_at_desc ON directories(created_at DESC);

# Optimize pagination query
def get_files_page(offset: int, limit: int, sort_by: str = "uploaded_at"):
    """Get paginated files with optimized query."""
    query = """
        SELECT id, original_name, size, uploaded_at, expires_at
        FROM files
        WHERE permanent = 0 OR expires_at > ?
        ORDER BY {} DESC
        LIMIT ? OFFSET ?
    """.format(sort_by)  # Validated against whitelist

    with get_db() as conn:
        rows = conn.execute(query, (time.time(), limit, offset)).fetchall()

    return [dict(row) for row in rows]
```

**Solution 2: Redis Caching**
```python
# app/services/cache.py

import json
import redis
from functools import wraps

redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/1"))

def cache_result(ttl: int = 300, key_prefix: str = ""):
    """Cache function result in Redis."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = f"{key_prefix}:{func.__name__}:{hash(str(args) + str(kwargs))}"

            # Check cache
            cached = redis_client.get(cache_key)
            if cached:
                return json.loads(cached)

            # Execute and cache
            result = func(*args, **kwargs)
            redis_client.setex(cache_key, ttl, json.dumps(result))
            return result

        return wrapper
    return decorator

# Usage
@cache_result(ttl=60, key_prefix="files")
def get_file_listing(page: int = 1, sort: str = "uploaded_at"):
    """Get file listing with caching."""
    # ... expensive query ...
    return results
```

**Benefits:**
- Faster page loads (60-80% reduction)
- Reduced database load
- Better scalability
- Cache invalidation on uploads/deletes

---

### MT-4: Webhook System
**Priority:** 🟢 NICE-TO-HAVE | **Effort:** 25h | **Impact:** Medium

**Use Cases:**
- Notify external systems on upload
- Trigger workflows on file expiration
- Integration with CI/CD pipelines
- Audit trail integration

**Implementation:**
```python
# app/models/webhook.py

from typing import Dict, List, Optional
import requests
import hashlib
import hmac

class WebhookEvent:
    """Webhook event types."""
    FILE_UPLOADED = "file.uploaded"
    FILE_DOWNLOADED = "file.downloaded"
    FILE_DELETED = "file.deleted"
    FILE_EXPIRED = "file.expired"

def deliver_webhook(
    event: str,
    payload: Dict,
    webhook_url: str,
    secret: Optional[str] = None
) -> bool:
    """
    Deliver webhook to external endpoint.

    Args:
        event: Event type (e.g., "file.uploaded")
        payload: Event data
        webhook_url: Destination URL
        secret: Optional HMAC secret for signature

    Returns:
        True if delivered successfully
    """
    headers = {
        "Content-Type": "application/json",
        "X-LocalHosting-Event": event,
        "User-Agent": "LocalHostingAPI/1.0",
    }

    # Sign payload if secret provided
    if secret:
        signature = hmac.new(
            secret.encode(),
            json.dumps(payload).encode(),
            hashlib.sha256
        ).hexdigest()
        headers["X-LocalHosting-Signature"] = f"sha256={signature}"

    try:
        response = requests.post(
            webhook_url,
            json=payload,
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        return True
    except requests.RequestException as e:
        logger.error(f"Webhook delivery failed: {e}")
        return False

# Usage in upload handler
@app.route("/fileupload", methods=["POST"])
def fileupload():
    # ... process upload ...

    # Trigger webhook
    webhooks = get_active_webhooks()  # From config
    for webhook in webhooks:
        if WebhookEvent.FILE_UPLOADED in webhook["events"]:
            deliver_webhook(
                event=WebhookEvent.FILE_UPLOADED,
                payload={
                    "file_id": file_id,
                    "original_name": original_name,
                    "size": size,
                    "uploaded_at": uploaded_at,
                    "download_url": download_url,
                },
                webhook_url=webhook["url"],
                secret=webhook.get("secret"),
            )
```

**Configuration:**
```json
// config.json
{
    "webhooks": [
        {
            "id": "webhook_001",
            "url": "https://example.com/webhook",
            "events": ["file.uploaded", "file.expired"],
            "secret": "your_webhook_secret",
            "active": true
        }
    ]
}
```

**Benefits:**
- External system integration
- Real-time notifications
- Workflow automation
- Audit trail

---

### MT-5: File Deduplication
**Priority:** 🟢 NICE-TO-HAVE | **Effort:** 30h | **Impact:** Medium

**Problem:** Identical files uploaded multiple times waste storage.

**Solution: Content-addressed Storage**
```python
# app/services/deduplication.py

import hashlib
from typing import Optional, Tuple

def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA-256 hash of file content."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def find_duplicate(content_hash: str) -> Optional[str]:
    """Check if file with same hash already exists."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT stored_name FROM files WHERE content_hash = ? LIMIT 1",
            (content_hash,)
        ).fetchone()
    return row["stored_name"] if row else None

def store_file_deduplicated(
    uploaded_file,
    original_name: str
) -> Tuple[str, bool]:
    """
    Store file with deduplication.

    Returns:
        (stored_name, is_duplicate)
    """
    # Save to temp location
    temp_path = save_temp_file(uploaded_file)

    # Calculate hash
    content_hash = calculate_file_hash(temp_path)

    # Check for duplicate
    existing = find_duplicate(content_hash)
    if existing:
        os.remove(temp_path)  # Delete temp file
        increment_reference_count(existing)
        return existing, True

    # Move to permanent location
    stored_name = generate_stored_name(original_name)
    permanent_path = get_storage_path(stored_name)
    os.rename(temp_path, permanent_path)

    return stored_name, False
```

**Schema Changes:**
```sql
-- Add content_hash column
ALTER TABLE files ADD COLUMN content_hash TEXT;
CREATE INDEX idx_files_content_hash ON files(content_hash);

-- Add reference counting
ALTER TABLE files ADD COLUMN reference_count INTEGER DEFAULT 1;
```

**Cleanup Considerations:**
```python
def cleanup_file_with_refcount(file_id: str):
    """Delete file only when reference count reaches zero."""
    with get_db() as conn:
        # Decrement reference count
        conn.execute(
            "UPDATE files SET reference_count = reference_count - 1 WHERE id = ?",
            (file_id,)
        )

        # Get updated count
        row = conn.execute(
            "SELECT reference_count, stored_name FROM files WHERE id = ?",
            (file_id,)
        ).fetchone()

        if row["reference_count"] <= 0:
            # Actually delete file from disk
            delete_from_disk(row["stored_name"])
            conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
```

**Benefits:**
- 30-70% storage reduction (depending on workload)
- Faster uploads for duplicates
- Bandwidth savings
- Automatic deduplication

---

## Long-term Enhancements (Months 7-12)
**Focus:** Enterprise Features, Scalability

### LT-1: Multi-Tenancy Support
**Priority:** 🔴 CRITICAL | **Effort:** 80h | **Impact:** High

**Goal:** Support multiple isolated tenants (organizations/teams) in single deployment.

**Schema Changes:**
```sql
-- Add tenants table
CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at REAL NOT NULL,
    storage_quota_gb REAL DEFAULT 10.0,
    max_upload_size_mb REAL DEFAULT 500.0,
    retention_default_hours REAL DEFAULT 24.0,
    active INTEGER DEFAULT 1
);

-- Add users table
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    username TEXT NOT NULL,
    email TEXT,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',  -- admin, user, viewer
    created_at REAL NOT NULL,
    last_login_at REAL,
    active INTEGER DEFAULT 1,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    UNIQUE(tenant_id, username)
);

-- Update files table
ALTER TABLE files ADD COLUMN tenant_id TEXT;
ALTER TABLE files ADD COLUMN uploaded_by TEXT;  -- user_id
CREATE INDEX idx_files_tenant_id ON files(tenant_id);
CREATE INDEX idx_files_uploaded_by ON files(uploaded_by);

-- Add tenant-specific API keys
ALTER TABLE api_keys ADD COLUMN tenant_id TEXT;
```

**Isolation Layers:**
```python
# app/services/tenant.py

from flask import g, request
from functools import wraps

def get_current_tenant() -> Optional[str]:
    """Extract tenant from API key or session."""
    # Check API key
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return get_tenant_from_api_key(api_key)

    # Check session
    if "user_id" in session:
        return get_tenant_from_user(session["user_id"])

    return None

def require_tenant(func):
    """Ensure request has valid tenant context."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        tenant_id = get_current_tenant()
        if not tenant_id:
            return jsonify({"error": "Unauthorized"}), 401

        g.tenant_id = tenant_id
        return func(*args, **kwargs)

    return wrapper

# Usage
@app.route("/fileupload", methods=["POST"])
@require_tenant
def fileupload():
    tenant_id = g.tenant_id

    # Check tenant quota
    if exceeds_tenant_quota(tenant_id):
        return jsonify({"error": "Tenant storage quota exceeded"}), 507

    # Store with tenant context
    file_id = store_file(
        file=request.files["file"],
        tenant_id=tenant_id,
        uploaded_by=g.get("user_id"),
    )
```

**Per-Tenant Configuration:**
```python
def get_tenant_config(tenant_id: str) -> Dict:
    """Get tenant-specific configuration."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM tenants WHERE id = ?",
            (tenant_id,)
        ).fetchone()

    return {
        "storage_quota_gb": row["storage_quota_gb"],
        "max_upload_size_mb": row["max_upload_size_mb"],
        "retention_default_hours": row["retention_default_hours"],
    }
```

**Benefits:**
- Serve multiple organizations from single deployment
- Isolated storage and quotas
- Per-tenant billing and analytics
- Enterprise feature enabler

---

### LT-2: Role-Based Access Control (RBAC)
**Priority:** 🟡 IMPORTANT | **Effort:** 60h | **Impact:** High

**Roles:**
- **Admin** - Full access, user management, settings
- **Uploader** - Can upload and delete own files
- **Viewer** - Can view and download files only
- **API** - Programmatic access only

**Implementation:**
```python
# app/models/permission.py

from enum import Enum

class Permission(Enum):
    """Fine-grained permissions."""
    UPLOAD_FILE = "upload:file"
    DOWNLOAD_FILE = "download:file"
    DELETE_FILE = "delete:file"
    VIEW_FILE = "view:file"
    MANAGE_USERS = "manage:users"
    MANAGE_SETTINGS = "manage:settings"
    VIEW_LOGS = "view:logs"
    MANAGE_API_KEYS = "manage:api_keys"

ROLE_PERMISSIONS = {
    "admin": [p for p in Permission],  # All permissions
    "uploader": [
        Permission.UPLOAD_FILE,
        Permission.DOWNLOAD_FILE,
        Permission.VIEW_FILE,
        Permission.DELETE_FILE,  # Own files only
    ],
    "viewer": [
        Permission.VIEW_FILE,
        Permission.DOWNLOAD_FILE,
    ],
    "api": [
        Permission.UPLOAD_FILE,
        Permission.DOWNLOAD_FILE,
    ],
}

def has_permission(user_id: str, permission: Permission) -> bool:
    """Check if user has specific permission."""
    user = get_user(user_id)
    role_perms = ROLE_PERMISSIONS.get(user["role"], [])
    return permission in role_perms

def require_permission(permission: Permission):
    """Decorator to enforce permission check."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = g.get("user_id")
            if not user_id or not has_permission(user_id, permission):
                return jsonify({"error": "Forbidden"}), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Usage
@app.route("/settings", methods=["POST"])
@require_permission(Permission.MANAGE_SETTINGS)
def update_settings():
    # Only admins can reach here
    ...
```

**Benefits:**
- Granular access control
- Compliance requirements (SOC2, ISO 27001)
- Audit trail foundation
- Enterprise readiness

---

### LT-3: S3 Backend Support
**Priority:** 🟢 NICE-TO-HAVE | **Effort:** 50h | **Impact:** High

**Goal:** Support AWS S3, MinIO, or other S3-compatible storage as backend.

**Architecture:**
```python
# app/storage/backends/__init__.py

from abc import ABC, abstractmethod
from typing import BinaryIO, Optional

class StorageBackend(ABC):
    """Abstract storage backend interface."""

    @abstractmethod
    def store_file(self, file: BinaryIO, key: str) -> str:
        """Store file and return storage key."""
        pass

    @abstractmethod
    def retrieve_file(self, key: str) -> BinaryIO:
        """Retrieve file by key."""
        pass

    @abstractmethod
    def delete_file(self, key: str) -> bool:
        """Delete file by key."""
        pass

    @abstractmethod
    def get_file_size(self, key: str) -> int:
        """Get file size in bytes."""
        pass

    @abstractmethod
    def file_exists(self, key: str) -> bool:
        """Check if file exists."""
        pass
```

**Local Filesystem Backend (Current):**
```python
# app/storage/backends/filesystem.py

class FilesystemBackend(StorageBackend):
    """Local filesystem storage."""

    def __init__(self, base_path: str):
        self.base_path = base_path

    def store_file(self, file: BinaryIO, key: str) -> str:
        path = os.path.join(self.base_path, key)
        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, "wb") as f:
            f.write(file.read())

        return key

    def retrieve_file(self, key: str) -> BinaryIO:
        path = os.path.join(self.base_path, key)
        return open(path, "rb")

    # ... other methods ...
```

**S3 Backend:**
```python
# app/storage/backends/s3.py

import boto3
from botocore.exceptions import ClientError

class S3Backend(StorageBackend):
    """AWS S3 storage backend."""

    def __init__(
        self,
        bucket: str,
        endpoint_url: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
    ):
        self.bucket = bucket
        self.s3 = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

    def store_file(self, file: BinaryIO, key: str) -> str:
        self.s3.upload_fileobj(file, self.bucket, key)
        return key

    def retrieve_file(self, key: str) -> BinaryIO:
        from io import BytesIO
        buffer = BytesIO()
        self.s3.download_fileobj(self.bucket, key, buffer)
        buffer.seek(0)
        return buffer

    def delete_file(self, key: str) -> bool:
        try:
            self.s3.delete_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError:
            return False

    def get_file_size(self, key: str) -> int:
        response = self.s3.head_object(Bucket=self.bucket, Key=key)
        return response["ContentLength"]

    def file_exists(self, key: str) -> bool:
        try:
            self.s3.head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError:
            return False
```

**Configuration:**
```python
# Environment-based backend selection
STORAGE_BACKEND = os.getenv("LOCALHOSTING_STORAGE_BACKEND", "filesystem")

if STORAGE_BACKEND == "s3":
    backend = S3Backend(
        bucket=os.getenv("S3_BUCKET"),
        endpoint_url=os.getenv("S3_ENDPOINT_URL"),
        access_key=os.getenv("S3_ACCESS_KEY"),
        secret_key=os.getenv("S3_SECRET_KEY"),
    )
elif STORAGE_BACKEND == "filesystem":
    backend = FilesystemBackend(UPLOADS_DIR)
else:
    raise ValueError(f"Unknown storage backend: {STORAGE_BACKEND}")
```

**Benefits:**
- Unlimited storage capacity
- Built-in redundancy and durability
- Geographic distribution
- Compliance certifications (AWS)

---

### LT-4: Audit Trail & Compliance
**Priority:** 🟡 IMPORTANT | **Effort:** 40h | **Impact:** Medium

**Goal:** Comprehensive audit logging for compliance (GDPR, HIPAA, SOC2).

**Schema:**
```sql
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,
    user_id TEXT,
    action TEXT NOT NULL,  -- upload, download, delete, view, modify
    resource_type TEXT NOT NULL,  -- file, directory, user, setting
    resource_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    timestamp REAL NOT NULL,
    metadata TEXT,  -- JSON with action-specific details
    success INTEGER DEFAULT 1,
    INDEX idx_audit_tenant_time (tenant_id, timestamp),
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_resource (resource_type, resource_id)
);
```

**Audit Decorator:**
```python
# app/services/audit.py

def audit_log(
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None
):
    """Decorator to automatically log actions."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            success = False
            error = None

            try:
                result = func(*args, **kwargs)
                success = True
                return result
            except Exception as e:
                error = str(e)
                raise
            finally:
                create_audit_entry(
                    tenant_id=g.get("tenant_id"),
                    user_id=g.get("user_id"),
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id or kwargs.get("file_id"),
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string,
                    timestamp=start_time,
                    success=success,
                    metadata={
                        "duration_ms": (time.time() - start_time) * 1000,
                        "error": error,
                    },
                )

        return wrapper
    return decorator

# Usage
@app.route("/download/<file_id>")
@audit_log(action="download", resource_type="file")
def download_file(file_id: str):
    # Download logic...
```

**Compliance Reports:**
```python
def generate_access_report(
    tenant_id: str,
    start_date: float,
    end_date: float
) -> List[Dict]:
    """Generate access report for compliance."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT
                user_id,
                action,
                resource_id,
                timestamp,
                ip_address
            FROM audit_log
            WHERE tenant_id = ?
              AND timestamp BETWEEN ? AND ?
              AND action IN ('download', 'view')
            ORDER BY timestamp DESC
        """, (tenant_id, start_date, end_date)).fetchall()

    return [dict(row) for row in rows]
```

**Benefits:**
- Regulatory compliance
- Security investigation support
- User activity tracking
- Evidence for audits

---

## Feature Backlog

### High-Value Features (Not Yet Prioritized)

1. **Batch Download as ZIP** - Download multiple files as archive
2. **File Versioning** - Keep multiple versions of same file
3. **Upload Resumption** - Resume interrupted uploads (tus protocol)
4. **Client-Side Encryption** - E2E encrypted file storage
5. **Video Thumbnails** - Generate preview thumbnails for videos
6. **Image Resizing** - Automatic image optimization
7. **File Compression** - Auto-compress before storage
8. **Shared Albums** - Public galleries with multiple files
9. **Temporary Upload Links** - Time-limited upload URLs
10. **Mobile App** - Native iOS/Android app
11. **Desktop App** - Electron-based desktop client
12. **Browser Extension** - Quick upload from context menu
13. **CLI Tool** - Command-line upload/download
14. **Metrics Dashboard** - Analytics and usage statistics
15. **Email Notifications** - Alerts for expiring files

---

## Technical Debt Tracking

### Current Technical Debt

| ID | Description | Impact | Effort | Priority |
|----|-------------|--------|--------|----------|
| TD-1 | Monolithic app.py (4,893 lines) | High | 40h | 🔴 Critical |
| TD-2 | No database migrations (Alembic) | Medium | 20h | 🟡 Important |
| TD-3 | Limited type hints | Medium | 30h | 🟡 Important |
| TD-4 | Test coverage below 50% | High | 50h | 🔴 Critical |
| TD-5 | In-memory rate limiting | Medium | 8h | 🟡 Important |
| TD-6 | No connection pooling | Low | 10h | 🟢 Nice-to-have |
| TD-7 | Plain-text logging only | Low | 3h | 🟢 Nice-to-have |
| TD-8 | Manual config file parsing | Low | 5h | 🟢 Nice-to-have |
| TD-9 | No API documentation (OpenAPI) | Medium | 15h | 🟡 Important |
| TD-10 | Generic exception handling | Medium | 10h | 🟡 Important |

**Total Estimated Debt:** ~191 hours (~5 weeks for 1 developer)

---

## Success Metrics

### Key Performance Indicators (KPIs)

**Code Quality:**
- Test coverage: Target 80%+ (current ~35%)
- Mypy compliance: 100% (current 0%)
- Code complexity: Max 15 cyclomatic complexity per function
- Documentation: All public APIs documented

**Performance:**
- Upload latency: < 100ms overhead (excluding transfer time)
- Download latency: < 50ms to first byte
- API response time (95th percentile): < 200ms
- Concurrent uploads: Support 50+ simultaneous

**Reliability:**
- Uptime: 99.9% (< 9 hours downtime per year)
- Error rate: < 0.1% of requests
- Data durability: 99.99% (no data loss)

**Security:**
- Zero critical vulnerabilities
- CSRF protection: 100% of forms
- Rate limiting: All public endpoints
- Audit logging: All sensitive operations

**User Satisfaction:**
- API compatibility: Maintain 100% backward compatibility
- Documentation clarity: User feedback > 4/5
- Setup time: < 10 minutes from clone to running

---

## Deployment Roadmap

### Version 1.1 (Month 1-2) - Stability
**Focus:** Code quality, testing, bug fixes

- ✅ Refactor app.py into modules
- ✅ Comprehensive test suite (80% coverage)
- ✅ Dependency updates
- ✅ Bug fixes from production

### Version 1.2 (Month 3-4) - Performance
**Focus:** Speed and scalability

- ✅ Redis-backed rate limiting
- ✅ Database connection pooling
- ✅ Query optimization and caching
- ✅ Storage quota caching

### Version 1.3 (Month 5-6) - Features
**Focus:** New capabilities

- ✅ Webhook system
- ✅ File deduplication
- ✅ Batch operations
- ✅ Enhanced API documentation

### Version 2.0 (Month 7-9) - Enterprise
**Focus:** Multi-tenancy and RBAC

- ✅ Multi-tenant support
- ✅ Role-based access control
- ✅ Audit trail
- ✅ Advanced user management

### Version 2.1 (Month 10-12) - Scale
**Focus:** Cloud-ready architecture

- ✅ S3 backend support
- ✅ Kubernetes manifests
- ✅ Horizontal scaling support
- ✅ Prometheus metrics

---

## Conclusion

This enhancement plan provides a **structured, phased approach** to improving LocalHostingAPI over the next 12 months. By focusing on quick wins first, then systematically addressing code quality, performance, and enterprise features, the project will evolve into a robust, scalable file hosting solution.

**Key Principles:**
1. Start with quick wins to build momentum
2. Address technical debt before adding features
3. Maintain backward compatibility
4. Measure impact of all changes
5. Prioritize security and reliability

**Next Steps:**
1. Review and approve this plan with stakeholders
2. Begin with Quick Wins sprint (1-2 weeks)
3. Establish continuous integration/deployment pipeline
4. Set up monitoring and metrics collection
5. Create regular release schedule (monthly)

**Estimated Total Effort:** ~600 hours over 12 months (1.5 developers full-time)

---

**Document Version:** 1.0
**Last Updated:** 2025-11-16
**Owner:** Development Team
**Review Schedule:** Monthly
