import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qsl, quote, urlparse
from xml.etree import ElementTree as ET

from werkzeug.security import check_password_hash


class LocalHostingAppIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.storage_dir = tempfile.TemporaryDirectory()
        root = Path(self.storage_dir.name)
        os.environ["LOCALHOSTING_STORAGE_ROOT"] = str(root)
        os.environ["LOCALHOSTING_DATA_DIR"] = str(root / "data")
        os.environ["LOCALHOSTING_UPLOADS_DIR"] = str(root / "uploads")
        os.environ["LOCALHOSTING_LOGS_DIR"] = str(root / "logs")
        self._reload_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()

    def tearDown(self):
        self.storage_dir.cleanup()
        for key in [
            "LOCALHOSTING_STORAGE_ROOT",
            "LOCALHOSTING_DATA_DIR",
            "LOCALHOSTING_UPLOADS_DIR",
            "LOCALHOSTING_LOGS_DIR",
            "LOCALHOSTING_DOCKER_LOG_PATH",
            "LOCALHOSTING_BLOCKED_EXTENSIONS",
            "LOCALHOSTING_STORAGE_QUOTA_GB",
        ]:
            os.environ.pop(key, None)
        for module in ["app.app", "app.storage", "app"]:
            sys.modules.pop(module, None)

    def _reload_app(self):
        for module in ["app.app", "app.storage", "app"]:
            if module in sys.modules:
                del sys.modules[module]
        import importlib

        app_module = importlib.import_module("app.app")  # noqa: WPS433
        storage = importlib.import_module("app.storage")  # noqa: WPS433

        self.app = app_module.app
        self.storage = storage
        self.app_module = app_module

    def test_upload_and_download_flow(self):
        response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"hello world"), "sample.txt"),
                "retention_hours": "1.5",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertIsNotNone(payload)
        self.assertIn("id", payload)
        self.assertEqual(payload["filename"], "sample.txt")

        download_path = urlparse(payload["download_url"]).path
        direct_path = urlparse(payload["direct_download_url"]).path
        raw_path = urlparse(payload["raw_download_url"]).path

        download_response = self.client.get(download_path)
        self.assertEqual(download_response.status_code, 200)
        self.assertIn("attachment", download_response.headers.get("Content-Disposition", ""))
        self.assertEqual(download_response.data, b"hello world")
        download_response.close()

        direct_response = self.client.get(direct_path)
        self.assertEqual(direct_response.status_code, 200)
        self.assertIn("attachment", direct_response.headers.get("Content-Disposition", ""))
        self.assertEqual(direct_response.data, b"hello world")
        direct_response.close()

        raw_response = self.client.get(raw_path)
        self.assertEqual(raw_response.status_code, 200)
        self.assertNotIn("attachment", raw_response.headers.get("Content-Disposition", ""))
        self.assertEqual(raw_response.data, b"hello world")
        raw_response.close()

        uploads_dir = Path(os.environ["LOCALHOSTING_UPLOADS_DIR"])
        record = self.storage.get_file(payload["id"])
        self.assertIsNotNone(record)
        file_path = self.storage.get_storage_path(record["id"], record["stored_name"])
        self.assertTrue(file_path.exists())
        self.assertEqual(file_path.parent.parent, uploads_dir)

    def test_retention_validation_and_cleanup(self):
        invalid_response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"oops"), "bad.txt"),
                "retention_hours": "9999",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(invalid_response.status_code, 400)
        error = invalid_response.get_json()
        self.assertIn("error", error)

        expiry_response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"soon gone"), "expire.txt"),
                "retention_hours": "0",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(expiry_response.status_code, 201)
        payload = expiry_response.get_json()
        download_path = urlparse(payload["download_url"]).path

        # File should be considered expired immediately and removed on access.
        download_response = self.client.get(download_path)
        self.assertEqual(download_response.status_code, 404)

        uploads_dir = Path(os.environ["LOCALHOSTING_UPLOADS_DIR"])
        self.assertFalse(any(path.is_file() for path in uploads_dir.rglob("*")))

    def test_failed_upload_cleanup(self):
        uploads_dir = Path(os.environ["LOCALHOSTING_UPLOADS_DIR"])
        files_before = [path for path in uploads_dir.rglob("*") if path.is_file()]
        count_before = len(files_before)

        response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"x" * 1024), "too_long.txt"),
                "retention_hours": "99999",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

        files_after = [path for path in uploads_dir.rglob("*") if path.is_file()]
        count_after = len(files_after)
        self.assertEqual(count_before, count_after)

        empty_dirs = [
            directory
            for directory in uploads_dir.rglob("*")
            if directory.is_dir() and not any(directory.iterdir())
        ]
        self.assertEqual(len(empty_dirs), 0)

    def test_blocked_extension_rejected(self):
        os.environ["LOCALHOSTING_BLOCKED_EXTENSIONS"] = "exe"
        self._reload_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()

        response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"malware"), "payload.exe"),
                "retention_hours": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertIsInstance(payload, dict)
        self.assertIn("errors", payload)
        reasons = {entry.get("reason") for entry in payload["errors"]}
        self.assertIn("invalid_filename", reasons)

        uploads_dir = Path(os.environ["LOCALHOSTING_UPLOADS_DIR"])
        self.assertFalse(any(uploads_dir.rglob("*.exe")))

    def test_storage_quota_enforced(self):
        os.environ["LOCALHOSTING_STORAGE_QUOTA_GB"] = "0.000001"  # ~1 KB

        response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"x" * 2048), "large.bin"),
                "retention_hours": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 507)
        payload = response.get_json()
        self.assertIsInstance(payload, dict)
        self.assertIn("message", payload)

        uploads_dir = Path(os.environ["LOCALHOSTING_UPLOADS_DIR"])
        self.assertFalse(any(path.is_file() for path in uploads_dir.rglob("*")))

    def test_multi_file_upload_support(self):
        response = self.client.post(
            "/fileupload",
            data={
                "file": [
                    (io.BytesIO(b"first"), "first.txt"),
                    (io.BytesIO(b"second"), "second.txt"),
                ],
                "retention_hours": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertIsNotNone(payload)
        self.assertIn("files", payload)
        self.assertEqual(len(payload["files"]), 2)
        filenames = {entry["filename"] for entry in payload["files"]}
        self.assertSetEqual(filenames, {"first.txt", "second.txt"})

        for entry in payload["files"]:
            self.assertIn("download_url", entry)
            download_path = urlparse(entry["download_url"]).path
            download_response = self.client.get(download_path)
            self.assertEqual(download_response.status_code, 200)
            download_response.close()

        hosting_page = self.client.get("/hosting")
        self.assertEqual(hosting_page.status_code, 200)
        html = hosting_page.data.decode()
        self.assertIn("first.txt", html)
        self.assertIn("second.txt", html)

    def test_multi_file_upload_rolls_back_on_failure(self):
        original_register = self.app_module.register_file
        call_tracker = {"count": 0}

        def register_side_effect(*args, **kwargs):
            if call_tracker["count"] == 0:
                call_tracker["count"] += 1
                return original_register(*args, **kwargs)
            call_tracker["count"] += 1
            raise RuntimeError("forced failure")

        with mock.patch("app.app.register_file", side_effect=register_side_effect):
            response = self.client.post(
                "/fileupload",
                data={
                    "file": [
                        (io.BytesIO(b"valid"), "ok.txt"),
                        (io.BytesIO(b"second"), "boom.txt"),
                    ],
                    "retention_hours": "1",
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertIn("errors", payload)
        self.assertGreaterEqual(len(payload["errors"]), 1)

        files = self.storage.list_files()
        self.assertEqual(len(files), 0)

    def test_settings_update_persists(self):
        retention_response = self.client.post(
            "/settings",
            data={
                "action": "update_retention",
                "retention_min_hours": "1",
                "retention_max_hours": "48",
                "retention_hours": "12",
            },
            follow_redirects=True,
        )
        self.assertEqual(retention_response.status_code, 200)

        performance_response = self.client.post(
            "/settings",
            data={
                "action": "update_performance",
                "max_upload_size_mb": "256",
                "max_concurrent_uploads": "8",
                "cleanup_interval_minutes": "7",
                "upload_rate_limit_per_hour": "90",
                "login_rate_limit_per_minute": "8",
                "download_rate_limit_per_minute": "110",
            },
            follow_redirects=True,
        )
        self.assertEqual(performance_response.status_code, 200)
        self.assertIn(b'name="max_upload_size_mb"', performance_response.data)
        self.assertIn(b'value="256.0"', performance_response.data)

        config = self.storage.load_config()
        self.assertEqual(config["retention_min_hours"], 1.0)
        self.assertEqual(config["retention_max_hours"], 48.0)
        self.assertEqual(config["retention_hours"], 12.0)
        self.assertEqual(config["max_upload_size_mb"], 256.0)
        self.assertEqual(config["max_concurrent_uploads"], 8)
        self.assertEqual(config["cleanup_interval_minutes"], 7)
        self.assertEqual(config["upload_rate_limit_per_hour"], 90)
        self.assertEqual(config["login_rate_limit_per_minute"], 8)
        self.assertEqual(config["download_rate_limit_per_minute"], 110)
        self.assertFalse(config["ui_auth_enabled"])
        self.assertFalse(config["api_auth_enabled"])
        self.assertEqual(
            self.app.config.get("MAX_CONTENT_LENGTH"),
            256 * 1024 * 1024,
        )

    def test_upload_page_renders(self):
        response = self.client.get("/upload-a-file")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Upload a File", response.data)

    def test_api_docs_page_lists_box_examples(self):
        response = self.client.get("/api-docs")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode()
        self.assertIn("Box API", html)
        self.assertIn("Sample JSON Response", html)

    def test_settings_page_renders_form(self):
        response = self.client.get("/settings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Retention Settings", response.data)
        self.assertIn(b"Maximum upload size", response.data)
        self.assertIn(b"Storage Management", response.data)
        self.assertIn(b"Performance Settings", response.data)
        self.assertIn(b"name=\"max_concurrent_uploads\"", response.data)
        self.assertIn(b"File Management Policies", response.data)

    def test_settings_cleanup_actions(self):
        response = self.client.post(
            "/settings",
            data={"action": "cleanup_expired_now"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Expired file cleanup complete", response.data)

        response = self.client.post(
            "/settings",
            data={"action": "cleanup_orphaned_now"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Orphaned file cleanup complete", response.data)

    def test_update_performance_settings(self):
        response = self.client.post(
            "/settings",
            data={
                "action": "update_performance",
                "max_upload_size_mb": "512",
                "max_concurrent_uploads": "7",
                "cleanup_interval_minutes": "9",
                "upload_rate_limit_per_hour": "75",
                "login_rate_limit_per_minute": "6",
                "download_rate_limit_per_minute": "80",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Performance settings updated", response.data)

        config = self.app_module.get_config()
        self.assertEqual(config["max_upload_size_mb"], 512.0)
        self.assertEqual(config["max_concurrent_uploads"], 7)
        self.assertEqual(config["cleanup_interval_minutes"], 9)
        self.assertEqual(config["upload_rate_limit_per_hour"], 75)
        self.assertEqual(config["login_rate_limit_per_minute"], 6)
        self.assertEqual(config["download_rate_limit_per_minute"], 80)

        self.assertEqual(self.app_module.max_concurrent_uploads_setting, 7)
        limiter = self.app_module.upload_limiter
        acquired = [limiter.acquire() for _ in range(7)]
        self.assertTrue(all(acquired))
        self.assertFalse(limiter.acquire())
        for flag in acquired:
            limiter.release(flag)

        self.assertEqual(self.app_module.cleanup_interval_minutes_setting, 9)
        self.assertEqual(self.app_module.upload_rate_limit_string(), "75 per hour")
        self.assertEqual(self.app_module.login_rate_limit_string(), "6 per minute")
        self.assertEqual(self.app_module.download_rate_limit_string(), "80 per minute")

    def test_get_config_detects_external_changes(self):
        config_before = self.app_module.get_config()
        self.assertEqual(config_before["max_upload_size_mb"], 500.0)

        updated = dict(config_before)
        updated["max_upload_size_mb"] = 777
        self.storage.save_config(updated)

        reloaded = self.app_module.get_config()
        self.assertEqual(reloaded["max_upload_size_mb"], 777.0)
        self.assertEqual(self.app.config["MAX_UPLOAD_SIZE_MB"], 777.0)

    def test_api_keys_page_renders(self):
        response = self.client.get("/apikeys")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"API Authentication", response.data)

    def test_index_redirects_to_hosting(self):
        response = self.client.get("/", follow_redirects=False)
        self.assertIn(response.status_code, {301, 302, 307, 308})
        self.assertEqual(response.headers.get("Location"), "/hosting")

    def test_delete_route_removes_file(self):
        upload_response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"delete me"), "delete.txt"),
                "retention_hours": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(upload_response.status_code, 201)
        file_id = upload_response.get_json()["id"]

        delete_response = self.client.post(
            f"/hosting/delete/{file_id}",
            follow_redirects=True,
        )
        self.assertEqual(delete_response.status_code, 200)
        self.assertIn(b"File deleted successfully.", delete_response.data)

        uploads_dir = Path(os.environ["LOCALHOSTING_UPLOADS_DIR"])
        self.assertFalse(any(path.is_file() for path in uploads_dir.rglob("*")))

    def test_delete_route_handles_disk_error(self):
        upload_response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"disk issue"), "disk.txt"),
                "retention_hours": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(upload_response.status_code, 201)
        payload = upload_response.get_json()
        file_id = payload["id"]
        record = self.storage.get_file(file_id)
        self.assertIsNotNone(record)
        stored_name = record["stored_name"]
        file_path = self.storage.get_storage_path(file_id, stored_name)

        with mock.patch("pathlib.Path.unlink", side_effect=PermissionError("denied")):
            delete_response = self.client.post(
                f"/hosting/delete/{file_id}",
                follow_redirects=True,
            )

        self.assertEqual(delete_response.status_code, 200)
        self.assertIn(b"File deleted successfully.", delete_response.data)
        self.assertIsNone(self.storage.get_file(file_id))
        self.assertTrue(file_path.exists())

        file_path.unlink()

    def test_cleanup_removes_expired_files_without_request(self):
        upload_response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"expire later"), "expire-later.txt"),
                "retention_hours": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(upload_response.status_code, 201)
        payload = upload_response.get_json()
        file_id = payload["id"]

        with self.storage.get_db() as conn:
            conn.execute(
                "UPDATE files SET expires_at = ? WHERE id = ?",
                (time.time() - 10, file_id),
            )
            conn.commit()

        uploads_dir = Path(os.environ["LOCALHOSTING_UPLOADS_DIR"])
        stored_files = list(uploads_dir.rglob("*"))
        self.assertTrue(any(path.is_file() for path in stored_files))

        removed = self.storage.cleanup_expired_files()
        self.assertEqual(removed, 1)

        # All stored files should be gone after cleanup.
        self.assertFalse(any(path.is_file() for path in uploads_dir.rglob("*")))
        record = self.storage.get_file(file_id)
        self.assertIsNone(record)

    def test_delete_route_missing_file_shows_error(self):
        response = self.client.post(
            "/hosting/delete/does-not-exist",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"File not found.", response.data)

    def test_delete_redirect_preserves_table_filters(self):
        uploads = []
        for name in ("report-one.txt", "report-two.txt"):
            upload_response = self.client.post(
                "/fileupload",
                data={
                    "file": (io.BytesIO(f"payload-{name}".encode()), name),
                    "retention_hours": "2",
                },
                content_type="multipart/form-data",
            )
            self.assertEqual(upload_response.status_code, 201)
            uploads.append(upload_response.get_json()["id"])

        delete_response = self.client.post(
            f"/hosting/delete/{uploads[0]}",
            data={
                "page": "2",
                "per_page": "1",
                "sort": "uploaded_at",
                "order": "desc",
                "search": "report",
            },
            follow_redirects=False,
        )

        self.assertEqual(delete_response.status_code, 302)
        location = delete_response.headers.get("Location")
        self.assertIsNotNone(location)
        self.assertTrue(location.startswith("/hosting"))

        parsed = urlparse(location)
        params = dict(parse_qsl(parsed.query))
        self.assertEqual(params.get("sort"), "uploaded_at")
        self.assertEqual(params.get("order"), "desc")
        self.assertEqual(params.get("per_page"), "1")
        self.assertEqual(params.get("search"), "report")
        self.assertEqual(params.get("page"), "1")

        follow_response = self.client.get(location)
        self.assertEqual(follow_response.status_code, 200)
        body = follow_response.data.decode()
        self.assertIn("File deleted successfully.", body)
        self.assertNotIn("report-one.txt", body)
        self.assertIn("report-two.txt", body)
        self.assertIsNone(self.storage.get_file(uploads[0]))

    def test_navigation_includes_logs_link(self):
        response = self.client.get("/hosting")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b">Logs<", response.data)

    def test_logs_page_renders_and_returns_payload(self):
        with self.app.app_context():
            self.app.logger.info("integration log entry")
            for handler in self.app.logger.handlers:
                handler.flush()

        response = self.client.get("/logs")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Application Logs", response.data)

        data_response = self.client.get("/logs/data")
        self.assertEqual(data_response.status_code, 200)
        payload = data_response.get_json()
        self.assertIsNotNone(payload)
        self.assertEqual(payload["source"], "application")
        self.assertIn("log entry", payload.get("text", ""))

    def test_logs_route_redirects_from_case_variants(self):
        response = self.client.get("/Logs", follow_redirects=False)
        self.assertEqual(response.status_code, 308)
        self.assertEqual(response.headers.get("Location"), "/logs")

    def test_settings_rejects_invalid_values(self):
        response = self.client.post(
            "/settings",
            data={
                "action": "update_retention",
                "retention_min_hours": "-1",
                "retention_max_hours": "48",
                "retention_hours": "12",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Minimum retention cannot be negative.", response.data)

        config = self.storage.load_config()
        self.assertEqual(config["retention_min_hours"], 0.0)

    def test_login_redirects_when_auth_disabled(self):
        response = self.client.get("/login", follow_redirects=False)
        self.assertIn(response.status_code, {301, 302})
        self.assertEqual(response.headers["Location"], "/hosting")

    def test_ui_authentication_flow(self):
        enable_response = self.client.post(
            "/settings",
            data={
                "action": "update_ui_auth",
                "retention_min_hours": "0",
                "retention_max_hours": "168",
                "retention_hours": "24",
                "ui_auth_enabled": "on",
                "ui_username": "manager",
                "ui_password": "s3cret!1",
                "ui_password_confirm": "s3cret!1",
            },
            follow_redirects=True,
        )
        self.assertEqual(enable_response.status_code, 200)

        config = self.storage.load_config()
        self.assertTrue(config["ui_auth_enabled"])
        self.assertEqual(config["ui_username"], "manager")
        self.assertTrue(check_password_hash(config["ui_password_hash"], "s3cret!1"))

        logout_response = self.client.post("/logout", follow_redirects=False)
        self.assertIn(logout_response.status_code, {301, 302})
        self.assertEqual(logout_response.headers["Location"], "/login")

        hosting_redirect = self.client.get("/hosting", follow_redirects=False)
        self.assertIn(hosting_redirect.status_code, {301, 302})
        self.assertEqual(hosting_redirect.headers["Location"], "/login")

        bad_login = self.client.post(
            "/login",
            data={"username": "manager", "password": "wrong"},
            follow_redirects=True,
        )
        self.assertEqual(bad_login.status_code, 200)
        self.assertIn("Invalid username or password", bad_login.data.decode())

        good_login = self.client.post(
            "/login",
            data={"username": "manager", "password": "s3cret!1"},
            follow_redirects=True,
        )
        self.assertEqual(good_login.status_code, 200)
        self.assertIn("Uploaded Files", good_login.data.decode())

    def test_reserved_direct_paths_are_regenerated(self):
        with self.storage.get_db() as conn:
            conn.execute(
                """
                INSERT INTO files (id, original_name, stored_name, content_type, size, uploaded_at, expires_at, direct_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "legacy",
                    "logs.txt",
                    "legacy.txt",
                    "text/plain",
                    4,
                    1000.0,
                    2000.0,
                    "logs",
                ),
            )
            conn.commit()

        self.storage.backfill_direct_paths()

        with self.storage.get_db() as conn:
            row = conn.execute(
                "SELECT direct_path FROM files WHERE id = ?", ("legacy",)
            ).fetchone()

        self.assertIsNotNone(row)
        self.assertNotEqual(row["direct_path"].lower(), "logs")
        self.assertTrue(row["direct_path"].startswith("logs"))

    def test_s3_post_upload_flow(self):
        response = self.client.post(
            "/s3/example-bucket",
            data={
                "key": "clips/${filename}",
                "x-amz-meta-retention-hours": "2",
                "file": (io.BytesIO(b"s3 post data"), "clip.txt"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.mimetype, "application/xml")
        file_id = response.headers.get("x-localhosting-file-id")
        self.assertIsNotNone(file_id)

        root = ET.fromstring(response.data)
        self.assertEqual(root.findtext("Bucket"), "example-bucket")
        self.assertEqual(root.findtext("Key"), "clips/clip.txt")
        location = root.findtext("Location")
        self.assertIsNotNone(location)

        download_path = urlparse(location).path
        download_response = self.client.get(download_path)
        self.assertEqual(download_response.status_code, 200)
        download_response.close()

    def test_hosting_lists_all_uploaded_files(self):
        api_response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"api upload"), "api-upload.txt"),
                "retention_hours": "2",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(api_response.status_code, 201)
        api_payload = api_response.get_json()

        s3_post_response = self.client.post(
            "/s3/example-bucket",
            data={
                "key": "assets/${filename}",
                "x-amz-meta-retention-hours": "3",
                "file": (io.BytesIO(b"s3 post upload"), "s3-post.bin"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(s3_post_response.status_code, 201)
        s3_post_id = s3_post_response.headers.get("x-localhosting-file-id")
        self.assertIsNotNone(s3_post_id)
        s3_post_record = self.storage.get_file(s3_post_id)

        s3_put_response = self.client.put(
            "/s3/example-bucket/videos/s3-put.bin",
            data=b"s3 put upload",
            headers={
                "x-amz-meta-retention-hours": "4",
                "Content-Type": "application/octet-stream",
            },
        )
        self.assertEqual(s3_put_response.status_code, 200)
        s3_put_id = s3_put_response.headers.get("x-localhosting-file-id")
        self.assertIsNotNone(s3_put_id)
        s3_put_record = self.storage.get_file(s3_put_id)

        hosting_page = self.client.get("/hosting")
        self.assertEqual(hosting_page.status_code, 200)
        html = hosting_page.data.decode()

        # Uploaded file names should appear in the listing.
        self.assertIn("api-upload.txt", html)
        self.assertIn(s3_post_record["original_name"], html)
        self.assertIn(s3_put_record["original_name"], html)

        # Download, direct, and raw URLs should be rendered for each upload.
        self.assertIn(f"/download/{api_payload['id']}", html)
        self.assertIn(f"/download/{s3_post_id}", html)
        self.assertIn(f"/download/{s3_put_id}", html)

        self.assertIn(
            f"/files/{api_payload['id']}/{quote(api_payload['filename'])}",
            html,
        )
        self.assertIn(
            f"/files/{s3_post_id}/{quote(s3_post_record['original_name'])}",
            html,
        )
        self.assertIn(
            f"/files/{s3_put_id}/{quote(s3_put_record['original_name'])}",
            html,
        )

        api_raw_path = api_payload.get("raw_download_path")
        if api_raw_path:
            self.assertIn(f"href=\"/{api_raw_path}\"", html)

        if s3_post_record["direct_path"]:
            self.assertIn(f"href=\"/{s3_post_record['direct_path']}\"", html)

        if s3_put_record["direct_path"]:
            self.assertIn(f"href=\"/{s3_put_record['direct_path']}\"", html)

    def test_box_api_upload_download_and_file_request(self):
        content = b"box api data"
        response = self.client.post(
            "/2.0/files/content",
            data={
                "attributes": json.dumps({"name": "box.txt"}),
                "file": (io.BytesIO(content), "ignored-name.txt"),
            },
            headers={"X-Localhosting-Retention-Hours": "1"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertIsNotNone(payload)
        self.assertEqual(payload["total_count"], 1)
        entry = payload["entries"][0]
        self.assertEqual(entry["name"], "box.txt")
        self.assertIn("sha1", entry)

        download_response = self.client.get(f"/2.0/files/{entry['id']}/content")
        self.assertEqual(download_response.status_code, 200)
        self.assertEqual(download_response.data, content)
        download_response.close()

        request_response = self.client.get(f"/2.0/file_requests/{entry['id']}")
        self.assertEqual(request_response.status_code, 200)
        request_payload = request_response.get_json()
        self.assertIsNotNone(request_payload)
        self.assertEqual(request_payload["id"], entry["id"])
        self.assertEqual(request_payload["title"], "box.txt")

        hosting_page = self.client.get("/hosting")
        self.assertEqual(hosting_page.status_code, 200)
        self.assertIn(b"box.txt", hosting_page.data)

    def test_logs_supports_docker_source_when_configured(self):
        logs_dir = Path(os.environ["LOCALHOSTING_LOGS_DIR"])
        docker_log = logs_dir / "container.log"
        docker_log.parent.mkdir(parents=True, exist_ok=True)
        docker_log.write_text("docker test line\n", encoding="utf-8")
        os.environ["LOCALHOSTING_DOCKER_LOG_PATH"] = str(docker_log)

        self._reload_app()
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

        response = self.client.get("/logs?source=docker")
        self.assertEqual(response.status_code, 200)

        data_response = self.client.get("/logs/data?source=docker")
        self.assertEqual(data_response.status_code, 200)
        payload = data_response.get_json()
        self.assertEqual(payload["source"], "docker")
        self.assertIn("docker test line", payload.get("text", ""))

    def test_s3_put_upload_flow(self):
        response = self.client.put(
            "/s3/example-bucket/assets/video.bin",
            data=b"binary payload",
            headers={
                "Content-Type": "application/octet-stream",
                "X-Amz-Meta-Retention-Hours": "1",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/xml")
        file_id = response.headers.get("x-localhosting-file-id")
        self.assertIsNotNone(file_id)

        root = ET.fromstring(response.data)
        self.assertEqual(root.findtext("Bucket"), "example-bucket")
        self.assertEqual(root.findtext("Key"), "assets/video.bin")
        location = root.findtext("Location")
        download_path = urlparse(location).path

        download_response = self.client.get(download_path)
        self.assertEqual(download_response.status_code, 200)
        self.assertEqual(download_response.data, b"binary payload")
        download_response.close()

    def test_s3_retention_validation_failure(self):
        response = self.client.put(
            "/s3/example-bucket/invalid.txt",
            data=b"bad",
            headers={"X-Amz-Meta-Retention-Hours": "9999"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.mimetype, "application/xml")
        root = ET.fromstring(response.data)
        self.assertEqual(root.findtext("Code"), "InvalidRequest")

    def test_api_authentication_requires_key_for_fileupload(self):
        enable = self.client.post(
            "/apikeys",
            data={"action": "update_api_auth", "api_auth_enabled": "on"},
            follow_redirects=False,
        )
        self.assertEqual(enable.status_code, 302)

        with self.client.session_transaction() as session:
            pending = session.get("pending_api_keys")
            if isinstance(pending, list) and pending:
                first = pending[0]
                api_key = first.get("value")
            else:
                api_key = None

        self.assertIsNotNone(api_key)
        self.client.get(enable.headers["Location"], follow_redirects=True)

        config = self.storage.load_config()
        self.assertTrue(config["api_auth_enabled"])
        self.assertTrue(config["api_keys"])
        self.assertIn("key_hash", config["api_keys"][0])
        self.assertIn("key_encrypted", config["api_keys"][0])
        self.assertIn("encryption_version", config["api_keys"][0])
        self.assertIn("secret_fingerprint", config["api_keys"][0])
        self.assertTrue(config["api_keys"][0]["key_encrypted"])
        self.assertNotIn("key", config["api_keys"][0])

        unauthorized = self.client.post(
            "/fileupload",
            data={"file": (io.BytesIO(b"blocked"), "blocked.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(unauthorized.status_code, 401)

        upload_page = self.client.get("/upload-a-file")
        self.assertEqual(upload_page.status_code, 200)
        upload_markup = upload_page.get_data(as_text=True)
        self.assertIn(api_key, upload_markup)

        authorized = self.client.post(
            "/fileupload",
            data={"file": (io.BytesIO(b"allowed"), "allowed.txt")},
            content_type="multipart/form-data",
            headers={"X-API-Key": api_key},
        )
        self.assertEqual(authorized.status_code, 201)
        payload = authorized.get_json()
        self.assertIsNotNone(payload)
        self.assertEqual(payload["filename"], "allowed.txt")

    def test_api_authentication_applies_to_s3_and_box(self):
        enable = self.client.post(
            "/apikeys",
            data={"action": "update_api_auth", "api_auth_enabled": "on"},
            follow_redirects=False,
        )
        with self.client.session_transaction() as session:
            pending = session.get("pending_api_keys")
            if isinstance(pending, list) and pending:
                api_key = pending[0].get("value")
            else:
                api_key = None

        self.assertIsNotNone(api_key)
        self.client.get(enable.headers["Location"], follow_redirects=True)

        s3_unauthorized = self.client.post(
            "/s3/test-bucket",
            data={"file": (io.BytesIO(b"s3"), "s3.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(s3_unauthorized.status_code, 403)

        s3_authorized = self.client.post(
            "/s3/test-bucket",
            data={"file": (io.BytesIO(b"s3 auth"), "s3-auth.txt")},
            content_type="multipart/form-data",
            headers={"X-API-Key": api_key},
        )
        self.assertEqual(s3_authorized.status_code, 201)

        box_unauthorized = self.client.post(
            "/2.0/files/content",
            data={"file": (io.BytesIO(b"box"), "box.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(box_unauthorized.status_code, 401)

        box_authorized = self.client.post(
            "/2.0/files/content",
            data={"file": (io.BytesIO(b"box auth"), "box-auth.txt")},
            content_type="multipart/form-data",
            headers={"X-API-Key": api_key},
        )
        self.assertEqual(box_authorized.status_code, 201)

    def test_api_key_management_via_api_keys_page(self):
        self.client.post(
            "/apikeys",
            data={"action": "update_api_auth", "api_auth_enabled": "on"},
            follow_redirects=True,
        )
        config = self.storage.load_config()
        original_keys = config["api_keys"]
        self.assertTrue(original_keys)
        initial_id = original_keys[0]["id"]
        self.assertIn("key_hash", original_keys[0])
        self.assertIn("secret_fingerprint", original_keys[0])

        generate = self.client.post(
            "/apikeys",
            data={"action": "generate_api_key", "api_key_label": "Build Server"},
            follow_redirects=False,
        )
        with self.client.session_transaction() as session:
            pending = session.get("pending_api_keys")
        self.assertIsInstance(pending, list)
        self.assertTrue(pending)
        self.client.get(generate.headers["Location"], follow_redirects=True)
        config = self.storage.load_config()
        self.assertGreaterEqual(len(config["api_keys"]), 2)
        labelled = [entry for entry in config["api_keys"] if entry["label"] == "Build Server"]
        self.assertTrue(labelled)
        new_key_id = labelled[0]["id"]

        self.client.post(
            "/apikeys",
            data={"action": "set_primary_api_key", "api_key_id": new_key_id},
            follow_redirects=True,
        )
        config = self.storage.load_config()
        self.assertEqual(config["api_ui_key_id"], new_key_id)

        self.client.post(
            "/apikeys",
            data={"action": "delete_api_key", "api_key_id": initial_id},
            follow_redirects=True,
        )
        config = self.storage.load_config()
        remaining_ids = {entry["id"] for entry in config["api_keys"]}
        self.assertNotIn(initial_id, remaining_ids)
        self.assertEqual(config["api_ui_key_id"], new_key_id)


if __name__ == "__main__":
    unittest.main()
