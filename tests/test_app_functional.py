import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote, urlparse
from xml.etree import ElementTree as ET


class LocalHostingAppIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.storage_dir = tempfile.TemporaryDirectory()
        root = Path(self.storage_dir.name)
        os.environ["LOCALHOSTING_STORAGE_ROOT"] = str(root)
        os.environ["LOCALHOSTING_DATA_DIR"] = str(root / "data")
        os.environ["LOCALHOSTING_UPLOADS_DIR"] = str(root / "uploads")
        os.environ["LOCALHOSTING_LOGS_DIR"] = str(root / "logs")
        self._reload_app()
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    def tearDown(self):
        self.storage_dir.cleanup()
        for key in [
            "LOCALHOSTING_STORAGE_ROOT",
            "LOCALHOSTING_DATA_DIR",
            "LOCALHOSTING_UPLOADS_DIR",
            "LOCALHOSTING_LOGS_DIR",
            "LOCALHOSTING_DOCKER_LOG_PATH",
        ]:
            os.environ.pop(key, None)
        for module in ["app.app", "app.storage", "app"]:
            sys.modules.pop(module, None)

    def _reload_app(self):
        for module in ["app.app", "app.storage", "app"]:
            if module in sys.modules:
                del sys.modules[module]
        from app import app  # noqa: WPS433 (import required during reload)
        import app.storage as storage  # noqa: WPS433

        self.app = app
        self.storage = storage

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
        stored_files = list(uploads_dir.iterdir())
        self.assertEqual(len(stored_files), 1)

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
        self.assertFalse(any(uploads_dir.iterdir()))

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

    def test_settings_update_persists(self):
        response = self.client.post(
            "/settings",
            data={
                "retention_min_hours": "1",
                "retention_max_hours": "48",
                "retention_hours": "12",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        config = self.storage.load_config()
        self.assertEqual(config["retention_min_hours"], 1.0)
        self.assertEqual(config["retention_max_hours"], 48.0)
        self.assertEqual(config["retention_hours"], 12.0)

    def test_upload_page_renders(self):
        response = self.client.get("/upload-a-file")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Upload a File", response.data)

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
        self.assertFalse(any(uploads_dir.iterdir()))

    def test_delete_route_missing_file_shows_error(self):
        response = self.client.post(
            "/hosting/delete/does-not-exist",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"File not found.", response.data)

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
                "retention_min_hours": "-1",
                "retention_max_hours": "48",
                "retention_hours": "12",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Minimum retention cannot be negative.", response.data)

        config = self.storage.load_config()
        self.assertEqual(config["retention_min_hours"], 0.0)

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


if __name__ == "__main__":
    unittest.main()
