import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlparse


class LocalHostingAppIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.storage_dir = tempfile.TemporaryDirectory()
        root = Path(self.storage_dir.name)
        os.environ["LOCALHOSTING_STORAGE_ROOT"] = str(root)
        os.environ["LOCALHOSTING_DATA_DIR"] = str(root / "data")
        os.environ["LOCALHOSTING_UPLOADS_DIR"] = str(root / "uploads")
        self._reload_app()
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    def tearDown(self):
        self.storage_dir.cleanup()
        for key in [
            "LOCALHOSTING_STORAGE_ROOT",
            "LOCALHOSTING_DATA_DIR",
            "LOCALHOSTING_UPLOADS_DIR",
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


if __name__ == "__main__":
    unittest.main()
