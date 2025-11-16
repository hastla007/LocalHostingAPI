"""
Test suite for bug fixes and additional coverage
Tests specifically designed to verify bug fixes and close testing gaps
"""

import io
import json
import math
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class BugFixTests(unittest.TestCase):
    """Tests for specific bug fixes"""

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
        ]:
            os.environ.pop(key, None)
        for module in ["app.app", "app.storage", "app"]:
            sys.modules.pop(module, None)

    def _reload_app(self):
        for module in ["app.app", "app.storage", "app"]:
            if module in sys.modules:
                del sys.modules[module]
        import importlib

        app_module = importlib.import_module("app.app")
        storage = importlib.import_module("app.storage")

        self.app = app_module.app
        self.storage = storage
        self.app_module = app_module

    def test_config_rejects_nan_values(self):
        """Test that config coercion rejects NaN values (Bug Fix)"""
        config = self.storage.load_config()

        # Try to set retention_hours to NaN
        malicious_config = config.copy()
        malicious_config["retention_hours"] = float('nan')
        self.storage.save_config(malicious_config)

        # Reload and verify it falls back to default
        reloaded = self.storage.load_config()
        self.assertFalse(math.isnan(reloaded["retention_hours"]))
        self.assertTrue(reloaded["retention_hours"] > 0)

    def test_config_rejects_infinity_values(self):
        """Test that config coercion rejects infinity values (Bug Fix)"""
        config = self.storage.load_config()

        # Try to set max_upload_size_mb to infinity
        malicious_config = config.copy()
        malicious_config["max_upload_size_mb"] = float('inf')
        self.storage.save_config(malicious_config)

        # Reload and verify it falls back to default
        reloaded = self.storage.load_config()
        self.assertFalse(math.isinf(reloaded["max_upload_size_mb"]))
        self.assertTrue(reloaded["max_upload_size_mb"] > 0)
        self.assertTrue(reloaded["max_upload_size_mb"] < 10000)  # Reasonable limit

    def test_prometheus_metrics_show_correct_file_count(self):
        """Test that Prometheus metrics show correct file count (Bug Fix)"""
        # Upload a test file
        response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"test content"), "test.txt"),
                "retention_hours": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)

        # Get Prometheus metrics
        metrics_response = self.client.get(
            "/metrics",
            headers={"Accept": "text/plain"}
        )
        self.assertEqual(metrics_response.status_code, 200)

        metrics_text = metrics_response.data.decode()

        # Verify metrics contain correct field names and non-zero values
        self.assertIn("localhosting_files_total", metrics_text)
        self.assertIn("localhosting_files_expired", metrics_text)
        self.assertIn("localhosting_storage_active_bytes", metrics_text)
        self.assertIn("localhosting_storage_expired_bytes", metrics_text)

        # Verify at least one file is counted
        # Look for the gauge value after localhosting_files_total
        for line in metrics_text.split('\n'):
            if line.startswith('localhosting_files_total '):
                count = int(line.split()[1])
                self.assertGreater(count, 0, "File count should be greater than 0")
                break
        else:
            self.fail("localhosting_files_total metric not found")

    def test_s3_auth_error_returns_401_not_403(self):
        """Test that S3 authentication failures return 401, not 403 (Bug Fix)"""
        # Enable API authentication
        enable_response = self.client.post(
            "/apikeys",
            data={"action": "update_api_auth", "api_auth_enabled": "on"},
            follow_redirects=False,
        )
        self.assertEqual(enable_response.status_code, 302)

        # Try S3 upload without auth - should get 401 (authentication required)
        # not 403 (authorization denied)
        s3_response = self.client.post(
            "/s3/test-bucket",
            data={"file": (io.BytesIO(b"test"), "test.txt")},
            content_type="multipart/form-data",
        )

        # Bug fix: Should return 401 (authentication failure) not 403
        self.assertEqual(
            s3_response.status_code,
            401,
            "S3 authentication failures should return 401, not 403"
        )

    def test_streaming_download_function_exists(self):
        """Test that the streaming download function exists (Bug Fix)"""
        # Verify the download_file_from_url_to_path function exists
        # This is the fix for the memory exhaustion bug
        self.assertTrue(
            hasattr(self.storage, 'download_file_from_url_to_path'),
            "Streaming download function should exist to prevent memory exhaustion"
        )

        # Verify it's callable
        self.assertTrue(
            callable(getattr(self.storage, 'download_file_from_url_to_path')),
            "Streaming download function should be callable"
        )

    def test_metadata_operations_work(self):
        """Test that metadata can be set and retrieved"""
        # Upload a file
        response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"test"), "test.txt"),
                "retention_hours": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        file_id = response.get_json()["id"]

        # Set metadata - must be wrapped in metadata object
        metadata_response = self.client.put(
            f"/files/{file_id}/metadata",
            json={"metadata": {"tag": "test", "category": "automated"}},
        )

        # Should succeed
        self.assertEqual(metadata_response.status_code, 200)

        # Retrieve and verify
        get_response = self.client.get(f"/files/{file_id}/metadata")
        self.assertEqual(get_response.status_code, 200)
        retrieved = get_response.get_json()
        self.assertEqual(retrieved.get("metadata", {}).get("tag"), "test")

    def test_direct_path_uniqueness_enforced(self):
        """Test that direct paths are unique and handle collisions"""
        # Upload two files with the same name
        response1 = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"first"), "duplicate.txt"),
                "retention_hours": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response1.status_code, 201)
        data1 = response1.get_json()

        response2 = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"second"), "duplicate.txt"),
                "retention_hours": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response2.status_code, 201)
        data2 = response2.get_json()

        # Direct paths should be different
        path1 = urlparse(data1["raw_download_url"]).path.lstrip("/")
        path2 = urlparse(data2["raw_download_url"]).path.lstrip("/")

        self.assertNotEqual(
            path1,
            path2,
            "Duplicate filenames should generate unique direct paths"
        )

    def test_expired_file_download_returns_404(self):
        """Test that expired files return 404 on download"""
        # Upload a file with 0 hour retention (immediately expired)
        response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"expired"), "expired.txt"),
                "retention_hours": "0",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        file_id = response.get_json()["id"]

        # Try to download - should get 404
        download_response = self.client.get(f"/download/{file_id}")
        self.assertEqual(
            download_response.status_code,
            404,
            "Expired files should return 404"
        )

    def test_permanent_files_not_cleaned_up(self):
        """Test that permanent files are not cleaned up"""
        # Upload a permanent file
        response = self.client.post(
            "/fileupload",
            data={
                "file": (io.BytesIO(b"permanent"), "permanent.txt"),
                "permanent": "true",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        file_id = response.get_json()["id"]

        # Run cleanup
        removed = self.storage.cleanup_expired_files()

        # Permanent file should still exist
        record = self.storage.get_file(file_id)
        self.assertIsNotNone(record, "Permanent files should not be cleaned up")
        self.assertEqual(record["permanent"], 1)

    def test_health_check_includes_all_components(self):
        """Test that health check includes all necessary components"""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        # Verify required fields
        self.assertIn("status", data)
        self.assertIn("checks", data)
        self.assertIn("timestamp", data)

        # Verify checks include important components
        checks = data["checks"]
        self.assertIn("database", checks)
        self.assertIn("disk_space_status", checks)

    def test_multiple_file_upload_creates_multiple_records(self):
        """Test that multiple file upload creates separate records"""
        # Upload multiple files
        response = self.client.post(
            "/fileupload",
            data={
                "file": [
                    (io.BytesIO(b"file1"), "file1.txt"),
                    (io.BytesIO(b"file2"), "file2.txt"),
                ],
                "retention_hours": "1",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        data = response.get_json()

        # Should have multiple files in response
        self.assertIn("files", data)
        self.assertEqual(len(data["files"]), 2)

        # Each file should be downloadable
        for file_entry in data["files"]:
            file_id = file_entry["id"]
            download_response = self.client.get(f"/download/{file_id}")
            self.assertEqual(download_response.status_code, 200)
            download_response.close()

    def test_directory_creation_and_listing(self):
        """Test that directories can be created and listed"""
        # Create directory
        dir_response = self.client.post(
            "/directories",
            json={"name": "Test Directory", "description": "Test description"},
        )
        self.assertEqual(dir_response.status_code, 201)
        dir_id = dir_response.get_json()["directory_id"]

        # List directories - UI endpoint
        list_response = self.client.get("/directories")
        self.assertEqual(list_response.status_code, 200)

        # Should contain our directory in the HTML
        html = list_response.data.decode()
        self.assertIn("Test Directory", html)

    def test_api_key_revocation(self):
        """Test that revoked API keys cannot be used"""
        # Enable API auth and generate key
        enable_response = self.client.post(
            "/apikeys",
            data={"action": "update_api_auth", "api_auth_enabled": "on"},
            follow_redirects=False,
        )

        with self.client.session_transaction() as session:
            pending = session.get("pending_api_keys", [])
            api_key = pending[0]["value"] if pending else None

        self.assertIsNotNone(api_key)

        # Follow redirect to commit the key
        self.client.get(enable_response.headers["Location"], follow_redirects=True)

        # Verify key works
        upload_response = self.client.post(
            "/fileupload",
            data={"file": (io.BytesIO(b"test"), "test.txt")},
            content_type="multipart/form-data",
            headers={"X-API-Key": api_key},
        )
        self.assertEqual(upload_response.status_code, 201)

        # Get the key ID
        config = self.storage.load_config()
        key_id = config["api_keys"][0]["id"]

        # Revoke the key
        revoke_response = self.client.post(
            "/apikeys",
            data={"action": "delete_api_key", "api_key_id": key_id},
        )
        self.assertEqual(revoke_response.status_code, 302)

        # Try to use revoked key - should fail
        upload_response2 = self.client.post(
            "/fileupload",
            data={"file": (io.BytesIO(b"test2"), "test2.txt")},
            content_type="multipart/form-data",
            headers={"X-API-Key": api_key},
        )
        self.assertEqual(upload_response2.status_code, 401)


if __name__ == "__main__":
    unittest.main()
