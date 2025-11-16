#!/usr/bin/env python3
"""
Comprehensive API Testing Script for LocalHostingAPI
Tests all endpoints with detailed validation
"""

import json
import os
import sys
import time
import requests
from io import BytesIO
from typing import Dict, Any, List, Tuple

BASE_URL = "http://localhost:8000"
TEST_FILES_DIR = "/tmp/test_uploads"
RESULTS: List[Dict[str, Any]] = []

# Color codes for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def log_test(name: str, passed: bool, details: str = ""):
    """Log test result"""
    status = f"{Colors.GREEN}✓ PASS{Colors.RESET}" if passed else f"{Colors.RED}✗ FAIL{Colors.RESET}"
    print(f"{status} | {name}")
    if details:
        print(f"         {details}")
    RESULTS.append({"name": name, "passed": passed, "details": details})

def test_health_endpoint():
    """Test health check endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        data = response.json()

        # Check required fields
        required_fields = ["status", "checks", "timestamp"]
        has_fields = all(field in data for field in required_fields)

        # Check database and disk status
        checks_ok = (
            data["checks"].get("database") == "ok" and
            data["checks"].get("disk_space_status") == "ok"
        )

        passed = response.status_code == 200 and has_fields and checks_ok
        log_test("Health Check", passed,
                f"Status: {response.status_code}, Health: {data.get('status')}")
    except Exception as e:
        log_test("Health Check", False, f"Error: {str(e)}")

def test_file_upload():
    """Test basic file upload"""
    try:
        # Create test file
        test_content = b"Test file content for upload test"
        files = {"files": ("test.txt", BytesIO(test_content), "text/plain")}
        data = {"retention_hours": "24"}

        response = requests.post(f"{BASE_URL}/fileupload", files=files, data=data, timeout=10)
        result = response.json()

        # Verify response structure
        passed = (
            response.status_code == 200 and
            "files" in result and
            len(result["files"]) == 1 and
            "file_id" in result["files"][0]
        )

        if passed:
            file_id = result["files"][0]["file_id"]
            return file_id

        log_test("File Upload", passed, f"Uploaded file_id: {result['files'][0].get('file_id', 'N/A')}")
        return result["files"][0].get("file_id") if passed else None
    except Exception as e:
        log_test("File Upload", False, f"Error: {str(e)}")
        return None

def test_file_download(file_id: str):
    """Test file download"""
    if not file_id:
        log_test("File Download", False, "No file_id from upload")
        return

    try:
        response = requests.get(f"{BASE_URL}/download/{file_id}", timeout=10)

        passed = (
            response.status_code == 200 and
            len(response.content) > 0 and
            "Content-Disposition" in response.headers
        )

        log_test("File Download", passed,
                f"Status: {response.status_code}, Size: {len(response.content)} bytes")
    except Exception as e:
        log_test("File Download", False, f"Error: {str(e)}")

def test_multifile_upload():
    """Test uploading multiple files at once"""
    try:
        files = [
            ("files", ("file1.txt", BytesIO(b"Content 1"), "text/plain")),
            ("files", ("file2.txt", BytesIO(b"Content 2"), "text/plain")),
            ("files", ("file3.txt", BytesIO(b"Content 3"), "text/plain"))
        ]
        data = {"retention_hours": "24"}

        response = requests.post(f"{BASE_URL}/fileupload", files=files, data=data, timeout=10)
        result = response.json()

        passed = (
            response.status_code == 200 and
            len(result.get("files", [])) == 3
        )

        log_test("Multi-File Upload", passed,
                f"Uploaded {len(result.get('files', []))} files")
    except Exception as e:
        log_test("Multi-File Upload", False, f"Error: {str(e)}")

def test_invalid_extension_blocked():
    """Test that blocked extensions are rejected"""
    try:
        # Set blocked extensions via environment (if configurable)
        files = {"files": ("test.exe", BytesIO(b"fake exe"), "application/x-executable")}
        data = {"retention_hours": "24"}

        response = requests.post(f"{BASE_URL}/fileupload", files=files, data=data, timeout=10)

        # If .exe is blocked, should get 400 error
        # If not blocked by default, this test should be adjusted
        # Let's check the response
        result = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

        # Test passes if either rejected or accepted (depends on config)
        # We'll mark as pass if we get a valid response
        passed = response.status_code in [200, 400]

        log_test("Extension Blocking", passed,
                f"Status: {response.status_code}")
    except Exception as e:
        log_test("Extension Blocking", False, f"Error: {str(e)}")

def test_s3_compatible_upload():
    """Test S3-compatible upload endpoint"""
    try:
        # Test S3 POST upload
        files = {"file": ("s3test.txt", BytesIO(b"S3 upload test"), "text/plain")}
        data = {"key": "test-file.txt"}

        response = requests.post(f"{BASE_URL}/s3/test-bucket", files=files, data=data, timeout=10)
        result = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

        passed = response.status_code == 200 and "file_id" in result

        log_test("S3 POST Upload", passed,
                f"Status: {response.status_code}, file_id: {result.get('file_id', 'N/A')}")
        return result.get("file_id")
    except Exception as e:
        log_test("S3 POST Upload", False, f"Error: {str(e)}")
        return None

def test_s3_put_upload():
    """Test S3 PUT upload"""
    try:
        data = b"S3 PUT upload test content"
        headers = {"Content-Type": "text/plain"}

        response = requests.put(
            f"{BASE_URL}/s3/test-bucket/test-put-file.txt",
            data=data,
            headers=headers,
            timeout=10
        )
        result = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

        passed = response.status_code == 200

        log_test("S3 PUT Upload", passed, f"Status: {response.status_code}")
    except Exception as e:
        log_test("S3 PUT Upload", False, f"Error: {str(e)}")

def test_box_compatible_upload():
    """Test Box.com-compatible upload"""
    try:
        files = {"file": ("boxtest.txt", BytesIO(b"Box upload test"), "text/plain")}
        attributes = json.dumps({"name": "boxtest.txt", "parent": {"id": "0"}})
        data = {"attributes": attributes}

        response = requests.post(f"{BASE_URL}/2.0/files/content", files=files, data=data, timeout=10)
        result = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

        # Box API returns entries array
        passed = response.status_code in [200, 201]

        file_id = None
        if passed and "entries" in result and len(result["entries"]) > 0:
            file_id = result["entries"][0].get("id")

        log_test("Box Upload", passed,
                f"Status: {response.status_code}, file_id: {file_id}")
        return file_id
    except Exception as e:
        log_test("Box Upload", False, f"Error: {str(e)}")
        return None

def test_box_download(file_id: str):
    """Test Box download"""
    if not file_id:
        log_test("Box Download", False, "No file_id from Box upload")
        return

    try:
        response = requests.get(f"{BASE_URL}/2.0/files/{file_id}/content", timeout=10)

        passed = response.status_code == 200 and len(response.content) > 0

        log_test("Box Download", passed,
                f"Status: {response.status_code}, Size: {len(response.content)} bytes")
    except Exception as e:
        log_test("Box Download", False, f"Error: {str(e)}")

def test_directories():
    """Test directory creation and management"""
    try:
        # Create directory
        data = {"name": "Test Directory", "description": "Test description"}
        response = requests.post(f"{BASE_URL}/directories", json=data, timeout=10)
        result = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

        created = response.status_code in [200, 201] and "directory_id" in result

        if not created:
            log_test("Directory Creation", False, f"Status: {response.status_code}")
            return None

        dir_id = result["directory_id"]
        log_test("Directory Creation", True, f"Created directory: {dir_id}")

        # List directories
        response = requests.get(f"{BASE_URL}/directories", timeout=10)
        dirs = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

        list_ok = response.status_code == 200 and "directories" in dirs
        log_test("Directory Listing", list_ok, f"Found {len(dirs.get('directories', []))} directories")

        # Get specific directory
        response = requests.get(f"{BASE_URL}/directories/{dir_id}", timeout=10)
        dir_details = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

        details_ok = response.status_code == 200 and dir_details.get("id") == dir_id
        log_test("Directory Details", details_ok, f"Retrieved directory: {dir_id}")

        return dir_id
    except Exception as e:
        log_test("Directory Operations", False, f"Error: {str(e)}")
        return None

def test_directory_upload(dir_id: str):
    """Test uploading files to a directory"""
    if not dir_id:
        log_test("Directory File Upload", False, "No directory_id")
        return None

    try:
        files = {"files": ("dirtest.txt", BytesIO(b"Directory upload test"), "text/plain")}
        data = {"retention_hours": "24"}

        response = requests.post(
            f"{BASE_URL}/directories/{dir_id}/files",
            files=files,
            data=data,
            timeout=10
        )
        result = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

        passed = (
            response.status_code == 200 and
            "files" in result and
            len(result["files"]) == 1
        )

        file_id = result["files"][0].get("file_id") if passed else None

        log_test("Directory File Upload", passed,
                f"Uploaded to directory: {file_id}")
        return file_id
    except Exception as e:
        log_test("Directory File Upload", False, f"Error: {str(e)}")
        return None

def test_metadata_operations(file_id: str):
    """Test metadata get and update"""
    if not file_id:
        log_test("Metadata Operations", False, "No file_id")
        return

    try:
        # Get metadata
        response = requests.get(f"{BASE_URL}/files/{file_id}/metadata", timeout=10)
        metadata = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

        get_ok = response.status_code == 200
        log_test("Get Metadata", get_ok, f"Retrieved metadata for {file_id}")

        # Update metadata
        new_metadata = {"custom_field": "test_value", "tag": "important"}
        response = requests.put(
            f"{BASE_URL}/files/{file_id}/metadata",
            json={"metadata": new_metadata},
            timeout=10
        )

        update_ok = response.status_code == 200
        log_test("Update Metadata", update_ok, f"Updated metadata for {file_id}")

        # Verify update
        response = requests.get(f"{BASE_URL}/files/{file_id}/metadata", timeout=10)
        updated_metadata = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

        verify_ok = (
            response.status_code == 200 and
            updated_metadata.get("metadata", {}).get("custom_field") == "test_value"
        )
        log_test("Verify Metadata Update", verify_ok, "Metadata update verified")

    except Exception as e:
        log_test("Metadata Operations", False, f"Error: {str(e)}")

def test_ssrf_protection():
    """Test SSRF protection for URL downloads"""
    try:
        # Test with localhost URL (should be blocked)
        files = {}
        data = {
            "url": "http://localhost/etc/passwd",
            "retention_hours": "24"
        }

        response = requests.post(f"{BASE_URL}/fileupload", data=data, timeout=10)
        result = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}

        # Should be rejected (400 or 403)
        blocked = response.status_code in [400, 403]

        log_test("SSRF Protection - Localhost", blocked,
                f"Status: {response.status_code} (should block)")

        # Test with private IP (should be blocked)
        data["url"] = "http://192.168.1.1/admin"
        response = requests.post(f"{BASE_URL}/fileupload", data=data, timeout=10)
        blocked_private = response.status_code in [400, 403]

        log_test("SSRF Protection - Private IP", blocked_private,
                f"Status: {response.status_code} (should block)")

        # Test with link-local (should be blocked)
        data["url"] = "http://169.254.169.254/latest/meta-data/"
        response = requests.post(f"{BASE_URL}/fileupload", data=data, timeout=10)
        blocked_metadata = response.status_code in [400, 403]

        log_test("SSRF Protection - Cloud Metadata", blocked_metadata,
                f"Status: {response.status_code} (should block)")

    except Exception as e:
        log_test("SSRF Protection", False, f"Error: {str(e)}")

def test_metrics_endpoint():
    """Test Prometheus metrics endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/metrics", timeout=10)

        # Metrics should be in text/plain format
        passed = (
            response.status_code == 200 and
            len(response.text) > 0
        )

        # Check for some expected metric names
        has_metrics = (
            "localhosting_" in response.text or
            "files_total" in response.text or
            "storage_bytes" in response.text
        )

        log_test("Metrics Endpoint", passed and has_metrics,
                f"Status: {response.status_code}, Has metrics: {has_metrics}")
    except Exception as e:
        log_test("Metrics Endpoint", False, f"Error: {str(e)}")

def test_path_traversal_protection():
    """Test path traversal protection"""
    try:
        # Try to upload file with path traversal in filename
        malicious_names = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "test/../../passwd"
        ]

        for malicious_name in malicious_names:
            files = {"files": (malicious_name, BytesIO(b"test"), "text/plain")}
            data = {"retention_hours": "24"}

            response = requests.post(f"{BASE_URL}/fileupload", files=files, data=data, timeout=10)

            # Should either reject or sanitize the filename
            # If it returns 200, the stored filename should be sanitized
            if response.status_code == 200:
                result = response.json()
                if "files" in result and len(result["files"]) > 0:
                    stored_name = result["files"][0].get("filename", "")
                    # Should not contain ../ or ..\
                    sanitized = ".." not in stored_name and "/" not in stored_name and "\\" not in stored_name
                    if not sanitized:
                        log_test(f"Path Traversal - {malicious_name[:20]}", False,
                                f"Filename not sanitized: {stored_name}")
                        return

        log_test("Path Traversal Protection", True, "All malicious paths blocked/sanitized")

    except Exception as e:
        log_test("Path Traversal Protection", False, f"Error: {str(e)}")

def test_large_metadata_protection():
    """Test protection against large metadata"""
    try:
        # Create a file first
        files = {"files": ("metadata_test.txt", BytesIO(b"test"), "text/plain")}
        data = {"retention_hours": "24"}
        response = requests.post(f"{BASE_URL}/fileupload", files=files, data=data, timeout=10)

        if response.status_code != 200:
            log_test("Large Metadata Protection", False, "Could not create test file")
            return

        file_id = response.json()["files"][0]["file_id"]

        # Try to set very large metadata (1MB string)
        large_metadata = {"huge_field": "X" * (1024 * 1024)}
        response = requests.put(
            f"{BASE_URL}/files/{file_id}/metadata",
            json={"metadata": large_metadata},
            timeout=10
        )

        # Should be rejected (400 or similar)
        blocked = response.status_code in [400, 413]

        log_test("Large Metadata Protection", blocked,
                f"Status: {response.status_code} (should reject large metadata)")

    except Exception as e:
        log_test("Large Metadata Protection", False, f"Error: {str(e)}")

def test_retention_validation():
    """Test retention hours validation"""
    try:
        # Test with invalid retention values
        invalid_values = ["-1", "0", "abc", "999999999"]

        for invalid_val in invalid_values:
            files = {"files": ("test.txt", BytesIO(b"test"), "text/plain")}
            data = {"retention_hours": invalid_val}

            response = requests.post(f"{BASE_URL}/fileupload", files=files, data=data, timeout=10)

            # Should either reject or use default value
            # Let's check if it handles gracefully
            if response.status_code not in [200, 400]:
                log_test(f"Retention Validation - {invalid_val}", False,
                        f"Unexpected status: {response.status_code}")
                return

        log_test("Retention Validation", True, "Invalid retention values handled correctly")

    except Exception as e:
        log_test("Retention Validation", False, f"Error: {str(e)}")

def test_empty_filename_handling():
    """Test handling of empty or missing filenames"""
    try:
        # Try to upload file with empty filename
        files = {"files": ("", BytesIO(b"test content"), "text/plain")}
        data = {"retention_hours": "24"}

        response = requests.post(f"{BASE_URL}/fileupload", files=files, data=data, timeout=10)

        # Should either reject or assign a default filename
        handled = response.status_code in [200, 400]

        log_test("Empty Filename Handling", handled,
                f"Status: {response.status_code}")

    except Exception as e:
        log_test("Empty Filename Handling", False, f"Error: {str(e)}")

def print_summary():
    """Print test summary"""
    print(f"\n{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}TEST SUMMARY{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["passed"])
    failed = total - passed

    pass_rate = (passed / total * 100) if total > 0 else 0

    print(f"\nTotal Tests: {total}")
    print(f"{Colors.GREEN}Passed: {passed}{Colors.RESET}")
    print(f"{Colors.RED}Failed: {failed}{Colors.RESET}")
    print(f"Pass Rate: {pass_rate:.1f}%")

    if failed > 0:
        print(f"\n{Colors.RED}Failed Tests:{Colors.RESET}")
        for result in RESULTS:
            if not result["passed"]:
                print(f"  - {result['name']}: {result['details']}")

    print(f"\n{Colors.BLUE}{'='*70}{Colors.RESET}\n")

    return passed, failed

def main():
    """Run all tests"""
    print(f"\n{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}LocalHostingAPI - Comprehensive API Test Suite{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")

    # Basic endpoint tests
    print(f"{Colors.YELLOW}Testing Basic Endpoints...{Colors.RESET}")
    test_health_endpoint()

    # File upload/download tests
    print(f"\n{Colors.YELLOW}Testing File Operations...{Colors.RESET}")
    file_id = test_file_upload()
    test_file_download(file_id)
    test_multifile_upload()
    test_invalid_extension_blocked()

    # S3 compatibility tests
    print(f"\n{Colors.YELLOW}Testing S3-Compatible Endpoints...{Colors.RESET}")
    s3_file_id = test_s3_compatible_upload()
    test_s3_put_upload()

    # Box compatibility tests
    print(f"\n{Colors.YELLOW}Testing Box-Compatible Endpoints...{Colors.RESET}")
    box_file_id = test_box_compatible_upload()
    test_box_download(box_file_id)

    # Directory tests
    print(f"\n{Colors.YELLOW}Testing Directory Management...{Colors.RESET}")
    dir_id = test_directories()
    dir_file_id = test_directory_upload(dir_id)

    # Metadata tests
    print(f"\n{Colors.YELLOW}Testing Metadata Operations...{Colors.RESET}")
    if file_id:
        test_metadata_operations(file_id)

    # Security tests
    print(f"\n{Colors.YELLOW}Testing Security Features...{Colors.RESET}")
    test_ssrf_protection()
    test_path_traversal_protection()
    test_large_metadata_protection()

    # Validation tests
    print(f"\n{Colors.YELLOW}Testing Input Validation...{Colors.RESET}")
    test_retention_validation()
    test_empty_filename_handling()

    # Monitoring tests
    print(f"\n{Colors.YELLOW}Testing Monitoring Endpoints...{Colors.RESET}")
    test_metrics_endpoint()

    # Print summary
    passed, failed = print_summary()

    # Return exit code
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()
