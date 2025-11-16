#!/usr/bin/env python3
"""
Comprehensive API Testing Script for LocalHostingAPI
Tests all endpoints and documents issues found
"""

import requests
import json
import time
import sys
from io import BytesIO

BASE_URL = "http://localhost:8000"
test_results = []

# Add proper headers for CSRF protection
DEFAULT_HEADERS = {
    'Referer': BASE_URL + '/'
}

class TestResult:
    def __init__(self, endpoint, method, status, message, severity="info"):
        self.endpoint = endpoint
        self.method = method
        self.status = status
        self.message = message
        self.severity = severity

    def __str__(self):
        status_symbol = "✓" if self.status == "PASS" else "✗" if self.status == "FAIL" else "!"
        return f"[{status_symbol}] {self.method} {self.endpoint}: {self.message}"

def log_test(endpoint, method, status, message, severity="info"):
    result = TestResult(endpoint, method, status, message, severity)
    test_results.append(result)
    print(result)

def test_health_endpoint():
    """Test /health endpoint"""
    print("\n=== Testing Health Endpoint ===")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "healthy":
                log_test("/health", "GET", "PASS", "Health check passed")
            else:
                log_test("/health", "GET", "WARN", f"Unhealthy status: {data}", "warning")
        else:
            log_test("/health", "GET", "FAIL", f"Unexpected status code: {response.status_code}", "error")
    except Exception as e:
        log_test("/health", "GET", "FAIL", f"Exception: {str(e)}", "error")

def test_file_upload():
    """Test /fileupload endpoint"""
    print("\n=== Testing File Upload ===")
    try:
        # Create a test file
        files = {'file': ('test.txt', BytesIO(b'Hello World!'), 'text/plain')}
        response = requests.post(f"{BASE_URL}/fileupload", files=files, headers=DEFAULT_HEADERS, timeout=10)

        if response.status_code == 201:
            data = response.json()
            log_test("/fileupload", "POST", "PASS", f"File uploaded successfully: {data.get('id', 'N/A')}")
            return data.get('id')
        else:
            log_test("/fileupload", "POST", "FAIL", f"Status: {response.status_code}, Response: {response.text}", "error")
            return None
    except Exception as e:
        log_test("/fileupload", "POST", "FAIL", f"Exception: {str(e)}", "error")
        return None

def test_file_download(file_id):
    """Test /download/<file_id> endpoint"""
    print("\n=== Testing File Download ===")
    if not file_id:
        log_test("/download/<file_id>", "GET", "SKIP", "No file_id from upload test")
        return

    try:
        response = requests.get(f"{BASE_URL}/download/{file_id}", timeout=10)
        if response.status_code == 200:
            log_test(f"/download/{file_id}", "GET", "PASS", "File downloaded successfully")
        else:
            log_test(f"/download/{file_id}", "GET", "FAIL", f"Status: {response.status_code}", "error")
    except Exception as e:
        log_test(f"/download/{file_id}", "GET", "FAIL", f"Exception: {str(e)}", "error")

def test_upload_with_retention():
    """Test upload with custom retention"""
    print("\n=== Testing Upload with Custom Retention ===")
    try:
        files = {'file': ('retention_test.txt', BytesIO(b'Retention test'), 'text/plain')}
        data = {'retention_hours': '48'}
        response = requests.post(f"{BASE_URL}/fileupload", files=files, data=data, headers=DEFAULT_HEADERS, timeout=10)

        if response.status_code == 201:
            log_test("/fileupload", "POST", "PASS", "Custom retention upload successful")
        else:
            log_test("/fileupload", "POST", "FAIL", f"Status: {response.status_code}", "error")
    except Exception as e:
        log_test("/fileupload", "POST", "FAIL", f"Exception: {str(e)}", "error")

def test_upload_permanent():
    """Test upload with permanent flag"""
    print("\n=== Testing Permanent Upload ===")
    try:
        files = {'file': ('permanent_test.txt', BytesIO(b'Permanent test'), 'text/plain')}
        data = {'permanent': 'true'}
        response = requests.post(f"{BASE_URL}/fileupload", files=files, data=data, headers=DEFAULT_HEADERS, timeout=10)

        if response.status_code == 201:
            log_test("/fileupload", "POST", "PASS", "Permanent upload successful")
        else:
            log_test("/fileupload", "POST", "FAIL", f"Status: {response.status_code}", "error")
    except Exception as e:
        log_test("/fileupload", "POST", "FAIL", f"Exception: {str(e)}", "error")

def test_multiple_upload():
    """Test uploading multiple files"""
    print("\n=== Testing Multiple File Upload ===")
    try:
        files = [
            ('file', ('multi1.txt', BytesIO(b'File 1'), 'text/plain')),
            ('file', ('multi2.txt', BytesIO(b'File 2'), 'text/plain')),
        ]
        response = requests.post(f"{BASE_URL}/fileupload", files=files, headers=DEFAULT_HEADERS, timeout=10)

        if response.status_code == 201:
            data = response.json()
            if isinstance(data, list) and len(data) == 2:
                log_test("/fileupload", "POST", "PASS", f"Multiple files uploaded: {len(data)} files")
            else:
                log_test("/fileupload", "POST", "WARN", f"Unexpected response format: {data}", "warning")
        else:
            log_test("/fileupload", "POST", "FAIL", f"Status: {response.status_code}", "error")
    except Exception as e:
        log_test("/fileupload", "POST", "FAIL", f"Exception: {str(e)}", "error")

def test_directory_creation():
    """Test /directories endpoint"""
    print("\n=== Testing Directory Creation ===")
    try:
        payload = {"name": "Test Directory", "description": "Testing directory creation"}
        response = requests.post(f"{BASE_URL}/directories", json=payload, headers=DEFAULT_HEADERS, timeout=10)

        if response.status_code == 201:
            data = response.json()
            log_test("/directories", "POST", "PASS", f"Directory created: {data.get('id', 'N/A')}")
            return data.get('id')
        else:
            log_test("/directories", "POST", "FAIL", f"Status: {response.status_code}, Response: {response.text}", "error")
            return None
    except Exception as e:
        log_test("/directories", "POST", "FAIL", f"Exception: {str(e)}", "error")
        return None

def test_directory_list():
    """Test listing directories"""
    print("\n=== Testing Directory List ===")
    try:
        response = requests.get(f"{BASE_URL}/directories", timeout=10)
        if response.status_code == 200:
            data = response.json()
            log_test("/directories", "GET", "PASS", f"Retrieved {len(data) if isinstance(data, list) else 'unknown'} directories")
        else:
            log_test("/directories", "GET", "FAIL", f"Status: {response.status_code}", "error")
    except Exception as e:
        log_test("/directories", "GET", "FAIL", f"Exception: {str(e)}", "error")

def test_upload_to_directory(directory_id):
    """Test uploading to a directory"""
    print("\n=== Testing Upload to Directory ===")
    if not directory_id:
        log_test(f"/directories/<id>/files", "POST", "SKIP", "No directory_id from creation test")
        return

    try:
        files = {'file': ('dir_test.txt', BytesIO(b'Directory file test'), 'text/plain')}
        response = requests.post(f"{BASE_URL}/directories/{directory_id}/files", files=files, headers=DEFAULT_HEADERS, timeout=10)

        if response.status_code == 201:
            log_test(f"/directories/{directory_id}/files", "POST", "PASS", "File uploaded to directory")
        else:
            log_test(f"/directories/{directory_id}/files", "POST", "FAIL", f"Status: {response.status_code}", "error")
    except Exception as e:
        log_test(f"/directories/{directory_id}/files", "POST", "FAIL", f"Exception: {str(e)}", "error")

def test_metadata_endpoints(file_id):
    """Test metadata GET/PUT endpoints"""
    print("\n=== Testing Metadata Endpoints ===")
    if not file_id:
        log_test("/files/<id>/metadata", "GET/PUT", "SKIP", "No file_id available")
        return

    try:
        # Test GET metadata
        response = requests.get(f"{BASE_URL}/files/{file_id}/metadata", timeout=10)
        if response.status_code == 200:
            log_test(f"/files/{file_id}/metadata", "GET", "PASS", "Metadata retrieved")
        else:
            log_test(f"/files/{file_id}/metadata", "GET", "FAIL", f"Status: {response.status_code}", "error")

        # Test PUT metadata
        metadata = {"tag": "test", "category": "automated-test"}
        response = requests.put(f"{BASE_URL}/files/{file_id}/metadata", json=metadata, timeout=10)
        if response.status_code == 200:
            log_test(f"/files/{file_id}/metadata", "PUT", "PASS", "Metadata updated")
        else:
            log_test(f"/files/{file_id}/metadata", "PUT", "FAIL", f"Status: {response.status_code}", "error")

    except Exception as e:
        log_test(f"/files/{file_id}/metadata", "GET/PUT", "FAIL", f"Exception: {str(e)}", "error")

def test_s3_endpoints():
    """Test S3-compatible endpoints"""
    print("\n=== Testing S3 Endpoints ===")

    # Test S3 POST
    try:
        files = {'file': ('s3_test.txt', BytesIO(b'S3 test file'), 'text/plain')}
        data = {'key': 'test-${filename}'}
        response = requests.post(f"{BASE_URL}/s3/test-bucket", files=files, data=data, headers=DEFAULT_HEADERS, timeout=10)

        if response.status_code == 200:
            log_test("/s3/<bucket>", "POST", "PASS", "S3 POST successful")
        else:
            log_test("/s3/<bucket>", "POST", "FAIL", f"Status: {response.status_code}, Response: {response.text[:200]}", "error")
    except Exception as e:
        log_test("/s3/<bucket>", "POST", "FAIL", f"Exception: {str(e)}", "error")

def test_box_endpoints():
    """Test Box-compatible endpoints"""
    print("\n=== Testing Box Endpoints ===")

    # Test Box file upload
    try:
        files = {'file': ('box_test.txt', BytesIO(b'Box test file'), 'text/plain')}
        response = requests.post(f"{BASE_URL}/2.0/files/content", files=files, headers=DEFAULT_HEADERS, timeout=10)

        if response.status_code == 201:
            data = response.json()
            log_test("/2.0/files/content", "POST", "PASS", "Box upload successful")
            return data.get('id')
        else:
            log_test("/2.0/files/content", "POST", "FAIL", f"Status: {response.status_code}", "error")
            return None
    except Exception as e:
        log_test("/2.0/files/content", "POST", "FAIL", f"Exception: {str(e)}", "error")
        return None

def test_box_download(file_id):
    """Test Box file download"""
    if not file_id:
        log_test("/2.0/files/<id>/content", "GET", "SKIP", "No file_id from Box upload")
        return

    try:
        response = requests.get(f"{BASE_URL}/2.0/files/{file_id}/content", timeout=10)
        if response.status_code == 200:
            log_test(f"/2.0/files/{file_id}/content", "GET", "PASS", "Box download successful")
        else:
            log_test(f"/2.0/files/{file_id}/content", "GET", "FAIL", f"Status: {response.status_code}", "error")
    except Exception as e:
        log_test(f"/2.0/files/{file_id}/content", "GET", "FAIL", f"Exception: {str(e)}", "error")

def test_metrics_endpoint():
    """Test /metrics endpoint"""
    print("\n=== Testing Metrics Endpoint ===")
    try:
        response = requests.get(f"{BASE_URL}/metrics", timeout=5)
        if response.status_code == 200:
            log_test("/metrics", "GET", "PASS", f"Metrics retrieved ({len(response.text)} bytes)")
        else:
            log_test("/metrics", "GET", "FAIL", f"Status: {response.status_code}", "error")
    except Exception as e:
        log_test("/metrics", "GET", "FAIL", f"Exception: {str(e)}", "error")

def test_invalid_inputs():
    """Test various invalid inputs"""
    print("\n=== Testing Invalid Inputs ===")

    # Test upload without file
    try:
        response = requests.post(f"{BASE_URL}/fileupload", headers=DEFAULT_HEADERS, timeout=10)
        if response.status_code == 400:
            log_test("/fileupload", "POST", "PASS", "Correctly rejected empty upload")
        else:
            log_test("/fileupload", "POST", "WARN", f"Unexpected status for empty upload: {response.status_code}", "warning")
    except Exception as e:
        log_test("/fileupload", "POST", "FAIL", f"Exception: {str(e)}", "error")

    # Test download with invalid ID
    try:
        response = requests.get(f"{BASE_URL}/download/invalid-id-12345", timeout=10)
        if response.status_code in [404, 410]:
            log_test("/download/invalid-id", "GET", "PASS", "Correctly returned 404/410 for invalid ID")
        else:
            log_test("/download/invalid-id", "GET", "WARN", f"Unexpected status: {response.status_code}", "warning")
    except Exception as e:
        log_test("/download/invalid-id", "GET", "FAIL", f"Exception: {str(e)}", "error")

    # Test invalid retention hours
    try:
        files = {'file': ('test.txt', BytesIO(b'Test'), 'text/plain')}
        data = {'retention_hours': '9999'}  # Should exceed max
        response = requests.post(f"{BASE_URL}/fileupload", files=files, data=data, headers=DEFAULT_HEADERS, timeout=10)
        if response.status_code == 400:
            log_test("/fileupload", "POST", "PASS", "Correctly rejected invalid retention hours")
        else:
            log_test("/fileupload", "POST", "WARN", f"Unexpected status for invalid retention: {response.status_code}", "warning")
    except Exception as e:
        log_test("/fileupload", "POST", "FAIL", f"Exception: {str(e)}", "error")

def test_ssrf_vulnerability():
    """Test for SSRF vulnerability"""
    print("\n=== Testing SSRF Vulnerability (Bug #1-2) ===")

    # Create a directory first
    try:
        payload = {"name": "SSRF Test"}
        response = requests.post(f"{BASE_URL}/directories", json=payload, headers=DEFAULT_HEADERS, timeout=10)
        if response.status_code == 201:
            dir_id = response.json().get('id')

            # Try to upload from localhost URL (should be blocked but currently isn't)
            dangerous_urls = [
                "http://127.0.0.1:8000/health",
                "http://localhost:8000/health",
                "http://169.254.169.254/latest/meta-data/"  # AWS metadata
            ]

            for url in dangerous_urls:
                try:
                    payload = {
                        "files": [{"url": url}],
                        "retention_hours": 1
                    }
                    response = requests.post(
                        f"{BASE_URL}/directories/{dir_id}/files",
                        json=payload,
                        headers=DEFAULT_HEADERS,
                        timeout=10
                    )

                    if response.status_code == 201:
                        log_test(f"/directories/{dir_id}/files", "POST", "FAIL",
                                f"SSRF VULNERABILITY: Successfully fetched internal URL: {url}", "critical")
                    else:
                        log_test(f"/directories/{dir_id}/files", "POST", "PASS",
                                f"Internal URL blocked: {url}")
                except Exception as e:
                    log_test(f"/directories/{dir_id}/files", "POST", "WARN",
                            f"Exception testing SSRF with {url}: {str(e)}", "warning")
        else:
            log_test("/directories", "POST", "SKIP", "Could not create directory for SSRF test")
    except Exception as e:
        log_test("/directories", "POST", "FAIL", f"Exception: {str(e)}", "error")

def test_csrf_bypass():
    """Test for CSRF bypass vulnerability"""
    print("\n=== Testing CSRF Bypass (Bug #3) ===")

    try:
        # Try upload without Origin or Referer headers
        files = {'file': ('csrf_test.txt', BytesIO(b'CSRF test'), 'text/plain')}
        headers = {}  # No Origin or Referer
        response = requests.post(f"{BASE_URL}/fileupload", files=files, headers=headers, timeout=10)

        if response.status_code == 201:
            log_test("/fileupload", "POST", "FAIL",
                    "CSRF BYPASS: Upload succeeded without Origin/Referer headers", "critical")
        elif response.status_code == 403:
            log_test("/fileupload", "POST", "PASS", "CSRF protection working: request blocked")
        else:
            log_test("/fileupload", "POST", "WARN",
                    f"Unexpected status for CSRF test: {response.status_code}", "warning")
    except Exception as e:
        log_test("/fileupload", "POST", "FAIL", f"Exception: {str(e)}", "error")

def print_summary():
    """Print test summary"""
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)

    passed = sum(1 for r in test_results if r.status == "PASS")
    failed = sum(1 for r in test_results if r.status == "FAIL")
    warned = sum(1 for r in test_results if r.status == "WARN")
    skipped = sum(1 for r in test_results if r.status == "SKIP")

    print(f"\nTotal Tests: {len(test_results)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Warnings: {warned}")
    print(f"Skipped: {skipped}")

    # Show critical issues
    critical = [r for r in test_results if r.severity == "critical"]
    if critical:
        print("\n" + "!"*80)
        print("CRITICAL ISSUES FOUND:")
        print("!"*80)
        for r in critical:
            print(f"  - {r.method} {r.endpoint}: {r.message}")

    # Show errors
    errors = [r for r in test_results if r.status == "FAIL"]
    if errors:
        print("\nFAILED TESTS:")
        for r in errors:
            print(f"  - {r.method} {r.endpoint}: {r.message}")

    # Show warnings
    warnings = [r for r in test_results if r.status == "WARN"]
    if warnings:
        print("\nWARNINGS:")
        for r in warnings:
            print(f"  - {r.method} {r.endpoint}: {r.message}")

def main():
    """Run all tests"""
    print("Starting comprehensive API testing...")
    print(f"Base URL: {BASE_URL}")
    print("="*80)

    # Basic tests
    test_health_endpoint()
    file_id = test_file_upload()
    test_file_download(file_id)
    test_upload_with_retention()
    test_upload_permanent()
    test_multiple_upload()

    # Directory tests
    directory_id = test_directory_creation()
    test_directory_list()
    test_upload_to_directory(directory_id)

    # Metadata tests
    test_metadata_endpoints(file_id)

    # S3 and Box tests
    test_s3_endpoints()
    box_file_id = test_box_endpoints()
    test_box_download(box_file_id)

    # Metrics
    test_metrics_endpoint()

    # Invalid inputs
    test_invalid_inputs()

    # Security tests
    test_ssrf_vulnerability()
    test_csrf_bypass()

    # Print summary
    print_summary()

    # Return exit code
    failed = sum(1 for r in test_results if r.status == "FAIL")
    critical = sum(1 for r in test_results if r.severity == "critical")

    if critical > 0:
        print("\n⚠️  CRITICAL VULNERABILITIES FOUND!")
        return 2
    elif failed > 0:
        print("\n⚠️  TESTS FAILED!")
        return 1
    else:
        print("\n✓ All tests passed!")
        return 0

if __name__ == "__main__":
    sys.exit(main())
