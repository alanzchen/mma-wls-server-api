#!/usr/bin/env python3
"""
Test script for the folder sync functionality.
Run the server first, then execute this script.
"""

import json
import sys
import tempfile
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install it with: pip install requests")
    sys.exit(1)


def test_sync_endpoints():
    """Test the new sync endpoints."""
    base_url = "http://localhost:8000"
    session = requests.Session()

    print("Testing folder sync endpoints...")

    # Create a test execution with some files
    print("\n1. Creating test execution...")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".wls", delete=False) as f:
        f.write('Print["Hello from test"]')
        script_path = Path(f.name)

    try:
        with open(script_path, "rb") as f:
            response = session.post(
                f"{base_url}/run",
                files={"file": ("test.wls", f, "application/octet-stream")},
                data={"timeout": 60},
            )
        response.raise_for_status()
        execution_data = response.json()
        execution_id = execution_data["execution_id"]
        print(f"   Created execution: {execution_id}")
    finally:
        script_path.unlink()

    # Test listing files
    print("\n2. Testing file listing...")
    response = session.get(f"{base_url}/executions/{execution_id}/files")
    response.raise_for_status()
    files_data = response.json()
    print(f"   Found {len(files_data['files'])} files:")
    for file in files_data["files"]:
        print(f"     - {file['path']} ({file['size_bytes']} bytes)")

    # Test uploading a file
    print("\n3. Testing file upload...")
    test_content = b"This is a test file for syncing"
    response = session.put(
        f"{base_url}/executions/{execution_id}/files/test_data.txt",
        files={"file": ("test_data.txt", test_content)},
    )
    response.raise_for_status()
    upload_result = response.json()
    print(f"   Uploaded: {upload_result['path']} ({upload_result['size_bytes']} bytes)")

    # Verify file appears in listing
    print("\n4. Verifying file in listing...")
    response = session.get(f"{base_url}/executions/{execution_id}/files")
    response.raise_for_status()
    files_data = response.json()
    file_paths = [f["path"] for f in files_data["files"]]
    assert "test_data.txt" in file_paths, "Uploaded file not found in listing"
    print("   ✓ File found in listing")

    # Test downloading the file
    print("\n5. Testing file download...")
    response = session.get(
        f"{base_url}/executions/{execution_id}/artifacts/test_data.txt"
    )
    response.raise_for_status()
    downloaded_content = response.content
    assert downloaded_content == test_content, "Downloaded content doesn't match"
    print("   ✓ Downloaded content matches")

    # Test uploading a nested file
    print("\n6. Testing nested file upload...")
    response = session.put(
        f"{base_url}/executions/{execution_id}/files/data/nested/file.csv",
        files={"file": ("file.csv", b"col1,col2\n1,2\n3,4")},
    )
    response.raise_for_status()
    print("   ✓ Nested file uploaded")

    # Test executing a file
    print("\n7. Testing file execution...")
    # Upload a new script
    script_content = b'Print["Execution test successful"]'
    response = session.put(
        f"{base_url}/executions/{execution_id}/files/execute_test.wls",
        files={"file": ("execute_test.wls", script_content)},
    )
    response.raise_for_status()

    # Execute it
    response = session.post(
        f"{base_url}/executions/{execution_id}/execute",
        data={"file_path": "execute_test.wls", "timeout": 30},
    )
    response.raise_for_status()
    exec_result = response.json()
    print(f"   Execution returncode: {exec_result['returncode']}")
    print(f"   Execution time: {exec_result['elapsed_seconds']:.2f}s")
    if exec_result.get("stdout"):
        print(f"   Stdout: {exec_result['stdout']}")

    # Test deleting a file
    print("\n8. Testing file deletion...")
    response = session.delete(
        f"{base_url}/executions/{execution_id}/files/test_data.txt"
    )
    assert response.status_code == 204, f"Expected 204, got {response.status_code}"
    print("   ✓ File deleted")

    # Verify file is gone
    print("\n9. Verifying file deletion...")
    response = session.get(f"{base_url}/executions/{execution_id}/files")
    response.raise_for_status()
    files_data = response.json()
    file_paths = [f["path"] for f in files_data["files"]]
    assert "test_data.txt" not in file_paths, "Deleted file still in listing"
    print("   ✓ File removed from listing")

    # Clean up
    print("\n10. Cleaning up...")
    response = session.delete(f"{base_url}/executions/{execution_id}")
    assert response.status_code == 204, f"Expected 204, got {response.status_code}"
    print("   ✓ Execution deleted")

    print("\n✅ All tests passed!")


if __name__ == "__main__":
    try:
        test_sync_endpoints()
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Cannot connect to server at http://localhost:8000")
        print("   Please start the server first with: uvicorn app.main:app")
        sys.exit(1)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
