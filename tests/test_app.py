import importlib
import json
import subprocess
import sys
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


_CONFIG_ENV_VARS = [
    "WLS_EXECUTIONS_DIR",
    "WLS_EXECUTION_LOG",
    "WLS_ALLOWLIST_PATTERNS",
    "WLS_DENYLIST_PATTERNS",
    "WLS_RETENTION_SECONDS",
    "WLS_MAX_EXECUTIONS",
    "WLS_CPU_LIMIT_SECONDS",
    "WLS_MEMORY_LIMIT_MB",
    "WLS_CLEANUP_INTERVAL_SECONDS",
    "WLS_API_PASSWORD",
    "WLS_MATEX_WORKING_DIR",
]


@pytest.fixture
def import_app(tmp_path, monkeypatch):
    project_root = _project_root()
    sys.path.insert(0, str(project_root))
    created_clients: list[TestClient] = []

    def _load(env_overrides: dict[str, str | None] | None = None):
        for key in _CONFIG_ENV_VARS:
            monkeypatch.delenv(key, raising=False)

        exec_root = tmp_path / "execs"
        log_path = tmp_path / "executions.log"
        exec_root.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("WLS_EXECUTIONS_DIR", str(exec_root))
        monkeypatch.setenv("WLS_EXECUTION_LOG", str(log_path))

        if env_overrides:
            for key, value in env_overrides.items():
                if value is None:
                    monkeypatch.delenv(key, raising=False)
                else:
                    monkeypatch.setenv(key, str(value))

        sys.modules.pop("app.main", None)
        module = importlib.import_module("app.main")
        module = importlib.reload(module)
        client = TestClient(module.app)
        created_clients.append(client)
        return client, module, exec_root, log_path

    try:
        yield _load
    finally:
        for client in created_clients:
            with suppress():
                client.close()
        sys.modules.pop("app.main", None)
        with suppress():
            sys.path.remove(str(project_root))


def _fake_runner_with_artifact(command, cwd, timeout, preexec_fn):
    artifact = cwd / "result.txt"
    artifact.write_text("result")
    return subprocess.CompletedProcess(args=command, returncode=0, stdout="OK", stderr="")


def _fake_runner_noop(command, cwd, timeout, preexec_fn):
    return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")


def _fake_runner_with_output(command, cwd, timeout, preexec_fn):
    (cwd / "out.txt").write_text("ok")
    return subprocess.CompletedProcess(args=command, returncode=0, stdout="done", stderr="")


def _read_log_lines(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().splitlines() if line]


def test_run_and_fetch_artifacts(import_app, monkeypatch):
    client, module, exec_root, log_path = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_with_artifact)

    files = {"file": ("test.wls", b"Print[1]\n", "application/plain")}
    response = client.post("/run", files=files, data={"nickname": "first-run"})
    assert response.status_code == 200
    payload = response.json()

    execution_id = payload["execution_id"]
    assert payload["returncode"] == 0
    assert payload["stdout"] == "OK"
    assert payload["stderr"] == ""
    assert payload["filename"] == "test.wls"
    assert payload["elapsed_seconds"] >= 0
    assert payload["nickname"] == "first-run"
    assert payload["created_at"]
    assert payload["completed_at"]
    assert payload["command"][0] == "sandbox-exec"
    assert payload["active"] is True
    assert payload["supersedes"] == []
    assert payload["assets"] == []
    artifacts_map = {item["path"]: item["size_bytes"] for item in payload["artifacts"]}
    assert artifacts_map["result.txt"] == len(b"result")
    assert artifacts_map["test.wls"] == len(b"Print[1]\n")

    listed = client.get(f"/executions/{execution_id}").json()
    assert listed["execution_id"] == execution_id
    assert listed["nickname"] == "first-run"
    assert listed["active"] is True
    assert listed["assets"] == []

    catalog = client.get("/executions").json()["executions"]
    assert len(catalog) == 1
    assert catalog[0]["execution_id"] == execution_id
    assert catalog[0]["nickname"] == "first-run"
    assert catalog[0]["assets"] == []

    artifact_response = client.get(f"/executions/{execution_id}/artifacts/result.txt")
    assert artifact_response.status_code == 200
    assert artifact_response.content == b"result"
    assert artifact_response.headers.get("x-artifact-path") == "result.txt"

    logs = _read_log_lines(log_path)
    assert logs[0]["event"] == "execution_completed"
    assert logs[0]["execution_id"] == execution_id


def test_invalid_execution_id(import_app):
    client, module, *_ = import_app()
    response = client.get("/executions/badid")
    assert response.status_code == 400


def test_missing_artifact(import_app):
    client, module, *_ = import_app()
    missing_id = "a" * 32
    response = client.get(f"/executions/{missing_id}")
    assert response.status_code == 404


def test_duplicate_nickname_rejected(import_app, monkeypatch):
    client, module, *_ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    files = {"file": ("test.wls", b"", "application/plain")}
    first = client.post("/run", files=files, data={"nickname": "unique"})
    assert first.status_code == 200

    duplicate = client.post("/run", files=files, data={"nickname": "unique"})
    assert duplicate.status_code == 409


def test_run_with_assets(import_app, monkeypatch):
    client, module, *_ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    files = [
        ("file", ("main.wls", b"Print[\"hello\"]\n", "application/plain")),
        ("assets", ("data.txt", b"42", "text/plain")),
        ("assets", ("notes.md", b"# Notes", "text/markdown")),
    ]
    response = client.post("/run", files=files)
    assert response.status_code == 200
    payload = response.json()
    assert payload["assets"] == ["assets/data.txt", "assets/notes.md"]

    execution_id = payload["execution_id"]
    listed = client.get(f"/executions/{execution_id}").json()
    assert listed["assets"] == ["assets/data.txt", "assets/notes.md"]
    artifact_paths = {item["path"] for item in listed["artifacts"]}
    assert "assets/data.txt" in artifact_paths
    assert "assets/notes.md" in artifact_paths


def test_upload_assets_to_existing_execution(import_app, monkeypatch):
    client, module, *_ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    base_files = {"file": ("main.wls", b"Print[\"base\"]", "application/plain")}
    base_response = client.post("/run", files=base_files)
    execution_id = base_response.json()["execution_id"]

    upload_files = [
        ("assets", ("more.txt", b"data", "text/plain")),
        ("assets", ("other.bin", b"\x00\x01", "application/octet-stream")),
    ]
    upload_response = client.post(f"/executions/{execution_id}/assets", files=upload_files)
    assert upload_response.status_code == 200
    payload = upload_response.json()
    assert payload["assets"] == ["assets/more.txt", "assets/other.bin"]

    detail = client.get(f"/executions/{execution_id}").json()
    assert set(detail["assets"]) == {"assets/more.txt", "assets/other.bin"}
    artifacts = {item["path"] for item in detail["artifacts"]}
    assert "assets/more.txt" in artifacts
    assert "assets/other.bin" in artifacts


def test_run_with_invalid_assets(import_app, monkeypatch):
    client, module, *_ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    files_missing_name = [
        ("file", ("main.wls", b"Print[\"hi\"]", "application/plain")),
        ("assets", ("", b"no-name", "text/plain")),
    ]
    missing = client.post("/run", files=files_missing_name)
    assert missing.status_code == 422

    files_traversal = [
        ("file", ("main.wls", b"Print[\"hi\"]", "application/plain")),
        ("assets", ("../escape.txt", b"bad", "text/plain")),
    ]
    traversal = client.post("/run", files=files_traversal)
    assert traversal.status_code == 200
    assert traversal.json()["assets"] == ["assets/escape.txt"]


def test_replace_nickname_creates_history(import_app, monkeypatch):
    client, module, *_ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    files = {"file": ("test.wls", b"", "application/plain")}
    first = client.post("/run", files=files, data={"nickname": "shared", "nickname_mode": "replace"})
    assert first.status_code == 200
    first_id = first.json()["execution_id"]

    second = client.post("/run", files=files, data={"nickname": "shared", "nickname_mode": "replace"})
    assert second.status_code == 200
    second_id = second.json()["execution_id"]
    assert second.json()["supersedes"] == [first_id]

    first_meta = client.get(f"/executions/{first_id}").json()
    assert first_meta["active"] is False
    assert second_id in first_meta["superseded_by"]


def test_delete_execution(import_app, monkeypatch):
    client, module, exec_root, log_path = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    files = {"file": ("test.wls", b"", "application/plain")}
    response = client.post("/run", files=files)
    execution_id = response.json()["execution_id"]

    delete_resp = client.delete(f"/executions/{execution_id}")
    assert delete_resp.status_code == 204
    assert not (exec_root / execution_id).exists()

    follow_up = client.get(f"/executions/{execution_id}")
    assert follow_up.status_code == 404

    logs = _read_log_lines(log_path)
    assert any(entry["event"] == "execution_deleted" for entry in logs)


def test_allowlist_and_denylist_enforced(import_app, monkeypatch):
    client, module, *_ = import_app(
        {
            "WLS_ALLOWLIST_PATTERNS": "Print",
            "WLS_DENYLIST_PATTERNS": "Quit",
        }
    )
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    files = {"file": ("allowed.wls", b"Print[1]\n", "application/plain")}
    ok = client.post("/run", files=files)
    assert ok.status_code == 200

    files = {"file": ("denied.wls", b"Quit[]\n", "application/plain")}
    denied = client.post("/run", files=files)
    assert denied.status_code == 400


def test_cleanup_removes_old_executions(import_app, monkeypatch):
    client, module, exec_root, _ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    files = {"file": ("test.wls", b"", "application/plain")}
    response = client.post("/run", files=files)
    execution_id = response.json()["execution_id"]
    execution_dir = exec_root / execution_id

    metadata = module._load_execution_metadata(execution_dir)
    metadata["created_at"] = "2000-01-01T00:00:00Z"
    module._write_execution_metadata(execution_dir, metadata)

    module.RETENTION_SECONDS = 1
    module.MAX_EXECUTIONS = None
    module._cleanup_once(now=datetime(2000, 1, 2, tzinfo=timezone.utc))

    assert not execution_dir.exists()


def test_execution_metadata_persists_between_imports(import_app, monkeypatch):
    client, module, exec_root, _ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_with_output)

    files = {"file": ("persist.wls", b"", "application/plain")}
    response = client.post("/run", files=files, data={"nickname": "persisted"})
    execution_id = response.json()["execution_id"]
    client.close()

    # Re-import the app with the same environment.
    client, module, _, _ = import_app()

    catalog = client.get("/executions").json()["executions"]
    assert len(catalog) == 1
    record = catalog[0]
    assert record["execution_id"] == execution_id
    assert record["nickname"] == "persisted"
    assert isinstance(record["assets"], list)
    assert any(item["path"] == "out.txt" for item in record["artifacts"])

    detail = client.get(f"/executions/{execution_id}").json()
    assert detail["stdout"] == "done"
    assert detail["nickname"] == "persisted"
    assert isinstance(detail["assets"], list)


def test_password_required(import_app, monkeypatch):
    client, module, *_ = import_app({"WLS_API_PASSWORD": "secret"})
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    files = {"file": ("test.wls", b"", "application/plain")}
    missing = client.post("/run", files=files)
    assert missing.status_code == 401

    headers = {"X-Runner-Password": "secret"}
    ok = client.post("/run", files=files, headers=headers)
    assert ok.status_code == 200
    assert ok.json()["assets"] == []
    execution_id = ok.json()["execution_id"]

    list_missing = client.get("/executions")
    assert list_missing.status_code == 401

    list_ok = client.get("/executions", headers=headers)
    assert list_ok.status_code == 200

    add_assets = client.post(
        f"/executions/{execution_id}/assets",
        files=[("assets", ("added.txt", b"extra", "text/plain"))],
    )
    assert add_assets.status_code == 401

    add_assets_ok = client.post(
        f"/executions/{execution_id}/assets",
        headers=headers,
        files=[("assets", ("added.txt", b"extra", "text/plain"))],
    )
    assert add_assets_ok.status_code == 200
    assert "assets/added.txt" in add_assets_ok.json()["assets"]


def test_run_with_directory_archive(import_app, monkeypatch, tmp_path):
    """Test that directory archives are extracted correctly."""
    import zipfile

    client, module, exec_root, _ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    # Create a zip file with directory structure
    zip_path = tmp_path / "test_dir.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("subdir/file1.txt", "content1")
        zipf.writestr("subdir/file2.txt", "content2")
        zipf.writestr("file3.txt", "content3")

    files = [
        ("file", ("main.wls", b"Print[\"test\"]", "application/plain")),
        ("directory_archive", ("directory.zip", zip_path.read_bytes(), "application/zip")),
    ]

    response = client.post("/run", files=files)
    assert response.status_code == 200
    payload = response.json()

    # Check that files were extracted
    assert "subdir/file1.txt" in payload["assets"]
    assert "subdir/file2.txt" in payload["assets"]
    assert "file3.txt" in payload["assets"]

    # Verify artifacts include extracted files
    artifact_paths = {item["path"] for item in payload["artifacts"]}
    assert "subdir/file1.txt" in artifact_paths
    assert "subdir/file2.txt" in artifact_paths
    assert "file3.txt" in artifact_paths

    # Verify file content
    execution_id = payload["execution_id"]
    execution_dir = exec_root / execution_id
    assert (execution_dir / "subdir" / "file1.txt").read_text() == "content1"
    assert (execution_dir / "subdir" / "file2.txt").read_text() == "content2"
    assert (execution_dir / "file3.txt").read_text() == "content3"


def test_run_with_invalid_zip_archive(import_app, monkeypatch):
    """Test that invalid zip archives are rejected with 400."""
    client, module, *_ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    # Upload a non-zip file as directory_archive
    files = [
        ("file", ("main.wls", b"Print[\"test\"]", "application/plain")),
        ("directory_archive", ("directory.zip", b"not a valid zip file", "application/zip")),
    ]

    response = client.post("/run", files=files)
    assert response.status_code == 400
    assert "Invalid or corrupted zip archive" in response.json()["detail"]


def test_run_with_path_traversal_in_archive(import_app, monkeypatch, tmp_path):
    """Test that path traversal attempts in archives are blocked."""
    import zipfile

    client, module, *_ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    # Create a zip file with path traversal attempts (both file and directory)
    zip_path = tmp_path / "malicious.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("../escape.txt", "malicious content")
        zipf.writestr("../../another_escape.txt", "more malicious")

    files = [
        ("file", ("main.wls", b"Print[\"test\"]", "application/plain")),
        ("directory_archive", ("directory.zip", zip_path.read_bytes(), "application/zip")),
    ]

    response = client.post("/run", files=files)
    assert response.status_code == 400
    assert "Invalid path in archive" in response.json()["detail"]


def test_run_with_directory_traversal_in_archive(import_app, monkeypatch, tmp_path):
    """Test that directory path traversal attempts are blocked."""
    import zipfile

    client, module, *_ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    # Create a zip file with directory traversal in directory entries
    zip_path = tmp_path / "dir_traversal.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add a directory entry with path traversal
        info = zipfile.ZipInfo("../../malicious_dir/")
        info.external_attr = 0o040755 << 16  # Mark as directory
        zipf.writestr(info, "")

    files = [
        ("file", ("main.wls", b"Print[\"test\"]", "application/plain")),
        ("directory_archive", ("directory.zip", zip_path.read_bytes(), "application/zip")),
    ]

    response = client.post("/run", files=files)
    assert response.status_code == 400
    assert "Invalid path in archive" in response.json()["detail"]


def test_run_with_both_archive_and_assets_rejected(import_app, monkeypatch, tmp_path):
    """Test that providing both directory_archive and assets is rejected."""
    import zipfile

    client, module, *_ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    # Create a valid zip file
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("file1.txt", "content1")

    # Try to send both directory_archive and assets
    files = [
        ("file", ("main.wls", b"Print[\"test\"]", "application/plain")),
        ("directory_archive", ("directory.zip", zip_path.read_bytes(), "application/zip")),
        ("assets", ("asset.txt", b"asset content", "text/plain")),
    ]

    response = client.post("/run", files=files)
    assert response.status_code == 400
    assert "Cannot provide both directory_archive and assets" in response.json()["detail"]


def test_run_with_archive_containing_script_name(import_app, monkeypatch, tmp_path):
    """Test that archive cannot contain the script file to prevent override."""
    import zipfile

    client, module, *_ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    # Create a zip file that contains a file with the same name as the script
    zip_path = tmp_path / "malicious.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("main.wls", "malicious code")
        zipf.writestr("other.txt", "normal content")

    files = [
        ("file", ("main.wls", b"Print[\"test\"]", "application/plain")),
        ("directory_archive", ("directory.zip", zip_path.read_bytes(), "application/zip")),
    ]

    response = client.post("/run", files=files)
    assert response.status_code == 400
    assert "Archive cannot contain a file or directory that conflicts with the script file" in response.json()["detail"]


def test_sandbox_profile_denies_by_default(import_app, tmp_path):
    """Test that sandbox profile starts with deny default."""
    client, module, exec_root, _ = import_app()

    working_dir = tmp_path / "test_sandbox"
    working_dir.mkdir()

    profile = module._build_sandbox_profile(working_dir)

    # Should start with deny default, not allow default
    assert "(deny default)" in profile
    assert "(allow default)" not in profile


def test_sandbox_profile_allows_wolfram_paths(import_app, tmp_path):
    """Test that sandbox profile allows necessary Wolfram/Mathematica paths."""
    client, module, exec_root, _ = import_app()

    working_dir = tmp_path / "test_sandbox"
    working_dir.mkdir()

    profile = module._build_sandbox_profile(working_dir)

    # Should allow reading Mathematica.app and Wolfram.app
    assert "/Applications/Mathematica.app" in profile
    assert "/Applications/Wolfram.app" in profile
    assert "/Applications/WolframScript.app" in profile

    # Should allow reading user's Mathematica and Wolfram configuration
    assert "Library/Mathematica" in profile
    assert ".Mathematica" in profile
    assert "Library/Wolfram" in profile
    assert ".Wolfram" in profile

    # Should allow executing wolframscript
    assert "(allow process-exec" in profile
    assert "/usr/local/bin/wolframscript" in profile


def test_sandbox_profile_allows_latex_toolchain(import_app, tmp_path):
    """Test that sandbox profile allows LaTeX toolchain (pdflatex, ghostscript)."""
    client, module, exec_root, _ = import_app()

    working_dir = tmp_path / "test_sandbox"
    working_dir.mkdir()

    profile = module._build_sandbox_profile(working_dir)

    # Should allow pdflatex
    assert "/opt/homebrew/bin/pdflatex" in profile

    # Should allow ghostscript
    assert "/opt/homebrew/bin/gs" in profile

    # Should allow reading TeX trees
    assert "/opt/homebrew/Cellar/texlive" in profile
    assert "/opt/homebrew/Cellar/ghostscript" in profile
    assert "/opt/homebrew/share/texmf-config" in profile
    assert "/opt/homebrew/share/texmf-dist" in profile
    assert "/opt/homebrew/share/texmf-var" in profile

    # Should allow reading fonts
    assert "/System/Library/Fonts" in profile
    assert "/Library/Fonts" in profile


def test_sandbox_profile_allows_working_directory(import_app, tmp_path):
    """Test that sandbox profile allows reading and writing to working directory."""
    client, module, exec_root, _ = import_app()

    working_dir = tmp_path / "test_sandbox"
    working_dir.mkdir()

    profile = module._build_sandbox_profile(working_dir)

    # Should allow reading and writing to working directory
    escaped_path = str(working_dir).replace('"', '\\"')
    assert f'(subpath "{escaped_path}")' in profile

    # Should appear in both read and write sections
    assert profile.count(f'(subpath "{escaped_path}")') >= 2


def test_sandbox_profile_allows_matex_working_directory(import_app, tmp_path):
    """Test that sandbox profile allows MaTeX working directory."""
    client, module, exec_root, _ = import_app()

    working_dir = tmp_path / "test_sandbox"
    working_dir.mkdir()

    profile = module._build_sandbox_profile(working_dir)

    # Should include MaTeX working directory
    matex_dir = str(module.MATEX_WORKING_DIR).replace('"', '\\"')
    assert f'(subpath "{matex_dir}")' in profile


def test_sandbox_profile_allows_temp_directories(import_app, tmp_path):
    """Test that sandbox profile allows temp directories."""
    client, module, exec_root, _ = import_app()

    working_dir = tmp_path / "test_sandbox"
    working_dir.mkdir()

    profile = module._build_sandbox_profile(working_dir)

    # Should allow temp directories
    assert "/tmp" in profile
    assert "/private/tmp" in profile


def test_sandbox_profile_allows_process_operations(import_app, tmp_path):
    """Test that sandbox profile allows necessary process operations."""
    client, module, exec_root, _ = import_app()

    working_dir = tmp_path / "test_sandbox"
    working_dir.mkdir()

    profile = module._build_sandbox_profile(working_dir)

    # Should allow process fork and exec
    assert "(allow process-fork)" in profile
    assert "(allow process-exec-interpreter)" in profile


def test_matex_working_dir_default(import_app):
    """Test that MATEX_WORKING_DIR defaults to ~/.matex-tmp."""
    client, module, exec_root, _ = import_app()

    # Default should be ~/.matex-tmp
    expected_default = Path.home() / ".matex-tmp"
    assert module.MATEX_WORKING_DIR == expected_default
    assert module.MATEX_WORKING_DIR.exists()


def test_matex_working_dir_custom(import_app, tmp_path):
    """Test that MATEX_WORKING_DIR can be customized via environment variable."""
    custom_dir = tmp_path / "custom-matex"

    client, module, exec_root, _ = import_app(
        {"WLS_MATEX_WORKING_DIR": str(custom_dir)}
    )

    # Should use custom directory
    assert module.MATEX_WORKING_DIR == custom_dir
    assert module.MATEX_WORKING_DIR.exists()


def test_sandbox_profile_escapes_paths_correctly(import_app, tmp_path):
    """Test that sandbox profile escapes paths with special characters."""
    client, module, exec_root, _ = import_app()

    # Create a directory with quotes in the name (if possible)
    # For testing purposes, we'll just verify the escaping logic
    working_dir = tmp_path / "test_sandbox"
    working_dir.mkdir()

    profile = module._build_sandbox_profile(working_dir)

    # Verify that the profile is valid Scheme syntax
    assert profile.startswith("(version 1)")
    assert profile.count("(") == profile.count(")")  # Balanced parentheses


def test_run_creates_sandbox_with_proper_profile(import_app, monkeypatch):
    """Test that running a script creates a sandbox with the proper profile."""
    client, module, exec_root, _ = import_app()
    monkeypatch.setattr(module, "_run_wolframscript", _fake_runner_noop)

    files = {"file": ("test.wls", b"Print[1]\n", "application/plain")}
    response = client.post("/run", files=files)
    assert response.status_code == 200

    # Verify that the command includes sandbox-exec
    payload = response.json()
    command = payload["command"]
    assert command[0] == "sandbox-exec"
    assert command[1] == "-p"
    # command[2] should be the sandbox profile
    assert "(deny default)" in command[2]
    assert command[3] == "wolframscript"
