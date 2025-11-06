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
