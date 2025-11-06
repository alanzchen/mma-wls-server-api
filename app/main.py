from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, TypedDict

from fastapi import FastAPI, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse

try:
    import resource  # type: ignore
except ImportError:  # pragma: no cover - not expected on macOS/Linux
    resource = None  # type: ignore


def _compile_patterns(value: str | None) -> list[re.Pattern[str]]:
    if not value:
        return []
    patterns: list[re.Pattern[str]] = []
    for raw in value.split(","):
        raw = raw.strip()
        if raw:
            patterns.append(re.compile(raw, re.IGNORECASE))
    return patterns


def _read_int_env(name: str) -> int | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def _read_float_env(name: str) -> float | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if value > 0 else None


EXECUTIONS_ROOT = Path(
    os.environ.get("WLS_EXECUTIONS_DIR")
    or Path(tempfile.gettempdir()) / "wolframscript-executions"
).resolve()
EXECUTIONS_ROOT.mkdir(parents=True, exist_ok=True)

LOG_PATH_RAW = os.environ.get("WLS_EXECUTION_LOG")
LOG_PATH = Path(LOG_PATH_RAW).resolve() if LOG_PATH_RAW else None
if LOG_PATH:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

EXECUTION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
METADATA_FILENAME = "metadata.json"
IGNORED_ARTIFACT_NAMES = {METADATA_FILENAME}

ALLOWLIST_PATTERNS = _compile_patterns(os.environ.get("WLS_ALLOWLIST_PATTERNS"))
DENYLIST_PATTERNS = _compile_patterns(os.environ.get("WLS_DENYLIST_PATTERNS"))

CPU_LIMIT_SECONDS = _read_int_env("WLS_CPU_LIMIT_SECONDS")
MEMORY_LIMIT_MB = _read_int_env("WLS_MEMORY_LIMIT_MB")
MEMORY_LIMIT_BYTES = MEMORY_LIMIT_MB * 1024 * 1024 if MEMORY_LIMIT_MB else None

RETENTION_SECONDS = _read_float_env("WLS_RETENTION_SECONDS")
MAX_EXECUTIONS = _read_int_env("WLS_MAX_EXECUTIONS")
CLEANUP_INTERVAL_SECONDS = _read_float_env("WLS_CLEANUP_INTERVAL_SECONDS") or 300.0

NICKNAME_MAX_LENGTH = 128
ALLOWED_NICKNAME_MODES = {"unique", "replace"}


@asynccontextmanager
async def _lifespan(app: FastAPI):
    cleanup_task: asyncio.Task | None = None
    app.state.cleanup_task = None
    if RETENTION_SECONDS or MAX_EXECUTIONS:
        cleanup_task = asyncio.create_task(_cleanup_loop())
        app.state.cleanup_task = cleanup_task
    try:
        yield
    finally:
        if cleanup_task:
            cleanup_task.cancel()
            with suppress(asyncio.CancelledError):
                await cleanup_task
        app.state.cleanup_task = None


app = FastAPI(
    title="WolframScript Runner",
    version="0.3.0",
    description=(
        "Upload a WolframScript (.wls) file, execute it via the wolframscript CLI, "
        "and manage the produced artifacts."
    ),
    lifespan=_lifespan,
)


class Artifact(TypedDict):
    path: str
    size_bytes: int


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(timestamp: str | None) -> datetime | None:
    if not timestamp:
        return None
    try:
        ts = timestamp.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _iter_execution_dirs() -> Iterable[Path]:
    if not EXECUTIONS_ROOT.exists():
        return
    for child in EXECUTIONS_ROOT.iterdir():
        if child.is_dir():
            yield child


def _make_preexec_fn() -> Callable[[], None] | None:
    if resource is None:
        return None

    def preexec() -> None:
        if resource is None:  # pragma: no cover - defensive check
            return
        if CPU_LIMIT_SECONDS:
            resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SECONDS, CPU_LIMIT_SECONDS))
        if MEMORY_LIMIT_BYTES:
            resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT_BYTES, MEMORY_LIMIT_BYTES))

    return preexec if (CPU_LIMIT_SECONDS or MEMORY_LIMIT_BYTES) else None


def _run_wolframscript(
    command: list[str],
    cwd: Path,
    timeout: float,
    preexec_fn: Callable[[], None] | None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        cwd=cwd,
        preexec_fn=preexec_fn,
    )


def _build_sandbox_profile(working_dir: Path) -> str:
    path = str(working_dir).replace('"', '\\"')
    return (
        "(version 1)\n"
        "(allow default)\n"
        f'(allow file-write* (subpath "{path}") (subpath "/tmp"))\n'
        f'(allow file-read* (subpath "{path}"))\n'
    )


def _resolve_execution_dir(execution_id: str) -> Path:
    if not EXECUTION_ID_PATTERN.match(execution_id):
        raise HTTPException(status_code=400, detail="Invalid execution id.")

    execution_dir = (EXECUTIONS_ROOT / execution_id).resolve()
    try:
        execution_dir.relative_to(EXECUTIONS_ROOT)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Execution not found.") from exc

    if not execution_dir.is_dir():
        raise HTTPException(status_code=404, detail="Execution not found.")
    return execution_dir


def _list_artifacts(execution_dir: Path) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for path in execution_dir.rglob("*"):
        if path.is_file() and path.name not in IGNORED_ARTIFACT_NAMES:
            artifacts.append(
                {
                    "path": path.relative_to(execution_dir).as_posix(),
                    "size_bytes": path.stat().st_size,
                }
            )
    return sorted(artifacts, key=lambda item: item["path"])


def _load_execution_metadata(execution_dir: Path) -> dict[str, Any]:
    metadata_path = execution_dir / METADATA_FILENAME
    metadata: dict[str, Any] = {}
    if metadata_path.is_file():
        try:
            metadata = json.loads(metadata_path.read_text())
        except json.JSONDecodeError:
            metadata = {}

    metadata["execution_id"] = execution_dir.name
    metadata.setdefault("nickname", None)
    metadata.setdefault("filename", None)
    metadata.setdefault("created_at", None)
    metadata.setdefault("completed_at", None)
    metadata.setdefault("timeout_seconds", None)
    metadata.setdefault("returncode", None)
    metadata.setdefault("elapsed_seconds", None)
    metadata.setdefault("stdout", "")
    metadata.setdefault("stderr", "")
    metadata.setdefault("active", metadata.get("active", True))
    metadata.setdefault("supersedes", [])
    metadata.setdefault("superseded_by", [])
    metadata["artifacts"] = _list_artifacts(execution_dir)
    return metadata


def _write_execution_metadata(execution_dir: Path, metadata: dict[str, Any]) -> None:
    metadata_path = execution_dir / METADATA_FILENAME
    temporary_path = metadata_path.with_suffix(".tmp")
    temporary_path.write_text(json.dumps(metadata, indent=2, sort_keys=True))
    temporary_path.replace(metadata_path)


def _append_execution_log(entry: dict[str, Any]) -> None:
    if not LOG_PATH:
        return
    log_line = json.dumps(entry, sort_keys=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(log_line + "\n")


def _list_all_executions() -> list[dict[str, Any]]:
    records = [_load_execution_metadata(directory) for directory in _iter_execution_dirs()]
    records.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    return records


def _find_executions_by_nickname(nickname: str) -> list[tuple[dict[str, Any], Path]]:
    matches: list[tuple[dict[str, Any], Path]] = []
    normalized = nickname.strip()
    for directory in _iter_execution_dirs():
        metadata = _load_execution_metadata(directory)
        if metadata.get("nickname") == normalized:
            matches.append((metadata, directory))
    return matches


def _mark_superseded(execution_dir: Path, superseded_by: str) -> None:
    metadata = _load_execution_metadata(execution_dir)
    metadata["active"] = False
    existing = metadata.get("superseded_by")
    if isinstance(existing, list):
        if superseded_by not in existing:
            existing.append(superseded_by)
    elif existing and existing != superseded_by:
        metadata["superseded_by"] = [existing, superseded_by]
    else:
        metadata["superseded_by"] = [superseded_by]
    _write_execution_metadata(execution_dir, metadata)


def _validate_script_content(script_bytes: bytes) -> None:
    text = script_bytes.decode("utf-8", errors="ignore")
    if ALLOWLIST_PATTERNS and not any(pattern.search(text) for pattern in ALLOWLIST_PATTERNS):
        raise HTTPException(
            status_code=400, detail="Script does not match the required allowlist patterns."
        )
    if any(pattern.search(text) for pattern in DENYLIST_PATTERNS):
        raise HTTPException(status_code=400, detail="Script matches a denied pattern.")


def _delete_execution_dir(execution_dir: Path) -> None:
    with suppress(FileNotFoundError):
        shutil.rmtree(execution_dir)


def _cleanup_once(now: datetime | None = None) -> None:
    records = []
    for directory in _iter_execution_dirs():
        metadata = _load_execution_metadata(directory)
        records.append((metadata, directory))

    if not records:
        return

    now = now or datetime.now(timezone.utc)

    if RETENTION_SECONDS:
        threshold = now - timedelta(seconds=RETENTION_SECONDS)
        for metadata, directory in records:
            created = _parse_iso(metadata.get("created_at"))
            if created and created < threshold:
                _delete_execution_dir(directory)

    if MAX_EXECUTIONS:
        remaining = []
        for metadata, directory in records:
            created_value = metadata.get("created_at") or ""
            remaining.append((created_value, directory))
        remaining.sort(reverse=True)
        for _, directory in remaining[MAX_EXECUTIONS:]:
            _delete_execution_dir(directory)


async def _cleanup_loop() -> None:
    if not (RETENTION_SECONDS or MAX_EXECUTIONS):
        return
    try:
        while True:
            await asyncio.to_thread(_cleanup_once)
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
    except asyncio.CancelledError:  # pragma: no cover - lifecycle management
        raise


@app.post("/run")
async def run_wolframscript(
    file: UploadFile = File(..., description="WolframScript file (.wls) to execute."),
    timeout: float = Query(
        60.0,
        gt=0,
        le=600,
        description="Maximum time in seconds the script is allowed to run.",
    ),
    nickname: str | None = Form(
        default=None,
        description="Optional nickname for this execution.",
    ),
    nickname_mode: str = Form(
        default="unique",
        description='Nickname conflict policy: "unique" or "replace".',
    ),
) -> dict[str, Any]:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Upload must include a filename.")

    script_filename = Path(file.filename).name
    if not script_filename.lower().endswith(".wls"):
        raise HTTPException(status_code=400, detail="Only .wls files are supported.")

    nickname_mode = nickname_mode.strip().lower()
    if nickname_mode not in ALLOWED_NICKNAME_MODES:
        raise HTTPException(status_code=400, detail="Unsupported nickname_mode value.")

    if nickname is not None:
        nickname = nickname.strip()
        if not nickname:
            nickname = None
        elif len(nickname) > NICKNAME_MAX_LENGTH:
            raise HTTPException(
                status_code=400, detail=f"Nickname must be <= {NICKNAME_MAX_LENGTH} characters."
            )

    content = await file.read()
    await file.close()

    _validate_script_content(content)

    superseded_ids: list[str] = []
    if nickname:
        matches = _find_executions_by_nickname(nickname)
        active_matches = [meta for meta, _ in matches if meta.get("active", True)]
        if matches and nickname_mode == "unique" and active_matches:
            raise HTTPException(status_code=409, detail="Nickname already in use.")
        if nickname_mode == "replace":
            superseded_ids = [meta["execution_id"] for meta in active_matches]

    execution_id = secrets.token_hex(16)
    execution_dir = (EXECUTIONS_ROOT / execution_id).resolve()
    execution_dir.mkdir(parents=True, exist_ok=False)

    script_path = execution_dir / script_filename
    script_path.write_bytes(content)

    sandbox_profile = _build_sandbox_profile(execution_dir)
    command = [
        "sandbox-exec",
        "-p",
        sandbox_profile,
        "wolframscript",
        "-file",
        str(script_path),
    ]

    started_at = _utcnow_iso()
    start = time.monotonic()
    preexec_fn = _make_preexec_fn()
    try:
        result = await run_in_threadpool(
            _run_wolframscript, command, execution_dir, timeout, preexec_fn
        )
        elapsed = time.monotonic() - start
        completed_at = _utcnow_iso()
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - defensive branch
        elapsed = time.monotonic() - start
        raise HTTPException(
            status_code=504,
            detail={
                "message": f"wolframscript timed out after {timeout} seconds.",
                "timeout_seconds": timeout,
                "stdout": exc.stdout or "",
                "stderr": exc.stderr or "",
                "elapsed_seconds": elapsed,
            },
        ) from exc
    except FileNotFoundError as exc:  # pragma: no cover - depends on host environment
        missing = exc.filename or "sandbox-exec"
        raise HTTPException(
            status_code=500,
            detail=f"{missing} command is not available on the server.",
        ) from exc

    artifacts = _list_artifacts(execution_dir)
    metadata: dict[str, Any] = {
        "execution_id": execution_id,
        "nickname": nickname,
        "nickname_mode": nickname_mode,
        "filename": script_filename,
        "command": command,
        "timeout_seconds": timeout,
        "created_at": started_at,
        "completed_at": completed_at,
        "returncode": result.returncode,
        "elapsed_seconds": elapsed,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "artifacts": artifacts,
        "active": True,
        "supersedes": superseded_ids,
        "superseded_by": [],
    }
    _write_execution_metadata(execution_dir, metadata)

    for superseded_id in superseded_ids:
        superseded_dir = _resolve_execution_dir(superseded_id)
        _mark_superseded(superseded_dir, execution_id)

    _append_execution_log(
        {
            "event": "execution_completed",
            "timestamp": completed_at,
            "execution_id": execution_id,
            "nickname": nickname,
            "returncode": result.returncode,
            "elapsed_seconds": elapsed,
        }
    )

    _cleanup_once()
    return metadata


@app.get("/executions")
async def list_executions() -> dict[str, Any]:
    return {"executions": _list_all_executions()}


@app.get("/executions/{execution_id}")
async def get_execution(execution_id: str) -> dict[str, Any]:
    execution_dir = _resolve_execution_dir(execution_id)
    return _load_execution_metadata(execution_dir)


@app.delete("/executions/{execution_id}", status_code=204)
async def delete_execution(execution_id: str) -> Response:
    execution_dir = _resolve_execution_dir(execution_id)
    metadata = _load_execution_metadata(execution_dir)
    _delete_execution_dir(execution_dir)
    _append_execution_log(
        {
            "event": "execution_deleted",
            "timestamp": _utcnow_iso(),
            "execution_id": execution_id,
            "nickname": metadata.get("nickname"),
        }
    )
    return Response(status_code=204)


@app.get("/executions/{execution_id}/artifacts/{artifact_path:path}")
async def fetch_execution_artifact(execution_id: str, artifact_path: str) -> FileResponse:
    execution_dir = _resolve_execution_dir(execution_id)
    candidate = (execution_dir / artifact_path).resolve()

    try:
        candidate.relative_to(execution_dir)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Artifact not found.") from exc

    if not candidate.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found.")

    return FileResponse(
        candidate,
        filename=candidate.name,
        media_type="application/octet-stream",
        headers={"X-Artifact-Path": candidate.relative_to(execution_dir).as_posix()},
    )
