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
import zipfile
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, TypedDict

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Response,
    UploadFile,
)
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

API_PASSWORD = os.environ.get("WLS_API_PASSWORD")

RETENTION_SECONDS = _read_float_env("WLS_RETENTION_SECONDS")
MAX_EXECUTIONS = _read_int_env("WLS_MAX_EXECUTIONS")
CLEANUP_INTERVAL_SECONDS = _read_float_env("WLS_CLEANUP_INTERVAL_SECONDS") or 300.0

NICKNAME_MAX_LENGTH = 128
ALLOWED_NICKNAME_MODES = {"unique", "replace"}

# Allowed Wolfram Language file extensions
WOLFRAM_FILE_EXTENSIONS = {".wls", ".wl", ".m", ".nb", ".cdf", ".mx"}


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
        "Upload a Wolfram Language file (.wls, .wl, .m, .nb, etc.), execute it via the wolframscript CLI, "
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


async def _store_assets(execution_dir: Path, uploads: list[UploadFile]) -> list[str]:
    if not uploads:
        return []
    assets_dir = execution_dir / "assets"
    assets_dir.mkdir(exist_ok=True)
    saved: list[str] = []
    for upload in uploads:
        try:
            if not upload.filename:
                raise HTTPException(status_code=400, detail="Asset uploads must include a filename.")
            asset_name = Path(upload.filename).name
            if not asset_name:
                raise HTTPException(status_code=400, detail="Asset filename is invalid.")
            asset_bytes = await upload.read()
            asset_path = (assets_dir / asset_name).resolve()
            try:
                asset_path.relative_to(assets_dir)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Asset filename is invalid.") from exc
            asset_path.write_bytes(asset_bytes)
            saved.append(asset_path.relative_to(execution_dir).as_posix())
        finally:
            await upload.close()
    return sorted(saved)


async def _extract_directory_archive(
    execution_dir: Path, archive_upload: UploadFile, script_filename: str
) -> list[str]:
    """Extract a directory archive into the execution directory.

    Args:
        execution_dir: The execution directory to extract files into
        archive_upload: The uploaded zip file
        script_filename: The name of the script file to protect from overwriting

    Returns:
        List of extracted file paths (relative to execution_dir)
    """
    if not archive_upload.filename:
        raise HTTPException(status_code=400, detail="Directory archive must include a filename.")

    temp_zip_path = None
    try:
        # Stream the content to a temporary file to avoid loading all in memory
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
            temp_zip_path = Path(temp_file.name)
            while chunk := await archive_upload.read(8192):  # Read in 8KB chunks
                await run_in_threadpool(temp_file.write, chunk)

        # Extract the zip file
        extracted_files = []
        with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
            # Validate all paths before extraction and collect filenames
            for zip_info in zipf.infolist():
                # Validate both files and directories for path traversal
                target_path = (execution_dir / zip_info.filename).resolve()
                try:
                    target_path.relative_to(execution_dir)
                except ValueError as exc:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid path in archive: {zip_info.filename}"
                    ) from exc

                # Prevent archive from overwriting the validated script file
                if zip_info.filename == script_filename or zip_info.filename.endswith(f"/{script_filename}"):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Archive cannot contain the script file: {script_filename}"
                    )

                # Collect only file paths (not directories)
                if not zip_info.is_dir():
                    extracted_files.append(zip_info.filename)

            # Extract all files after validation
            zipf.extractall(execution_dir)

        return sorted(extracted_files)
    except zipfile.BadZipFile as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid or corrupted zip archive"
        ) from exc
    except zipfile.LargeZipFile as exc:
        raise HTTPException(
            status_code=400,
            detail="Zip archive is too large"
        ) from exc
    finally:
        # Clean up temporary zip file
        if temp_zip_path and temp_zip_path.exists():
            temp_zip_path.unlink()
        await archive_upload.close()


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
    metadata.setdefault("assets", [])
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


async def _require_password(
    password_header: str | None = Header(default=None, alias="X-Runner-Password"),
    authorization: str | None = Header(default=None),
) -> None:
    if not API_PASSWORD:
        return

    if password_header == API_PASSWORD:
        return

    if authorization:
        if authorization.startswith("Bearer "):
            token = authorization[len("Bearer ") :].strip()
            if token == API_PASSWORD:
                return
        if authorization.startswith("Basic "):
            import base64

            try:
                decoded = base64.b64decode(authorization[len("Basic ") :]).decode("utf-8")
                _, _, pwd = decoded.partition(":")
                if pwd == API_PASSWORD:
                    return
            except (ValueError, UnicodeDecodeError):
                pass

    raise HTTPException(
        status_code=401,
        detail="Invalid or missing password.",
        headers={"WWW-Authenticate": "Bearer"},
    )


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


@app.get("/executions")
async def list_executions(_: None = Depends(_require_password)) -> dict[str, Any]:
    return {"executions": _list_all_executions()}


@app.post("/run")
async def run_wolframscript(
    file: UploadFile = File(..., description="Wolfram Language file (.wls, .wl, .m, .nb, etc.) to execute."),
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
    assets: list[UploadFile] | None = File(
        default=None,
        description="Optional additional files to stage alongside the script.",
    ),
    directory_archive: UploadFile | None = File(
        default=None,
        description="Optional directory archive (zip) to extract into the execution directory.",
    ),
    _: None = Depends(_require_password),
) -> dict[str, Any]:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Upload must include a filename.")

    script_filename = Path(file.filename).name
    file_ext = Path(script_filename).suffix.lower()
    if file_ext not in WOLFRAM_FILE_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Only Wolfram Language files are supported: {', '.join(sorted(WOLFRAM_FILE_EXTENSIONS))}"
        )

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

    # Validate mutually exclusive parameters
    if directory_archive and assets:
        raise HTTPException(
            status_code=400,
            detail="Cannot provide both directory_archive and assets. Use one or the other."
        )

    script_path = execution_dir / script_filename
    script_path.write_bytes(content)

    # Handle directory archive or individual assets
    saved_assets: list[str] = []
    if directory_archive:
        # Extract directory archive
        saved_assets = await _extract_directory_archive(execution_dir, directory_archive, script_filename)
    elif assets:
        # Store individual assets
        saved_assets = await _store_assets(execution_dir, assets)

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
        "assets": saved_assets,
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


@app.get("/executions/{execution_id}")
async def get_execution(
    execution_id: str, _: None = Depends(_require_password)
) -> dict[str, Any]:
    execution_dir = _resolve_execution_dir(execution_id)
    return _load_execution_metadata(execution_dir)


@app.delete("/executions/{execution_id}", status_code=204)
async def delete_execution(
    execution_id: str, _: None = Depends(_require_password)
) -> Response:
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
async def fetch_execution_artifact(
    execution_id: str,
    artifact_path: str,
    _: None = Depends(_require_password),
) -> FileResponse:
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


@app.post("/executions/{execution_id}/assets")
async def upload_execution_assets(
    execution_id: str,
    assets: list[UploadFile] = File(..., description="Files to upload into the execution assets directory."),
    _: None = Depends(_require_password),
) -> dict[str, Any]:
    if not assets:
        raise HTTPException(status_code=400, detail="At least one asset must be provided.")

    execution_dir = _resolve_execution_dir(execution_id)
    staged_assets = await _store_assets(execution_dir, assets)

    metadata = _load_execution_metadata(execution_dir)
    existing_assets = set(metadata.get("assets") or [])
    for asset in staged_assets:
        existing_assets.add(asset)
    metadata["assets"] = sorted(existing_assets)
    metadata["artifacts"] = _list_artifacts(execution_dir)
    _write_execution_metadata(execution_dir, metadata)

    _append_execution_log(
        {
            "event": "assets_uploaded",
            "timestamp": _utcnow_iso(),
            "execution_id": execution_id,
            "assets": staged_assets,
        }
    )

    return {
        "execution_id": execution_id,
        "assets": metadata["assets"],
        "artifacts": metadata["artifacts"],
    }


class FileInfo(TypedDict):
    path: str
    size_bytes: int
    mtime: float
    is_metadata: bool


@app.get("/executions/{execution_id}/files")
async def list_execution_files(
    execution_id: str, _: None = Depends(_require_password)
) -> dict[str, Any]:
    """List all files in an execution directory with metadata."""
    execution_dir = _resolve_execution_dir(execution_id)
    files: list[FileInfo] = []

    for path in execution_dir.rglob("*"):
        if path.is_file():
            stat = path.stat()
            files.append(
                {
                    "path": path.relative_to(execution_dir).as_posix(),
                    "size_bytes": stat.st_size,
                    "mtime": stat.st_mtime,
                    "is_metadata": path.name == METADATA_FILENAME,
                }
            )

    return {
        "execution_id": execution_id,
        "files": sorted(files, key=lambda f: f["path"]),
    }


@app.put("/executions/{execution_id}/files/{file_path:path}")
async def upload_execution_file(
    execution_id: str,
    file_path: str,
    file: UploadFile = File(..., description="File to upload."),
    _: None = Depends(_require_password),
) -> dict[str, Any]:
    """Upload or update a file in the execution directory."""
    execution_dir = _resolve_execution_dir(execution_id)

    # Prevent uploading metadata.json directly
    if file_path == METADATA_FILENAME or file_path.endswith(f"/{METADATA_FILENAME}"):
        raise HTTPException(status_code=400, detail="Cannot modify metadata file directly.")

    # Resolve and validate the target path
    target_path = (execution_dir / file_path).resolve()
    try:
        target_path.relative_to(execution_dir)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid file path.") from exc

    # Create parent directories if needed
    target_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the file
    content = await file.read()
    await file.close()
    target_path.write_bytes(content)

    stat = target_path.stat()
    return {
        "execution_id": execution_id,
        "path": file_path,
        "size_bytes": stat.st_size,
        "mtime": stat.st_mtime,
    }


@app.delete("/executions/{execution_id}/files/{file_path:path}", status_code=204)
async def delete_execution_file(
    execution_id: str,
    file_path: str,
    _: None = Depends(_require_password),
) -> Response:
    """Delete a file from the execution directory."""
    execution_dir = _resolve_execution_dir(execution_id)

    # Prevent deleting metadata.json
    if file_path == METADATA_FILENAME or file_path.endswith(f"/{METADATA_FILENAME}"):
        raise HTTPException(status_code=400, detail="Cannot delete metadata file.")

    # Resolve and validate the target path
    target_path = (execution_dir / file_path).resolve()
    try:
        target_path.relative_to(execution_dir)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="File not found.") from exc

    if not target_path.is_file():
        raise HTTPException(status_code=404, detail="File not found.")

    target_path.unlink()

    # Clean up empty parent directories (but not the execution dir itself)
    parent = target_path.parent
    while parent != execution_dir:
        try:
            if not any(parent.iterdir()):
                parent.rmdir()
                parent = parent.parent
            else:
                break
        except (OSError, ValueError):
            break

    return Response(status_code=204)


@app.post("/executions/{execution_id}/execute")
async def execute_file(
    execution_id: str,
    file_path: str = Form(..., description="Path to the Wolfram Language file to execute within the execution directory."),
    timeout: float = Form(
        60.0,
        gt=0,
        le=600,
        description="Maximum time in seconds the script is allowed to run.",
    ),
    _: None = Depends(_require_password),
) -> dict[str, Any]:
    """Execute a Wolfram Language file within an existing execution directory."""
    execution_dir = _resolve_execution_dir(execution_id)

    # Resolve and validate the script path
    script_path = (execution_dir / file_path).resolve()
    try:
        script_path.relative_to(execution_dir)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Script file not found.") from exc

    if not script_path.is_file():
        raise HTTPException(status_code=404, detail="Script file not found.")

    file_ext = script_path.suffix.lower()
    if file_ext not in WOLFRAM_FILE_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Only Wolfram Language files can be executed: {', '.join(sorted(WOLFRAM_FILE_EXTENSIONS))}"
        )

    # Validate script content
    script_content = script_path.read_bytes()
    _validate_script_content(script_content)

    # Build and execute the command
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

    # Update metadata with execution results
    metadata = _load_execution_metadata(execution_dir)
    execution_record = {
        "file_path": file_path,
        "started_at": started_at,
        "completed_at": completed_at,
        "returncode": result.returncode,
        "elapsed_seconds": elapsed,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timeout_seconds": timeout,
    }

    # Store execution history
    if "execution_history" not in metadata:
        metadata["execution_history"] = []
    metadata["execution_history"].append(execution_record)

    # Update last execution info
    metadata["last_execution"] = execution_record
    metadata["artifacts"] = _list_artifacts(execution_dir)
    _write_execution_metadata(execution_dir, metadata)

    _append_execution_log(
        {
            "event": "file_executed",
            "timestamp": completed_at,
            "execution_id": execution_id,
            "file_path": file_path,
            "returncode": result.returncode,
            "elapsed_seconds": elapsed,
        }
    )

    return {
        "execution_id": execution_id,
        "file_path": file_path,
        "returncode": result.returncode,
        "elapsed_seconds": elapsed,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "artifacts": metadata["artifacts"],
    }
