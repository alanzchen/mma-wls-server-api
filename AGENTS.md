# Agents Overview

This repository currently ships a single automation agent that accepts WolframScript uploads, executes them inside a sandboxed environment, and exposes execution metadata and artifacts over a FastAPI web API.

## Capabilities
- Upload `.wls` scripts via `POST /run` with optional nicknames and conflict policies (`nickname_mode`).
- Execute scripts using `sandbox-exec` with optional CPU and memory limits enforced through `RLIMIT_CPU` and `RLIMIT_AS`.
- Persist execution outputs, metadata, and generated artifacts for later retrieval.
- List, inspect, download artifacts, and delete executions through the `/executions` endpoints.
- Enforce simple security policies using allowlist and denylist regex patterns before execution.
- Optionally require per-request authentication via `WLS_API_PASSWORD` using the `X-Runner-Password` or `Authorization` headers.
- Emit structured newline-delimited JSON logs when `WLS_EXECUTION_LOG` is configured.

## Lifecycle
- Execution directories are stored under `WLS_EXECUTIONS_DIR` (defaults to `${TMPDIR}/wolframscript-executions`).
- A background retention task prunes old executions according to `WLS_RETENTION_SECONDS` and `WLS_MAX_EXECUTIONS`.
- Metadata is persisted per execution in `metadata.json`, enabling restart-safe history.

## Testing
- Run `uv run pytest` after changes to validate server behavior and safety features.
