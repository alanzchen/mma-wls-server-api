## WolframScript Web Runner

This service exposes a small FastAPI server that accepts an uploaded WolframScript (`.wls`) file, executes it with the `wolframscript` CLI, and returns the captured standard output, standard error, and exit code.

### Prerequisites
- `wolframscript` must be installed on the host and available on the `PATH`.
- Python 3.11 (managed automatically by [`uv`](https://docs.astral.sh/uv/)).

### Install Dependencies
```bash
uv sync
```

### Run the API
```bash
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The server boots on `http://127.0.0.1:8000` by default. Executions are stored under `${TMPDIR}/wolframscript-executions` unless `WLS_EXECUTIONS_DIR` is set.

### Execute a Script
```bash
curl -X POST \
  -F "file=@path/to/script.wls" \
  -F "nickname=my-run-name" \
  -F "nickname_mode=unique" \
  "http://127.0.0.1:8000/run?timeout=60"
```

The response contains the script's exit code, stdout, stderr, runtime, an optional `nickname`, a unique `execution_id`, and the artifacts created in that run. Set `nickname_mode=replace` to supersede an existing execution that already uses the nickname (history is retained).

### List Executions
```bash
curl "http://127.0.0.1:8000/executions"
```

### List Artifacts
```bash
curl "http://127.0.0.1:8000/executions/<execution_id>"
```

### Download an Artifact
```bash
curl -O \
  "http://127.0.0.1:8000/executions/<execution_id>/artifacts/path/to/file"
```

Each execution directory stores its own `metadata.json`, ensuring execution history persists across server restarts.

### Delete an Execution
```bash
curl -X DELETE "http://127.0.0.1:8000/executions/<execution_id>"
```

### Configuration

| Environment variable | Purpose |
| --- | --- |
| `WLS_EXECUTIONS_DIR` | Override where execution folders are stored. Defaults to `${TMPDIR}/wolframscript-executions`. |
| `WLS_EXECUTION_LOG` | Path to a newline-delimited JSON log that captures each execution and deletion event. |
| `WLS_ALLOWLIST_PATTERNS` | Comma-separated regex patterns that uploaded scripts must match (case-insensitive). |
| `WLS_DENYLIST_PATTERNS` | Comma-separated regex patterns that, if matched, reject an uploaded script. |
| `WLS_CPU_LIMIT_SECONDS` | CPU time limit enforced via `ulimit`/`RLIMIT_CPU`. |
| `WLS_MEMORY_LIMIT_MB` | Memory ceiling (MB) enforced via `RLIMIT_AS`. |
| `WLS_RETENTION_SECONDS` | Automatically delete executions older than this age. |
| `WLS_MAX_EXECUTIONS` | Keep only the newest N executions (older ones are removed automatically). |
| `WLS_CLEANUP_INTERVAL_SECONDS` | Period for the background retention sweep. Defaults to 300 seconds. |

> **Warning:** Running arbitrary WolframScript files can be dangerous. Each execution is sandboxed via `sandbox-exec` on macOS, but you should still only run scripts from trusted sources.
