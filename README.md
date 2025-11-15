## WolframScript Web Runner

This service exposes a small FastAPI server that accepts uploaded Wolfram Language files (`.wls`, `.wl`, `.m`, `.nb`, etc.), executes them with the `wolframscript` CLI, and returns the captured standard output, standard error, and exit code.

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
  -F "assets=@path/to/data.csv" \
  -F "assets=@path/to/config.json" \
  -H "X-Runner-Password: change-me" \
  "http://127.0.0.1:8000/run?timeout=60"
```

The response contains the script's exit code, stdout, stderr, runtime, an optional `nickname`, a unique `execution_id`, the list of staged asset paths, and the artifacts created in that run. Set `nickname_mode=replace` to supersede an existing execution that already uses the nickname (history is retained). When `WLS_API_PASSWORD` is configured, every request must include the password via the `X-Runner-Password` header (or an `Authorization: Bearer` token).

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

### Upload Additional Assets to an Existing Execution
```bash
curl -X POST \
  -H "X-Runner-Password: change-me" \
  -F "assets=@path/to/new-data.parquet" \
  -F "assets=@path/to/more-config.json" \
  "http://127.0.0.1:8000/executions/<execution_id>/assets"
```

The response lists the merged asset inventory and updated artifacts, letting you stage supporting files after the initial run.

Each execution directory stores its own `metadata.json`, ensuring execution history persists across server restarts.

### Folder Sync Operations

#### List All Files in an Execution
```bash
curl "http://127.0.0.1:8000/executions/<execution_id>/files"
```

Returns a list of all files in the execution directory with metadata (path, size, mtime).

#### Upload/Update a Single File
```bash
curl -X PUT \
  -H "X-Runner-Password: change-me" \
  -F "file=@path/to/local/file.txt" \
  "http://127.0.0.1:8000/executions/<execution_id>/files/path/in/execution/file.txt"
```

Uploads or updates a file at the specified path within the execution directory.

#### Delete a File
```bash
curl -X DELETE \
  -H "X-Runner-Password: change-me" \
  "http://127.0.0.1:8000/executions/<execution_id>/files/path/to/file.txt"
```

Deletes a specific file from the execution directory.

#### Execute a File
```bash
curl -X POST \
  -H "X-Runner-Password: change-me" \
  -F "file_path=script.wls" \
  -F "timeout=60" \
  "http://127.0.0.1:8000/executions/<execution_id>/execute"
```

Executes a Wolfram Language file that exists within the execution directory. The execution results are stored in the metadata's `execution_history` and `last_execution` fields.

**Supported file types:** `.wls`, `.wl`, `.m`, `.nb`, `.cdf`, `.mx`

### Comprehensive CLI Tool

A full-featured command-line utility `wls` provides access to all API operations.

#### Installation

**Install from GitHub with uv (recommended):**
```bash
# Install the package and CLI tool
uv pip install git+https://github.com/alanzchen/mma-wls-server-api.git

# Or use uvx to run without installing
uvx --from git+https://github.com/alanzchen/mma-wls-server-api.git wls --help
```

**Install locally for development:**
```bash
# Clone the repository
git clone https://github.com/alanzchen/mma-wls-server-api.git
cd mma-wls-server-api

# Install in development mode
uv pip install -e .

# The 'wls' command is now available
wls --help
```

**Install with pip:**
```bash
pip install git+https://github.com/alanzchen/mma-wls-server-api.git
```

#### Configuration

The CLI can be configured in three ways (in order of priority):

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **.env file** (lowest priority)

Create a `.env` file in your project directory:
```bash
# Copy the example file
cp .env.example .env

# Edit with your values
WLS_SERVER_URL=http://localhost:8000
WLS_API_PASSWORD=your-secret-password
```

Configuration variables:
- `WLS_SERVER_URL`: Server base URL (default: `http://localhost:8000`)
- `WLS_API_PASSWORD`: API password for authentication (default: none)

#### Quick Start

```bash
# Execute a script
wls run script.wls --asset data.csv

# List all executions
wls list

# Get execution details
wls info <execution_id>

# List files in execution
wls files <execution_id>

# Download a file
wls get <execution_id> output/result.txt

# Upload a file
wls put <execution_id> newdata.csv data/newdata.csv

# Execute a file already in the execution
wls exec <execution_id> main.wls

# Sync entire folder
wls sync ./my-project <execution_id>

# Get help
wls help
wls help run
```

#### All Available Commands

**Execution Management:**
- `wls run <script.wls>` - Upload and execute a script
- `wls list` - List all executions
- `wls info <execution_id>` - Get execution metadata
- `wls delete <execution_id>` - Delete an execution

**File Operations:**
- `wls files <execution_id>` - List files in execution
- `wls get <execution_id> <file_path>` - Download a file
- `wls put <execution_id> <local> [remote]` - Upload a file
- `wls rm <execution_id> <file_path>` - Delete a file

**Asset Operations:**
- `wls assets <execution_id> <files...>` - Upload additional assets

**Execution Operations:**
- `wls exec <execution_id> <script.wls>` - Execute file in execution

**Folder Sync:**
- `wls sync <dir> <execution_id>` - Bidirectional sync
- `wls upload <dir> <execution_id>` - Upload folder
- `wls download <dir> <execution_id>` - Download folder

**Help:**
- `wls help` - Show general help
- `wls help <command>` - Show help for specific command

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
| `WLS_API_PASSWORD` | If set, requires callers to authenticate using `X-Runner-Password` or `Authorization: Bearer`/Basic headers. |

> **Warning:** Running arbitrary WolframScript files can be dangerous. Each execution is sandboxed via `sandbox-exec` on macOS, but you should still only run scripts from trusted sources.
