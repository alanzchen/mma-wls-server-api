# Using the WolframScript Runner API with an LLM

This document describes how to guide a language model agent to run Wolfram Language files safely through the WolframScript Runner API.

## Base Configuration

- **API Endpoint:** `<<INSERT_API_ENDPOINT>>`
- **Password:** `<<INSERT_API_PASSWORD>>`
  The password must be sent on every request via the `X-Runner-Password` header (preferred) or using the `Authorization: Bearer <password>` header.

Ensure the LLM has explicit instructions about these values before attempting any requests.

## API Endpoints Reference

### Execution Management

#### 1. Upload and Execute Script
- **Method:** `POST`
- **Path:** `/run`
- **Headers:**
  - `X-Runner-Password: <<INSERT_API_PASSWORD>>`
- **Multipart form fields:**
  - `file`: Wolfram Language file to execute (required) - supports `.wls`, `.wl`, `.m`, `.nb`, `.cdf`, `.mx`
  - `nickname`: user-friendly identifier (optional)
  - `nickname_mode`: `unique` (default) or `replace` (optional)
  - `assets`: repeatable field for supporting files (optional)
- **Query parameters:**
  - `timeout` (seconds) – defaults to 60, max 600

**Response:** JSON object with `execution_id`, `returncode`, `stdout`, `stderr`, timing, artifacts list.

#### 2. List All Executions
- **Method:** `GET`
- **Path:** `/executions`
- **Headers:** `X-Runner-Password`
- **Response:** `{ "executions": [...] }` with metadata for all executions

#### 3. Get Execution Metadata
- **Method:** `GET`
- **Path:** `/executions/{execution_id}`
- **Headers:** `X-Runner-Password`
- **Response:** Full execution metadata including artifacts, execution history, and status

#### 4. Delete Execution
- **Method:** `DELETE`
- **Path:** `/executions/{execution_id}`
- **Headers:** `X-Runner-Password`
- **Response:** 204 No Content on success

### File Operations

#### 5. List Files in Execution
- **Method:** `GET`
- **Path:** `/executions/{execution_id}/files`
- **Headers:** `X-Runner-Password`
- **Response:** JSON with list of files, each containing `path`, `size_bytes`, `mtime`, `is_metadata`

#### 6. Download File/Artifact
- **Method:** `GET`
- **Path:** `/executions/{execution_id}/artifacts/{file_path}`
- **Headers:** `X-Runner-Password`
- **Response:** File content as binary stream

#### 7. Upload/Update Single File
- **Method:** `PUT`
- **Path:** `/executions/{execution_id}/files/{file_path}`
- **Headers:** `X-Runner-Password`
- **Multipart form fields:**
  - `file`: file content to upload
- **Response:** JSON with `execution_id`, `path`, `size_bytes`, `mtime`

**Note:** Cannot upload to `metadata.json` - this is protected.

#### 8. Delete File
- **Method:** `DELETE`
- **Path:** `/executions/{execution_id}/files/{file_path}`
- **Headers:** `X-Runner-Password`
- **Response:** 204 No Content on success

**Note:** Cannot delete `metadata.json` - this is protected.

### Asset Operations

#### 9. Upload Additional Assets
- **Method:** `POST`
- **Path:** `/executions/{execution_id}/assets`
- **Headers:** `X-Runner-Password`
- **Multipart form fields:**
  - `assets`: repeatable field for files to stage under `assets/` directory
- **Response:** JSON with `execution_id`, merged `assets` list, refreshed `artifacts`

### Execution Operations

#### 10. Execute File in Execution Directory
- **Method:** `POST`
- **Path:** `/executions/{execution_id}/execute`
- **Headers:** `X-Runner-Password`
- **Form fields:**
  - `file_path`: path to Wolfram Language file within execution directory (required) - supports `.wls`, `.wl`, `.m`, `.nb`, `.cdf`, `.mx`
  - `timeout`: execution timeout in seconds (default: 60, max: 600)
- **Response:** JSON with `execution_id`, `file_path`, `returncode`, `elapsed_seconds`, `stdout`, `stderr`, `artifacts`

**Use case:** After uploading files via file operations, execute a script that processes them.

## Common Workflows

### Workflow 1: Quick Script Execution
1. Use **Upload and Execute** (endpoint 1) with your `.wls` file
2. Get `execution_id` from response
3. Use **Download Artifact** (endpoint 6) to retrieve output files

### Workflow 2: Iterative Development
1. Use **Upload and Execute** (endpoint 1) to create execution directory
2. Use **Upload File** (endpoint 7) to update script or add data files
3. Use **Execute File** (endpoint 10) to run the updated script
4. Use **List Files** (endpoint 5) to see what was generated
5. Use **Download File** (endpoint 6) to retrieve results
6. Repeat steps 2-5 as needed

### Workflow 3: Data Processing Pipeline
1. Use **Upload and Execute** (endpoint 1) with initial script and data
2. Use **Upload Assets** (endpoint 9) to add more data files
3. Use **Execute File** (endpoint 10) to run processing script
4. Use **List Files** (endpoint 5) to verify outputs
5. Use **Download File** (endpoint 6) to retrieve processed data

### Workflow 4: Execution Management
1. Use **List Executions** (endpoint 2) to see all executions
2. Use **Get Execution Metadata** (endpoint 3) to inspect specific execution
3. Use **Delete Execution** (endpoint 4) to clean up old executions

## CLI Tool for LLMs

A comprehensive CLI tool (`wls`) is available that wraps all API endpoints. LLMs can use this tool directly via shell commands or reference its implementation.

### CLI Installation

**Install from GitHub:**
```bash
uv pip install git+https://github.com/alanzchen/mma-wls-server-api.git
```

**Or use uvx without installing:**
```bash
uvx --from git+https://github.com/alanzchen/mma-wls-server-api.git wls <command>
```

### CLI Configuration

The CLI reads configuration from (in order of priority):
1. Command-line arguments (`--url`, `--password`)
2. Environment variables (`WLS_SERVER_URL`, `WLS_API_PASSWORD`)
3. `.env` file in current directory

### CLI Commands Reference

```bash
# Execution management
wls run script.wls --nickname "my-run" --asset data.csv
wls run script.wls -d /path/to/folder  # Upload folder, execute, download new files
wls list [--json]
wls info <execution_id> [--json]
wls delete <execution_id>

# File operations
wls files <execution_id> [--json]
wls get <execution_id> <file_path> [-o output.txt]
wls put <execution_id> <local_file> [remote_path]
wls rm <execution_id> <file_path>

# Asset operations
wls assets <execution_id> file1.csv file2.json

# Execution operations
wls exec <execution_id> <script.wls> [--timeout 120]

# Folder sync operations
wls sync <local_dir> <execution_id> [--execute script.wls]
wls upload <local_dir> <execution_id> [--delete] [--execute script.wls]
wls download <local_dir> <execution_id> [--delete]

# Help
wls help [command]
```

### Example CLI Workflows for LLMs

**Execute a script:**
```bash
wls run analysis.wls --asset data.csv --timeout 120
```

**Execute with folder sync:**
```bash
# Upload entire folder, execute script, and download any new files
wls run script.wls -d ./my-project --timeout 120
```

**Iterative development:**
```bash
# Create execution
wls run main.wls

# Update file and re-execute
wls put abc123 updated_main.wls main.wls
wls exec abc123 main.wls

# Get results
wls files abc123
wls get abc123 output/results.txt
```

**Folder synchronization:**
```bash
# Sync entire project and execute
wls sync ./my-project abc123 --execute main.wls

# Download results
wls download ./my-project abc123
```

## Safety & Policy Reminders for LLMs

- Only execute Wolfram Language files from trusted sources.
- Supported file types: `.wls`, `.wl`, `.m`, `.nb`, `.cdf`, `.mx`
- Do not attempt to bypass the sandbox or change system configuration.
- Respect the timeout and nickname policies returned by the API.
- Handle non-200 responses explicitly; report errors back to the user.
- Store execution IDs securely for follow-up operations.
- When using file operations, never attempt to modify or delete `metadata.json`.
- Verify file paths to prevent path traversal attacks.

## Example API Requests

### Upload and Execute with cURL

```bash
curl -X POST \
  -H "X-Runner-Password: <<INSERT_API_PASSWORD>>" \
  -F "file=@script.wls" \
  -F "assets=@data.csv" \
  -F "nickname=my-run" \
  "<<INSERT_API_ENDPOINT>>/run?timeout=120"
```

### List Files in Execution

```bash
curl -H "X-Runner-Password: <<INSERT_API_PASSWORD>>" \
  "<<INSERT_API_ENDPOINT>>/executions/abc123/files"
```

### Upload Single File

```bash
curl -X PUT \
  -H "X-Runner-Password: <<INSERT_API_PASSWORD>>" \
  -F "file=@newdata.csv" \
  "<<INSERT_API_ENDPOINT>>/executions/abc123/files/data/newdata.csv"
```

### Execute File in Execution

```bash
curl -X POST \
  -H "X-Runner-Password: <<INSERT_API_PASSWORD>>" \
  -F "file_path=main.wls" \
  -F "timeout=60" \
  "<<INSERT_API_ENDPOINT>>/executions/abc123/execute"
```

### Download Artifact

```bash
curl -H "X-Runner-Password: <<INSERT_API_PASSWORD>>" \
  "<<INSERT_API_ENDPOINT>>/executions/abc123/artifacts/output/result.txt" \
  -o result.txt
```

## Response Handling

All successful responses (except DELETE operations) return JSON. Common fields:

- `execution_id`: Unique identifier for the execution
- `returncode`: Exit code from script execution (0 = success)
- `stdout`, `stderr`: Standard output and error streams
- `elapsed_seconds`: Execution time
- `artifacts`: List of generated files with paths and sizes
- `files`: List of all files (for file listing endpoint)

DELETE operations return `204 No Content` on success.

Error responses include:
- `400 Bad Request`: Invalid input (check `detail` field)
- `401 Unauthorized`: Missing or invalid password
- `404 Not Found`: Execution or file not found
- `409 Conflict`: Nickname already exists (unique mode)
- `504 Gateway Timeout`: Script execution timeout

Replace the placeholders (`<<INSERT_API_ENDPOINT>>`, `<<INSERT_API_PASSWORD>>`) with real values when deploying. This template can be embedded in agent system prompts or tool documentation to ensure LLMs interact with the WolframScript Runner consistently and securely.
