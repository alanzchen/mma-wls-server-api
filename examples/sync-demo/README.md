# Folder Sync Demo

This example demonstrates how to use the bidirectional folder sync feature.

## Files

- `main.wls` - Main WolframScript that lists files and processes data
- `data/input.txt` - Sample input data file

## Setup

### 1. Install the CLI tool

**Install from GitHub:**
```bash
# From the repository root
cd ../..

# Install the package with the CLI tool
uv pip install -e .

# The 'wls' command is now available
wls --help
```

**Or use uvx without installing:**
```bash
uvx --from git+https://github.com/alanzchen/mma-wls-server-api.git wls --help
```

### 2. Configure the CLI (optional)

Create a `.env` file in the project root:
```bash
cp .env.example .env
```

Edit `.env` with your server settings:
```
WLS_SERVER_URL=http://localhost:8000
WLS_API_PASSWORD=your-password-if-needed
```

## Usage

### 1. Start the server

```bash
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 2. Create an execution and run script

**Option A: Using the CLI (recommended)**
```bash
# Run the script directly
wls run main.wls --nickname sync-demo --nickname-mode replace --asset data/input.txt

# Save the execution_id from output
```

**Option B: Using cURL**
```bash
curl -X POST \
  -F "file=@main.wls" \
  -F "nickname=sync-demo" \
  -F "nickname_mode=replace" \
  "http://127.0.0.1:8000/run?timeout=60"
```

### 3. Work with execution files

**List files:**
```bash
wls files <execution_id>
```

**Download a specific file:**
```bash
wls get <execution_id> output/result.txt
```

**Upload a new file:**
```bash
wls put <execution_id> data/input.txt
```

**Execute the script again:**
```bash
wls exec <execution_id> main.wls
```

### 4. Folder synchronization

**Upload entire folder and execute:**
```bash
wls upload . <execution_id> --execute main.wls --verbose
```

**Download outputs after execution:**
```bash
wls download . <execution_id> --verbose
```

You should now see an `output/result.txt` file in your local directory!

**Bidirectional sync (newest wins):**
```bash
wls sync . <execution_id> --verbose
```

### 5. Iterative development

Try modifying `data/input.txt` locally, then:

```bash
# Sync changes and execute
wls sync . <execution_id> --execute main.wls --verbose

# Download results
wls download . <execution_id>
```

The new data will be uploaded, the script will run with the new data, and outputs will be downloaded.

## How it works

1. The CLI scans the local directory and compares files with the server
2. Files are uploaded/downloaded based on modification time and size
3. After syncing, the specified script is executed on the server
4. Generated output files can be synced back to your local machine
