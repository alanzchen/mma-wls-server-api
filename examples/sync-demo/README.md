# Folder Sync Demo

This example demonstrates how to use the bidirectional folder sync feature.

## Files

- `main.wls` - Main WolframScript that lists files and processes data
- `data/input.txt` - Sample input data file

## Usage

### 1. Start the server

```bash
cd ../..
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 2. Create an execution directory

You have two options:

**Option A: Create via initial run**
```bash
curl -X POST \
  -F "file=@examples/sync-demo/main.wls" \
  -F "nickname=sync-demo" \
  -F "nickname_mode=replace" \
  "http://127.0.0.1:8000/run?timeout=60"
```

Save the `execution_id` from the response.

**Option B: Use the sync CLI to upload first**

Get an execution ID from a previous run or create a new one, then sync:

```bash
../../wls_sync.py upload . <execution_id> --verbose
```

### 3. Sync and execute

**Upload local changes and execute:**
```bash
../../wls_sync.py upload . <execution_id> --execute main.wls --verbose
```

**Download outputs after execution:**
```bash
../../wls_sync.py download . <execution_id> --verbose
```

You should now see an `output/result.txt` file in your local directory!

**Bidirectional sync:**
```bash
../../wls_sync.py sync . <execution_id> --verbose
```

### 4. Modify and re-sync

Try modifying `data/input.txt` locally, then run:

```bash
../../wls_sync.py upload . <execution_id> --execute main.wls --verbose
../../wls_sync.py download . <execution_id> --verbose
```

The new data will be uploaded, the script will run with the new data, and outputs will be downloaded.

## How it works

1. The CLI scans the local directory and compares files with the server
2. Files are uploaded/downloaded based on modification time and size
3. After syncing, the specified script is executed on the server
4. Generated output files can be synced back to your local machine
