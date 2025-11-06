# Using the WolframScript Runner API with an LLM

This document describes how to guide a language model agent to run WolframScript files safely through the WolframScript Runner API.

## Base Configuration

- **API Endpoint:** `<<INSERT_API_ENDPOINT>>`
- **Password:** `<<INSERT_API_PASSWORD>>`  
  The password must be sent on every request via the `X-Runner-Password` header (preferred) or using the `Authorization: Bearer <password>` header.

Ensure the LLM has explicit instructions about these values before attempting any requests.

## Request Workflow

1. **Upload and Execute**
   - Method: `POST`
   - Path: `/run`
   - Headers:
     - `X-Runner-Password: <<INSERT_API_PASSWORD>>`
   - Multipart form fields:
     - `file`: the `.wls` WolframScript to execute.
     - Optional `nickname`: user-friendly identifier.
     - Optional `nickname_mode`: `unique` (default) or `replace`.
     - Optional `assets`: repeatable field for any supporting files the script needs (e.g., data tables, configs). Each asset is stored under `assets/` in the execution directory.
   - Query parameters:
     - `timeout` (seconds) – defaults to 60.

   On success, the response is a JSON object containing:
   - `execution_id` (string) – store this for follow-up requests.
   - `returncode`, `stdout`, `stderr`
   - Timing, nickname info, and artifact metadata.

2. **List Executions**
   - Method: `GET`
   - Path: `/executions`
   - Use the same password header.
   - Response: `{ "executions": [...] }`

3. **Get Execution Metadata**
   - Method: `GET`
   - Path: `/executions/{execution_id}`
   - Use the same password header.

4. **Download Artifacts**
   - Method: `GET`
   - Path: `/executions/{execution_id}/artifacts/{artifact_path}`
   - Use the password header and stream/save the response body.

5. **Upload Additional Assets**
   - Method: `POST`
   - Path: `/executions/{execution_id}/assets`
   - Headers: include the password.
   - Multipart form field `assets` (repeatable) for new files to stage under `assets/`.
   - Response returns the full asset list and refreshed artifacts.

6. **Delete Executions**
   - Method: `DELETE`
   - Path: `/executions/{execution_id}`
   - Use the password header.

## Safety & Policy Reminders for LLMs

- Only execute WolframScripts from trusted sources.
- Do not attempt to bypass the sandbox or change system configuration.
- Respect the timeout and nickname policies returned by the API.
- Handle non-200 responses explicitly; report errors back to the user.
- Store execution IDs securely for follow-up operations.

## Example cURL Upload (for reference)

```bash
curl -X POST \
  -H "X-Runner-Password: <<INSERT_API_PASSWORD>>" \
  -F "file=@path/to/script.wls" \
  -F "assets=@path/to/data.csv" \
  -F "nickname=my-run" \
  "<<INSERT_API_ENDPOINT>>/run"
```

Replace the placeholders with real values when deploying. This template can be embedded in agent system prompts or tool documentation to ensure LLMs interact with the WolframScript Runner consistently and securely.
