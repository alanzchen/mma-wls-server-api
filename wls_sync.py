#!/usr/bin/env python3
"""
WolframScript Execution Folder Sync CLI

A utility to bidirectionally sync folders with WolframScript execution directories on a server.
Supports upload, download, and bidirectional sync with optional execution of scripts after sync.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install it with: pip install requests")
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None  # type: ignore


@dataclass
class FileEntry:
    """Represents a file with its metadata."""

    path: str
    size_bytes: int
    mtime: float

    def __hash__(self) -> int:
        return hash(self.path)


class SyncClient:
    """Client for syncing folders with WolframScript execution directories."""

    def __init__(self, base_url: str, password: str | None = None, verbose: bool = False):
        self.base_url = base_url.rstrip("/")
        self.password = password
        self.verbose = verbose
        self.session = requests.Session()
        if password:
            self.session.headers["X-Runner-Password"] = password

    def log(self, message: str) -> None:
        """Print a message if verbose mode is enabled."""
        if self.verbose:
            print(message)

    def _url(self, path: str) -> str:
        """Construct a full URL from a relative path."""
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def list_remote_files(self, execution_id: str) -> dict[str, FileEntry]:
        """List all files in the remote execution directory."""
        self.log(f"Fetching remote file list for execution {execution_id}...")
        response = self.session.get(self._url(f"/executions/{execution_id}/files"))
        response.raise_for_status()
        data = response.json()

        files = {}
        for file_info in data["files"]:
            # Skip metadata file
            if file_info.get("is_metadata", False):
                continue
            files[file_info["path"]] = FileEntry(
                path=file_info["path"],
                size_bytes=file_info["size_bytes"],
                mtime=file_info["mtime"],
            )
        return files

    def list_local_files(self, local_dir: Path) -> dict[str, FileEntry]:
        """List all files in the local directory."""
        self.log(f"Scanning local directory: {local_dir}")
        files = {}
        for path in local_dir.rglob("*"):
            if path.is_file():
                rel_path = path.relative_to(local_dir).as_posix()
                stat = path.stat()
                files[rel_path] = FileEntry(
                    path=rel_path,
                    size_bytes=stat.st_size,
                    mtime=stat.st_mtime,
                )
        return files

    def upload_file(self, execution_id: str, file_path: str, content: bytes) -> None:
        """Upload a file to the remote execution directory."""
        self.log(f"  Uploading: {file_path}")
        response = self.session.put(
            self._url(f"/executions/{execution_id}/files/{file_path}"),
            files={"file": (Path(file_path).name, content)},
        )
        response.raise_for_status()

    def download_file(self, execution_id: str, file_path: str) -> bytes:
        """Download a file from the remote execution directory."""
        self.log(f"  Downloading: {file_path}")
        response = self.session.get(
            self._url(f"/executions/{execution_id}/artifacts/{file_path}")
        )
        response.raise_for_status()
        return response.content

    def delete_remote_file(self, execution_id: str, file_path: str) -> None:
        """Delete a file from the remote execution directory."""
        self.log(f"  Deleting remote: {file_path}")
        response = self.session.delete(
            self._url(f"/executions/{execution_id}/files/{file_path}")
        )
        response.raise_for_status()

    def execute_file(
        self, execution_id: str, file_path: str, timeout: float = 60.0
    ) -> dict:
        """Execute a .wls file on the server."""
        self.log(f"Executing: {file_path}")
        response = self.session.post(
            self._url(f"/executions/{execution_id}/execute"),
            data={"file_path": file_path, "timeout": timeout},
        )
        response.raise_for_status()
        return response.json()

    def sync_upload(
        self, local_dir: Path, execution_id: str, delete_remote: bool = False
    ) -> None:
        """Upload local files to remote execution directory."""
        local_files = self.list_local_files(local_dir)
        remote_files = self.list_remote_files(execution_id)

        upload_count = 0
        delete_count = 0

        # Upload new and modified files
        for path, local_file in local_files.items():
            remote_file = remote_files.get(path)
            needs_upload = False

            if remote_file is None:
                self.log(f"New file: {path}")
                needs_upload = True
            elif (
                local_file.size_bytes != remote_file.size_bytes
                or abs(local_file.mtime - remote_file.mtime) > 1.0
            ):
                self.log(f"Modified file: {path}")
                needs_upload = True

            if needs_upload:
                content = (local_dir / path).read_bytes()
                self.upload_file(execution_id, path, content)
                upload_count += 1

        # Delete remote files not present locally
        if delete_remote:
            for path in remote_files:
                if path not in local_files:
                    self.delete_remote_file(execution_id, path)
                    delete_count += 1

        print(
            f"Upload complete: {upload_count} uploaded"
            + (f", {delete_count} deleted" if delete_remote else "")
        )

    def sync_download(
        self, local_dir: Path, execution_id: str, delete_local: bool = False
    ) -> None:
        """Download files from remote execution directory to local."""
        local_files = self.list_local_files(local_dir)
        remote_files = self.list_remote_files(execution_id)

        download_count = 0
        delete_count = 0

        # Download new and modified files
        for path, remote_file in remote_files.items():
            local_file = local_files.get(path)
            needs_download = False

            if local_file is None:
                self.log(f"New file: {path}")
                needs_download = True
            elif (
                remote_file.size_bytes != local_file.size_bytes
                or abs(remote_file.mtime - local_file.mtime) > 1.0
            ):
                self.log(f"Modified file: {path}")
                needs_download = True

            if needs_download:
                content = self.download_file(execution_id, path)
                target_path = local_dir / path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_bytes(content)
                # Preserve modification time
                os.utime(target_path, (remote_file.mtime, remote_file.mtime))
                download_count += 1

        # Delete local files not present remotely
        if delete_local:
            for path in local_files:
                if path not in remote_files:
                    self.log(f"  Deleting local: {path}")
                    (local_dir / path).unlink()
                    delete_count += 1

        print(
            f"Download complete: {download_count} downloaded"
            + (f", {delete_count} deleted" if delete_local else "")
        )

    def sync_bidirectional(self, local_dir: Path, execution_id: str) -> None:
        """Bidirectionally sync local and remote directories (newest wins)."""
        local_files = self.list_local_files(local_dir)
        remote_files = self.list_remote_files(execution_id)

        upload_count = 0
        download_count = 0

        all_paths = set(local_files.keys()) | set(remote_files.keys())

        for path in sorted(all_paths):
            local_file = local_files.get(path)
            remote_file = remote_files.get(path)

            if local_file is None:
                # Only on remote, download
                self.log(f"Remote only: {path}")
                content = self.download_file(execution_id, path)
                target_path = local_dir / path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_bytes(content)
                os.utime(target_path, (remote_file.mtime, remote_file.mtime))
                download_count += 1

            elif remote_file is None:
                # Only local, upload
                self.log(f"Local only: {path}")
                content = (local_dir / path).read_bytes()
                self.upload_file(execution_id, path, content)
                upload_count += 1

            else:
                # Both exist, compare
                if local_file.size_bytes != remote_file.size_bytes or abs(
                    local_file.mtime - remote_file.mtime
                ) > 1.0:
                    # Newer wins
                    if local_file.mtime > remote_file.mtime:
                        self.log(f"Local newer: {path}")
                        content = (local_dir / path).read_bytes()
                        self.upload_file(execution_id, path, content)
                        upload_count += 1
                    else:
                        self.log(f"Remote newer: {path}")
                        content = self.download_file(execution_id, path)
                        target_path = local_dir / path
                        target_path.write_bytes(content)
                        os.utime(target_path, (remote_file.mtime, remote_file.mtime))
                        download_count += 1

        print(
            f"Bidirectional sync complete: {upload_count} uploaded, {download_count} downloaded"
        )


def main() -> None:
    """Main CLI entry point."""
    # Load environment variables from .env file if available
    if load_dotenv is not None:
        load_dotenv()

    parser = argparse.ArgumentParser(
        description="Sync folders with WolframScript execution directories.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Upload local folder to execution
  %(prog)s upload ./my-project abc123def456

  # Download from execution to local folder
  %(prog)s download ./my-project abc123def456

  # Bidirectional sync (newest wins)
  %(prog)s sync ./my-project abc123def456

  # Upload and then execute a script
  %(prog)s upload ./my-project abc123def456 --execute main.wls

  # Sync with custom server URL and password
  %(prog)s sync ./my-project abc123def456 \\
    --url http://localhost:8000 \\
    --password mypassword
        """,
    )

    parser.add_argument(
        "mode",
        choices=["upload", "download", "sync"],
        help="Sync mode: upload (local -> remote), download (remote -> local), or sync (bidirectional)",
    )
    parser.add_argument(
        "local_dir",
        type=Path,
        help="Local directory to sync",
    )
    parser.add_argument(
        "execution_id",
        help="Execution ID on the server",
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("WLS_SERVER_URL", "http://localhost:8000"),
        help="Server base URL (default: $WLS_SERVER_URL or http://localhost:8000)",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("WLS_API_PASSWORD"),
        help="API password (default: $WLS_API_PASSWORD)",
    )
    parser.add_argument(
        "--execute",
        metavar="FILE",
        help="Execute this .wls file after syncing to server (only for upload/sync modes)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Execution timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete files in destination that don't exist in source",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    # Validate local directory
    if not args.local_dir.exists():
        print(f"Error: Local directory does not exist: {args.local_dir}", file=sys.stderr)
        sys.exit(1)

    if not args.local_dir.is_dir():
        print(f"Error: Path is not a directory: {args.local_dir}", file=sys.stderr)
        sys.exit(1)

    # Validate execute option
    if args.execute and args.mode == "download":
        print("Error: --execute is not supported with download mode", file=sys.stderr)
        sys.exit(1)

    client = SyncClient(args.url, args.password, args.verbose)

    try:
        # Perform sync
        if args.mode == "upload":
            client.sync_upload(args.local_dir, args.execution_id, args.delete)
        elif args.mode == "download":
            client.sync_download(args.local_dir, args.execution_id, args.delete)
        elif args.mode == "sync":
            if args.delete:
                print(
                    "Warning: --delete is not supported in bidirectional sync mode",
                    file=sys.stderr,
                )
            client.sync_bidirectional(args.local_dir, args.execution_id)

        # Execute if requested
        if args.execute:
            print(f"\nExecuting {args.execute} on server...")
            result = client.execute_file(args.execution_id, args.execute, args.timeout)
            print(f"\nExecution completed with return code: {result['returncode']}")
            if result.get("stdout"):
                print("\n--- STDOUT ---")
                print(result["stdout"])
            if result.get("stderr"):
                print("\n--- STDERR ---")
                print(result["stderr"])
            print(f"\nElapsed time: {result['elapsed_seconds']:.2f}s")

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}", file=sys.stderr)
        if hasattr(e.response, "text"):
            try:
                error_detail = e.response.json()
                print(f"Server response: {json.dumps(error_detail, indent=2)}", file=sys.stderr)
            except Exception:
                print(f"Server response: {e.response.text}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
