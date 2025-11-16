#!/usr/bin/env python3
"""
WolframScript Server CLI

A comprehensive command-line utility for interacting with the WolframScript Server API.
Supports execution management, file operations, asset uploads, and folder synchronization.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
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


class WLSClient:
    """Client for interacting with WolframScript Server API."""

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

    # === Execution Management ===

    def run_script(
        self,
        script_path: Path,
        timeout: float = 60.0,
        nickname: str | None = None,
        nickname_mode: str = "unique",
        assets: list[Path] | None = None,
        assets_base_dir: Path | None = None,
        directory_zip_path: Path | None = None,
    ) -> dict[str, Any]:
        """Upload and execute a WolframScript file.

        Args:
            script_path: Path to the main script to execute
            timeout: Execution timeout in seconds
            nickname: Optional nickname for the execution
            nickname_mode: Nickname conflict policy ("unique" or "replace")
            assets: List of asset files to upload
            assets_base_dir: Base directory for computing relative paths of assets.
                           If provided, assets will preserve their directory structure
                           relative to this base directory.
            directory_zip_path: Path to a zip file containing the entire directory.
                              If provided, the server will extract it before execution.
        """
        self.log(f"Uploading and executing {script_path}...")

        # Prepare files for multipart upload. Use a list of tuples to support multiple assets.
        upload_files = [("file", (script_path.name, script_path.read_bytes()))]

        # Handle directory zip file
        if directory_zip_path:
            self.log(f"Uploading directory archive: {directory_zip_path}")
            upload_files.append(("directory_archive", ("directory.zip", directory_zip_path.read_bytes())))
        elif assets:
            # Handle individual assets
            for asset_path in assets:
                # Compute relative path if base directory is provided
                if assets_base_dir:
                    rel_path = asset_path.relative_to(assets_base_dir).as_posix()
                    upload_files.append(("assets", (rel_path, asset_path.read_bytes())))
                else:
                    upload_files.append(("assets", (asset_path.name, asset_path.read_bytes())))

        data = {}
        if nickname:
            data["nickname"] = nickname
            data["nickname_mode"] = nickname_mode

        response = self.session.post(
            self._url(f"/run?timeout={timeout}"),
            files=upload_files,
            data=data,
        )
        response.raise_for_status()
        return response.json()

    def list_executions(self) -> dict[str, Any]:
        """List all executions."""
        self.log("Fetching execution list...")
        response = self.session.get(self._url("/executions"))
        response.raise_for_status()
        return response.json()

    def get_execution(self, execution_id: str) -> dict[str, Any]:
        """Get metadata for a specific execution."""
        self.log(f"Fetching execution {execution_id}...")
        response = self.session.get(self._url(f"/executions/{execution_id}"))
        response.raise_for_status()
        return response.json()

    def delete_execution(self, execution_id: str) -> None:
        """Delete an execution."""
        self.log(f"Deleting execution {execution_id}...")
        response = self.session.delete(self._url(f"/executions/{execution_id}"))
        response.raise_for_status()

    # === File Operations ===

    def list_files(self, execution_id: str) -> dict[str, Any]:
        """List all files in an execution directory."""
        self.log(f"Listing files for execution {execution_id}...")
        response = self.session.get(self._url(f"/executions/{execution_id}/files"))
        response.raise_for_status()
        return response.json()

    def list_remote_files(self, execution_id: str) -> dict[str, FileEntry]:
        """List all files in the remote execution directory."""
        self.log(f"Fetching remote file list for execution {execution_id}...")
        response = self.session.get(self._url(f"/executions/{execution_id}/files"))
        response.raise_for_status()
        data = response.json()

        files = {}
        for file_info in data["files"]:
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

    def upload_file(self, execution_id: str, file_path: str, content: bytes) -> dict[str, Any]:
        """Upload a file to the remote execution directory."""
        self.log(f"  Uploading: {file_path}")
        response = self.session.put(
            self._url(f"/executions/{execution_id}/files/{file_path}"),
            files={"file": (Path(file_path).name, content)},
        )
        response.raise_for_status()
        return response.json()

    def download_file(self, execution_id: str, file_path: str) -> bytes:
        """Download a file from the remote execution directory."""
        self.log(f"  Downloading: {file_path}")
        response = self.session.get(
            self._url(f"/executions/{execution_id}/artifacts/{file_path}")
        )
        response.raise_for_status()
        return response.content

    def delete_file(self, execution_id: str, file_path: str) -> None:
        """Delete a file from the remote execution directory."""
        self.log(f"  Deleting: {file_path}")
        response = self.session.delete(
            self._url(f"/executions/{execution_id}/files/{file_path}")
        )
        response.raise_for_status()

    # === Asset Operations ===

    def upload_assets(self, execution_id: str, asset_paths: list[Path]) -> dict[str, Any]:
        """Upload additional assets to an execution."""
        self.log(f"Uploading {len(asset_paths)} asset(s)...")
        files = [("assets", (path.name, path.read_bytes())) for path in asset_paths]
        response = self.session.post(
            self._url(f"/executions/{execution_id}/assets"),
            files=files,
        )
        response.raise_for_status()
        return response.json()

    # === Execution Operations ===

    def execute_file(
        self, execution_id: str, file_path: str, timeout: float = 60.0
    ) -> dict[str, Any]:
        """Execute a Wolfram Language file on the server."""
        self.log(f"Executing: {file_path}")
        response = self.session.post(
            self._url(f"/executions/{execution_id}/execute"),
            data={"file_path": file_path, "timeout": timeout},
        )
        response.raise_for_status()
        return response.json()

    # === Sync Operations ===

    def sync_upload(
        self, local_dir: Path, execution_id: str, delete_remote: bool = False
    ) -> None:
        """Upload local files to remote execution directory."""
        local_files = self.list_local_files(local_dir)
        remote_files = self.list_remote_files(execution_id)

        upload_count = 0
        delete_count = 0

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

        if delete_remote:
            for path in remote_files:
                if path not in local_files:
                    self.delete_file(execution_id, path)
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
                os.utime(target_path, (remote_file.mtime, remote_file.mtime))
                download_count += 1

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
                self.log(f"Remote only: {path}")
                content = self.download_file(execution_id, path)
                target_path = local_dir / path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_bytes(content)
                os.utime(target_path, (remote_file.mtime, remote_file.mtime))
                download_count += 1

            elif remote_file is None:
                self.log(f"Local only: {path}")
                content = (local_dir / path).read_bytes()
                self.upload_file(execution_id, path, content)
                upload_count += 1

            else:
                if local_file.size_bytes != remote_file.size_bytes or abs(
                    local_file.mtime - remote_file.mtime
                ) > 1.0:
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


def format_json(data: dict | list) -> str:
    """Format JSON data for pretty printing."""
    return json.dumps(data, indent=2, sort_keys=True)


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="wls",
        description="WolframScript Server CLI - Manage executions, files, and sync operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global options
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
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # === run command ===
    run_parser = subparsers.add_parser("run", help="Upload and execute a Wolfram Language file")
    run_parser.add_argument("script", type=Path, help="Path to Wolfram Language file (.wls, .wl, .m, etc.)")
    run_parser.add_argument("--timeout", type=float, default=60.0, help="Execution timeout in seconds (default: 60)")
    run_parser.add_argument("--nickname", help="Optional nickname for this execution")
    run_parser.add_argument("--nickname-mode", choices=["unique", "replace"], default="unique", help="Nickname conflict policy")
    run_parser.add_argument("--asset", dest="assets", action="append", type=Path, help="Asset file to upload (can be specified multiple times)")
    run_parser.add_argument("-d", "--directory", type=Path, help="Upload entire directory and download new files after execution")

    # === list command ===
    list_parser = subparsers.add_parser("list", help="List all executions")
    list_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    # === info command ===
    info_parser = subparsers.add_parser("info", help="Get execution metadata")
    info_parser.add_argument("execution_id", help="Execution ID")
    info_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    # === delete command ===
    delete_parser = subparsers.add_parser("delete", help="Delete an execution")
    delete_parser.add_argument("execution_id", help="Execution ID")

    # === files command ===
    files_parser = subparsers.add_parser("files", help="List files in an execution")
    files_parser.add_argument("execution_id", help="Execution ID")
    files_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    # === get command ===
    get_parser = subparsers.add_parser("get", help="Download a file from an execution")
    get_parser.add_argument("execution_id", help="Execution ID")
    get_parser.add_argument("file_path", help="Path to file within execution")
    get_parser.add_argument("-o", "--output", type=Path, help="Output file path (default: same as remote filename)")

    # === put command ===
    put_parser = subparsers.add_parser("put", help="Upload a file to an execution")
    put_parser.add_argument("execution_id", help="Execution ID")
    put_parser.add_argument("local_path", type=Path, help="Local file to upload")
    put_parser.add_argument("remote_path", nargs="?", help="Remote path (default: same as local filename)")

    # === rm command ===
    rm_parser = subparsers.add_parser("rm", help="Delete a file from an execution")
    rm_parser.add_argument("execution_id", help="Execution ID")
    rm_parser.add_argument("file_path", help="Path to file within execution")

    # === assets command ===
    assets_parser = subparsers.add_parser("assets", help="Upload additional assets to an execution")
    assets_parser.add_argument("execution_id", help="Execution ID")
    assets_parser.add_argument("files", nargs="+", type=Path, help="Asset files to upload")

    # === execute command ===
    execute_parser = subparsers.add_parser("exec", help="Execute a Wolfram Language file in an existing execution")
    execute_parser.add_argument("execution_id", help="Execution ID")
    execute_parser.add_argument("file_path", help="Path to Wolfram Language file within execution")
    execute_parser.add_argument("--timeout", type=float, default=60.0, help="Execution timeout in seconds (default: 60)")

    # === sync commands ===
    sync_parser = subparsers.add_parser("sync", help="Bidirectional folder sync (newest wins)")
    sync_parser.add_argument("local_dir", type=Path, help="Local directory to sync")
    sync_parser.add_argument("execution_id", help="Execution ID")
    sync_parser.add_argument("--execute", metavar="FILE", help="Execute this Wolfram file after syncing")
    sync_parser.add_argument("--timeout", type=float, default=60.0, help="Execution timeout in seconds (default: 60)")

    upload_parser = subparsers.add_parser("upload", help="Upload local folder to server")
    upload_parser.add_argument("local_dir", type=Path, help="Local directory to upload")
    upload_parser.add_argument("execution_id", help="Execution ID")
    upload_parser.add_argument("--delete", action="store_true", help="Delete remote files not in local")
    upload_parser.add_argument("--execute", metavar="FILE", help="Execute this Wolfram file after uploading")
    upload_parser.add_argument("--timeout", type=float, default=60.0, help="Execution timeout in seconds (default: 60)")

    download_parser = subparsers.add_parser("download", help="Download server folder to local")
    download_parser.add_argument("local_dir", type=Path, help="Local directory to download to")
    download_parser.add_argument("execution_id", help="Execution ID")
    download_parser.add_argument("--delete", action="store_true", help="Delete local files not on server")

    # === help command ===
    help_parser = subparsers.add_parser("help", help="Show help for a specific command")
    help_parser.add_argument("subcommand", nargs="?", help="Command to show help for")

    return parser


def main() -> None:
    """Main CLI entry point."""
    # Load environment variables from .env file if available
    if load_dotenv is not None:
        load_dotenv()

    parser = create_parser()
    args = parser.parse_args()

    # Handle help command
    if args.command == "help":
        if args.subcommand:
            parser.parse_args([args.subcommand, "--help"])
        else:
            parser.print_help()
        return

    # Show help if no command specified
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Create client
    client = WLSClient(args.url, args.password, args.verbose)

    try:
        # Execute commands
        if args.command == "run":
            if not args.script.exists():
                print(f"Error: Script file not found: {args.script}", file=sys.stderr)
                sys.exit(1)

            # Check for mutually exclusive options
            if args.directory and args.assets:
                print("Error: Cannot use both -d/--directory and --asset options together.", file=sys.stderr)
                print("Use -d for directory sync or --asset for individual files, but not both.", file=sys.stderr)
                sys.exit(1)

            # Prepare for directory or asset upload
            directory_zip_path = None
            temp_zip_file = None

            if args.directory:
                # Directory mode: create a zip file
                if not args.directory.exists():
                    print(f"Error: Directory not found: {args.directory}", file=sys.stderr)
                    sys.exit(1)
                if not args.directory.is_dir():
                    print(f"Error: Not a directory: {args.directory}", file=sys.stderr)
                    sys.exit(1)

                # Create a temporary zip file
                print(f"Creating archive of directory: {args.directory}")
                temp_zip_file = tempfile.NamedTemporaryFile(mode='wb', suffix='.zip', delete=False)
                try:
                    with zipfile.ZipFile(temp_zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        for file_path in args.directory.rglob("*"):
                            if file_path.is_file():
                                # Store with relative path to preserve directory structure
                                arcname = file_path.relative_to(args.directory)
                                zipf.write(file_path, arcname)
                                if client.verbose:
                                    print(f"  Added to archive: {arcname}")
                    directory_zip_path = Path(temp_zip_file.name)
                    print(f"Archive created: {directory_zip_path.stat().st_size} bytes")
                finally:
                    temp_zip_file.close()

            # Upload and execute script
            try:
                result = client.run_script(
                    args.script,
                    timeout=args.timeout,
                    nickname=args.nickname,
                    nickname_mode=args.nickname_mode,
                    assets=args.assets,
                    directory_zip_path=directory_zip_path,
                )
            finally:
                # Clean up temporary zip file
                if temp_zip_file:
                    try:
                        Path(temp_zip_file.name).unlink()
                    except Exception:
                        pass

            # Print execution results
            print(f"Execution ID: {result['execution_id']}")
            print(f"Return code: {result['returncode']}")
            print(f"Elapsed time: {result['elapsed_seconds']:.2f}s")
            if result.get("stdout"):
                print("\n--- STDOUT ---")
                print(result["stdout"])
            if result.get("stderr"):
                print("\n--- STDERR ---")
                print(result["stderr"])

            # Download any new files created during execution (directory sync mode only)
            if args.directory:
                print("\nDownloading new files...")
                client.sync_download(args.directory, result['execution_id'], delete_local=False)

        elif args.command == "list":
            result = client.list_executions()
            if args.json:
                print(format_json(result))
            else:
                executions = result.get("executions", [])
                print(f"Total executions: {len(executions)}\n")
                for exec in executions:
                    print(f"ID: {exec['execution_id']}")
                    if exec.get("nickname"):
                        print(f"  Nickname: {exec['nickname']}")
                    print(f"  Created: {exec.get('created_at', 'N/A')}")
                    print(f"  Status: {'Active' if exec.get('active', True) else 'Inactive'}")
                    if exec.get("returncode") is not None:
                        print(f"  Return code: {exec['returncode']}")
                    print()

        elif args.command == "info":
            result = client.get_execution(args.execution_id)
            if args.json:
                print(format_json(result))
            else:
                print(f"Execution ID: {result['execution_id']}")
                if result.get("nickname"):
                    print(f"Nickname: {result['nickname']}")
                print(f"Created: {result.get('created_at', 'N/A')}")
                print(f"Status: {'Active' if result.get('active', True) else 'Inactive'}")
                if result.get("returncode") is not None:
                    print(f"Return code: {result['returncode']}")
                    print(f"Elapsed: {result.get('elapsed_seconds', 0):.2f}s")
                print(f"\nArtifacts: {len(result.get('artifacts', []))}")
                for artifact in result.get("artifacts", []):
                    print(f"  - {artifact['path']} ({artifact['size_bytes']} bytes)")

        elif args.command == "delete":
            client.delete_execution(args.execution_id)
            print(f"Deleted execution: {args.execution_id}")

        elif args.command == "files":
            result = client.list_files(args.execution_id)
            if args.json:
                print(format_json(result))
            else:
                files = result.get("files", [])
                print(f"Total files: {len(files)}\n")
                for file in files:
                    print(f"{file['path']}")
                    print(f"  Size: {file['size_bytes']} bytes")
                    print(f"  Modified: {file['mtime']}")

        elif args.command == "get":
            content = client.download_file(args.execution_id, args.file_path)
            output_path = args.output or Path(args.file_path).name
            Path(output_path).write_bytes(content)
            print(f"Downloaded to: {output_path}")

        elif args.command == "put":
            if not args.local_path.exists():
                print(f"Error: File not found: {args.local_path}", file=sys.stderr)
                sys.exit(1)
            remote_path = args.remote_path or args.local_path.name
            content = args.local_path.read_bytes()
            result = client.upload_file(args.execution_id, remote_path, content)
            print(f"Uploaded: {result['path']} ({result['size_bytes']} bytes)")

        elif args.command == "rm":
            client.delete_file(args.execution_id, args.file_path)
            print(f"Deleted: {args.file_path}")

        elif args.command == "assets":
            for file_path in args.files:
                if not file_path.exists():
                    print(f"Error: File not found: {file_path}", file=sys.stderr)
                    sys.exit(1)
            result = client.upload_assets(args.execution_id, args.files)
            print(f"Uploaded {len(args.files)} asset(s)")
            print(f"Total assets: {len(result.get('assets', []))}")

        elif args.command == "exec":
            result = client.execute_file(args.execution_id, args.file_path, args.timeout)
            print(f"Execution completed")
            print(f"Return code: {result['returncode']}")
            print(f"Elapsed time: {result['elapsed_seconds']:.2f}s")
            if result.get("stdout"):
                print("\n--- STDOUT ---")
                print(result["stdout"])
            if result.get("stderr"):
                print("\n--- STDERR ---")
                print(result["stderr"])

        elif args.command == "sync":
            if not args.local_dir.exists():
                print(f"Error: Directory not found: {args.local_dir}", file=sys.stderr)
                sys.exit(1)
            client.sync_bidirectional(args.local_dir, args.execution_id)
            if args.execute:
                print(f"\nExecuting {args.execute}...")
                result = client.execute_file(args.execution_id, args.execute, args.timeout)
                print(f"Return code: {result['returncode']}")
                if result.get("stdout"):
                    print("\n--- STDOUT ---")
                    print(result["stdout"])

        elif args.command == "upload":
            if not args.local_dir.exists():
                print(f"Error: Directory not found: {args.local_dir}", file=sys.stderr)
                sys.exit(1)
            client.sync_upload(args.local_dir, args.execution_id, args.delete)
            if args.execute:
                print(f"\nExecuting {args.execute}...")
                result = client.execute_file(args.execution_id, args.execute, args.timeout)
                print(f"Return code: {result['returncode']}")
                if result.get("stdout"):
                    print("\n--- STDOUT ---")
                    print(result["stdout"])

        elif args.command == "download":
            if not args.local_dir.exists():
                args.local_dir.mkdir(parents=True)
            client.sync_download(args.local_dir, args.execution_id, args.delete)

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}", file=sys.stderr)
        if hasattr(e, "response") and e.response is not None:
            try:
                error_detail = e.response.json()
                print(f"Server response: {format_json(error_detail)}", file=sys.stderr)
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
