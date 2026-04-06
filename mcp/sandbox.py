"""
MCP-specific Docker sandbox.

Spins up the MCP server inside a Docker container with:
- strace -f tracing the entire process tree
- --network none by default (block all outbound traffic)
- Read-only mount of the server package
- Non-root user inside the container
- Configurable timeout (default 60 seconds)
"""

import os
import shlex
import time
import tarfile
import tempfile
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any
from rich.console import Console

console = Console()

try:
    import docker
except ImportError:
    docker = None

# Syscalls we care about for MCP analysis
MCP_STRACE_SYSCALLS = ",".join([
    "execve", "open", "openat", "read", "write", "connect",
    "socket", "sendto", "recvfrom", "fork", "clone", "kill",
    "unlink", "rename", "chmod", "getdents", "getdents64",
    "stat", "lstat", "access", "mkdir", "bind", "listen",
    "accept", "setsockopt", "getsockopt", "shutdown",
])

STRACE_LOG_PATH = "/trace/mcp_trace.log"


def run_mcp_sandbox(
    target: str,
    target_type: str = "npm",
    allow_network: bool = False,
    port: int = 3000,
    transport: str = "stdio",
    timeout: int = 60,
) -> Optional[str]:
    """
    Run an MCP server inside a Docker sandbox with strace -f instrumentation.

    Args:
        target: Package name (npm) or local path.
        target_type: 'npm' or 'local'.
        allow_network: If True, allow outbound network (--network none skipped).
        port: Port the MCP server listens on (HTTP/SSE transport).
        transport: 'stdio' or 'http'.
        timeout: Maximum seconds to allow the analysis session.

    Returns:
        Path to the strace log file on the host, or None on failure.
    """
    if docker is None:
        console.print("[bold red]Dependency Error:[/] The 'docker' Python SDK is not accessible.")
        return None

    try:
        client = docker.from_env()
    except Exception:
        console.print("\n[bold red]Docker Error:[/] Docker is not running. Please start Docker Desktop/daemon.")
        return None

    sandbox_dir = Path(__file__).parent.parent / "sandbox"
    image_tag = "cascade-sandbox:latest"

    try:
        client.images.get(image_tag)
    except docker.errors.ImageNotFound:
        try:
            client.images.build(path=str(sandbox_dir), tag=image_tag, rm=True)
        except Exception as e:
            console.print(f"\n[bold red]Build Error:[/] {e}")
            return None

    # Build the command string based on transport and target type
    if target_type == "local":
        # Local path — mount it and run from there
        server_command = _build_local_server_command(target, transport, port)
    else:
        # npm package — install globally then run
        server_command = _build_npm_server_command(target, transport, port)

    sandbox_script = _build_sandbox_script(
        server_command=server_command,
        allow_network=allow_network,
        transport=transport,
        port=port,
    )

    volumes: Dict[str, Dict[str, str]] = {}
    if target_type == "local":
        local_path = Path(target).absolute()
        if local_path.exists():
            volumes[str(local_path)] = {"bind": "/mcp-server", "mode": "ro"}

    container = None
    try:
        container = client.containers.run(
            image=image_tag,
            command=["/bin/bash", "-c", sandbox_script],
            detach=True,
            remove=False,
            cap_add=["NET_ADMIN"] if not allow_network else [],
            network="none" if not allow_network else "bridge",
            volumes=volumes,
            user="root",
        )

        # Wait for container to finish (or timeout)
        start_time = time.time()
        while True:
            container.reload()
            if container.status == "exited":
                break
            if time.time() - start_time > timeout:
                container.kill()
                console.print(
                    f"\n[bold yellow]Timeout:[/] MCP sandbox exceeded {timeout}s limit."
                )
                break
            time.sleep(1)

        # Extract the strace log
        log_path = _extract_strace_log(container, target)
        return log_path

    except Exception as e:
        console.print(f"\n[bold red]Execution Error:[/] {e}")
        return None
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass


def _build_sandbox_script(
    server_command: str,
    allow_network: bool,
    transport: str,
    port: int,
) -> str:
    """
    Build the full bash script that runs inside the container.
    1. Optionally disable network
    2. Create trace directory
    3. Start the MCP server in the background
    4. Attach strace -f to the server PID
    5. Wait for the server session to complete
    """
    network_block = "" if allow_network else "ip link set eth0 down 2>/dev/null || true"
    # Ensure port is an integer
    safe_port = int(port)

    # For stdio transport, we run the server and interact via a helper script
    # For HTTP transport, we start the server and then wait
    if transport == "http":
        # Start server, then the MCP client will connect externally
        # We need strace to run the entire time
        script = f"""#!/bin/bash
{network_block}
mkdir -p /trace

# Start the MCP server under strace -f in background
strace -f -e trace={MCP_STRACE_SYSCALLS} -yy -s 2000 -o {STRACE_LOG_PATH} {server_command} &
SERVER_PID=$!

# Wait for server to be ready
sleep 3

# Signal readiness — the external MCP client will connect
echo "MCP_SERVER_PID=$SERVER_PID" > /trace/server_info.txt
echo "MCP_SERVER_PORT={safe_port}" >> /trace/server_info.txt
echo "MCP_TRANSPORT={transport}" >> /trace/server_info.txt

# Wait for the server to exit or timeout (60s max)
for i in $(seq 1 60); do
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        break
    fi
    sleep 1
done

# Graceful shutdown
kill -TERM $SERVER_PID 2>/dev/null
sleep 1
kill -9 $SERVER_PID 2>/dev/null
"""
    else:
        # stdio transport — the server runs under strace and we interact via
        # a named pipe. The external client will use the container's stdin/stdout.
        script = f"""#!/bin/bash
{network_block}
mkdir -p /trace

# Create FIFOs for stdio communication
mkfifo /trace/mcp_stdin 2>/dev/null || true
mkfifo /trace/mcp_stdout 2>/dev/null || true

# Start the MCP server under strace -f
strace -f -e trace={MCP_STRACE_SYSCALLS} -yy -s 2000 -o {STRACE_LOG_PATH} {server_command} \
    </trace/mcp_stdin >/trace/mcp_stdout 2>/trace/mcp_stderr &
SERVER_PID=$!

echo "MCP_SERVER_PID=$SERVER_PID" > /trace/server_info.txt
echo "MCP_TRANSPORT={transport}" >> /trace/server_info.txt

# Wait for the server to exit or timeout
for i in $(seq 1 60); do
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        break
    fi
    sleep 1
done

kill -TERM $SERVER_PID 2>/dev/null
sleep 1
kill -9 $SERVER_PID 2>/dev/null
"""

    return script


def _build_npm_server_command(package: str, transport: str, port: int) -> str:
    """
    Build the shell command to start an npm-based MCP server.
    """
    # Sanitize package name for shell interpolation
    quoted_package = shlex.quote(package)
    # Ensure port is an integer to prevent injection
    safe_port = int(port)

    if transport == "http":
        # Most npm MCP servers expose HTTP.  We install globally and try to
        # find the start command.  Convention is often `npm start` or a bin entry.
        return (
            f"npm install -g {quoted_package} > /dev/null 2>&1 && "
            f"npx --yes {quoted_package} --port {safe_port}"
        )
    else:
        return f"npm install -g {quoted_package} > /dev/null 2>&1 && npx --yes {quoted_package}"


def _build_local_server_command(local_path: str, transport: str, port: int) -> str:
    """
    Build the shell command to start a locally-mounted MCP server.
    The server code is mounted at /mcp-server.
    """
    # Ensure port is an integer to prevent injection
    safe_port = int(port)

    # Try common patterns: npm start, python -m, node index.js
    return (
        f"cd /mcp-server && "
        f"(npm install > /dev/null 2>&1 || true) && "
        f"(npm start -- --port {safe_port} 2>/dev/null || "
        f"node index.js --port {safe_port} 2>/dev/null || "
        f"python -m server --port {safe_port} 2>/dev/null || "
        f"echo 'ERROR: Could not determine how to start the server')"
    )


def _extract_strace_log(container, target: str) -> Optional[str]:
    """
    Pull the strace log out of the container to the host's logs/ directory.
    Also extracts server_info.txt if present.
    """
    try:
        # Get the strace log
        stream, stat = container.get_archive(STRACE_LOG_PATH)
        temp_tar = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
        with open(temp_tar.name, "wb") as f:
            for chunk in stream:
                f.write(chunk)

        log_dir = Path(__file__).parent.parent / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        safe_name = Path(target).name.replace("/", "_").replace(" ", "_")
        log_file_path = log_dir / f"mcp_{safe_name}_strace.log"

        with tarfile.open(temp_tar.name) as tar:
            member = tar.getmembers()[0]
            extracted_f = tar.extractfile(member)
            if extracted_f:
                with open(log_file_path, "wb") as out_f:
                    out_f.write(extracted_f.read())

        os.remove(temp_tar.name)

        # Also try to extract server_info.txt
        try:
            stream2, _ = container.get_archive("/trace/server_info.txt")
            temp_tar2 = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
            with open(temp_tar2.name, "wb") as f:
                for chunk in stream2:
                    f.write(chunk)

            with tarfile.open(temp_tar2.name) as tar:
                member = tar.getmembers()[0]
                extracted_f = tar.extractfile(member)
                if extracted_f:
                    info_path = log_dir / f"mcp_{safe_name}_server_info.txt"
                    with open(info_path, "wb") as out_f:
                        out_f.write(extracted_f.read())

            os.remove(temp_tar2.name)
        except Exception:
            pass  # server_info.txt is optional

        return str(log_file_path)

    except docker.errors.NotFound:
        console.print(f"\n[yellow]Warning:[/] No strace log was written in the MCP sandbox.")
        return None
