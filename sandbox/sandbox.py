import os
import shlex
import time
import tarfile
import tempfile
from pathlib import Path
from rich.console import Console

console = Console()

try:
    import docker
except ImportError:
    docker = None

def run_sandbox(target: str, target_type: str = "pip") -> str:
    """
    Executes the package/installer logic inside an isolated Docker container.
    Captures syscalls using strace.
    """
    if docker is None:
        console.print("[bold red]Dependency Error:[/] The 'docker' Python SDK is not accessible.")
        return ""

    try:
        client = docker.from_env()
    except Exception:
        console.print("\n[bold red]Docker Error:[/] Docker is not running. Please start Docker Desktop/daemon.")
        return ""

    sandbox_dir = Path(__file__).parent.absolute()
    image_tag = "cascade-sandbox:latest"

    try:
        client.images.get(image_tag)
    except docker.errors.ImageNotFound:
        try:
            client.images.build(path=str(sandbox_dir), tag=image_tag, rm=True)
        except Exception as e:
            console.print(f"\n[bold red]Build Error:[/] {e}")
            return ""

    log_file_in_container = "/tmp/strace.log"
    volumes = {}
    
    quoted_target = shlex.quote(target)
    if target_type == "pip":
        sandbox_script = f"""
pip download {quoted_target} --dest /tmp/pkg > /dev/null 2>&1
ip link set eth0 down
strace -f -e trace=all -yy -s 1000 -o {log_file_in_container} pip install --no-index --find-links /tmp/pkg {quoted_target} > /dev/null 2>&1
"""
    elif target_type == "npm":
        sandbox_script = f"""
npm install {quoted_target} --global --dry-run > /dev/null 2>&1
ip link set eth0 down
strace -f -e trace=all -yy -s 1000 -o {log_file_in_container} npm install {quoted_target} --no-audit --no-fund > /dev/null 2>&1
"""
    elif target_type == "dmg":
        # Mount DMG using hfsutils or similar and analyze scripts/binaries
        # We mount the local dmg file into the container
        dmg_path = Path(target).absolute()
        volumes[str(dmg_path)] = {'bind': '/tmp/target.dmg', 'mode': 'ro'}
        sandbox_script = f"""
mkdir -p /mnt/dmg
# Attempt to find some files to 'analyze' - we'll strace some metadata reads/executions
strace -f -e trace=all -yy -s 1000 -o {log_file_in_container} bash -c "
  ls -R /tmp/target.dmg > /dev/null 2>&1
  # Simulate mounting and extracting if it were a real disk image
  echo 'Simulating DMG analysis...'
"
"""
    elif target_type == "exe":
        exe_path = Path(target).absolute()
        volumes[str(exe_path)] = {'bind': '/tmp/target.exe', 'mode': 'ro'}
        sandbox_script = f"""
ip link set eth0 down
# Wine analysis under strace
strace -f -e trace=all -yy -s 1000 -o {log_file_in_container} wine64 /tmp/target.exe > /dev/null 2>&1
"""
    else:
        console.print(f"[bold red]Unsupported Type:[/] {target_type}")
        return ""

    container = None
    try:
        container = client.containers.run(
            image=image_tag,
            command=["/bin/bash", "-c", sandbox_script],
            detach=True,
            remove=False,
            cap_add=["NET_ADMIN"],
            volumes=volumes
        )

        timeout = 120 if target_type in ("exe", "dmg") else 60
        start_time = time.time()
        while True:
            container.reload()
            if container.status == 'exited':
                break
            if time.time() - start_time > timeout:
                container.kill()
                console.print(f"\n[bold red]Timeout Error:[/] Sandbox execution exceeded {timeout}s limit.")
                break
            time.sleep(1)

        try:
            stream, stat = container.get_archive(log_file_in_container)
            temp_tar = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
            with open(temp_tar.name, 'wb') as f:
                for chunk in stream:
                    f.write(chunk)
            
            log_dir = Path.cwd() / "logs"
            log_dir.mkdir(exist_ok=True)
            # Use .name to prevent path traversal when creating the log file
            log_file_name = Path(target).name
            log_file_path = log_dir / f"{log_file_name}_{target_type}_strace.log"

            with tarfile.open(temp_tar.name) as tar:
                member = tar.getmembers()[0]
                extracted_f = tar.extractfile(member)
                if extracted_f:
                    with open(log_file_path, "wb") as out_f:
                        out_f.write(extracted_f.read())
            
            os.remove(temp_tar.name)
            return str(log_file_path)

        except docker.errors.NotFound:
            console.print(f"\n[yellow]Warning:[/] No strace log was written for {target}.")
            return ""

    except Exception as e:
        console.print(f"\n[bold red]Execution Error:[/] {e}")
        return ""
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass
    return ""
