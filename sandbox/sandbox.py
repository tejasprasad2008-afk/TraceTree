import os
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

def run_sandbox(package_name: str) -> str:
    """
    Executes the package installation inside an isolated Docker container,
    with network dynamically detached before actual installation triggers.
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
    
    # 1. Download
    # 2. Drop Network via ip link
    # 3. Strace Install targeting the offline wheels
    sandbox_script = f"""
pip download {package_name} --dest /tmp/pkg > /dev/null 2>&1
ip link set eth0 down
strace -f -e trace=all -yy -s 1000 -o {log_file_in_container} pip install --no-index --find-links /tmp/pkg {package_name} > /dev/null 2>&1
"""

    container = None
    try:
        container = client.containers.run(
            image=image_tag,
            command=["/bin/bash", "-c", sandbox_script],
            detach=True,
            remove=False,
            cap_add=["NET_ADMIN"],
        )

        timeout = 60
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
            log_file_path = log_dir / f"{package_name}_strace.log"

            with tarfile.open(temp_tar.name) as tar:
                member = tar.getmembers()[0]
                extracted_f = tar.extractfile(member)
                if extracted_f:
                    with open(log_file_path, "wb") as out_f:
                        out_f.write(extracted_f.read())
            
            os.remove(temp_tar.name)
            return str(log_file_path)

        except docker.errors.NotFound:
            console.print(f"\n[yellow]Warning:[/] No strace log was written for {package_name}.")
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
