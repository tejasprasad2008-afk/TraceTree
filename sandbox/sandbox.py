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

# --------------------------------------------------------------------------- #
#  DMG extraction & analysis script (runs inside the container)
# --------------------------------------------------------------------------- #

_DMG_ANALYZE_SCRIPT = r"""
set -euo pipefail

LOG_FILE="/tmp/strace.log"
DST="/tmp/dmg_extracted"
INPUT="$1"

mkdir -p "$DST"

# Try 7z first (handles most DMG formats)
if 7z x "$INPUT" -o"$DST" -y > /dev/null 2>&1; then
    echo "[dmg] Extracted with 7z" >&2
elif 7z x "$INPUT" -o"$DST" -y > /dev/null 2>&1; then
    echo "[dmg] Extracted with 7z (alternate)" >&2
else
    echo "[dmg] ERROR: Could not extract DMG with 7z" >&2
    # Still produce a log so the pipeline doesn't crash
    echo "NO EXECUTABLES FOUND" > "$LOG_FILE"
    exit 0
fi

# Find executables to trace
EXECUTABLES=()
while IFS= read -r -d '' file; do
    EXECUTABLES+=("$file")
done < <(find "$DST" \( \
    -name "*.sh" -o -name "*.py" -o -name "*.command" -o \
    -name "*.pkg" -o -name "*.mpkg" -o \
    -name "*.app" -type d \
\) -print0 2>/dev/null)

# Also look for Mach-O binaries inside .app bundles
while IFS= read -r -d '' app_dir; do
    macos_dir="$app_dir/Contents/MacOS"
    if [ -d "$macos_dir" ]; then
        while IFS= read -r -d '' bin; do
            EXECUTABLES+=("$bin")
        done < <(find "$macos_dir" -type f -print0 2>/dev/null)
    fi
done < <(find "$DST" -name "*.app" -type d -print0 2>/dev/null)

# Also look for bare executable files (no extension) that have execute permission
while IFS= read -r -d '' file; do
    # Check if it's a Mach-O or ELF binary using file command
    if file "$file" | grep -qiE "executable|mach-o|elf"; then
        EXECUTABLES+=("$file")
    fi
done < <(find "$DST" -type f -perm /111 ! -name "*.sh" ! -name "*.py" ! -name "*.command" -print0 2>/dev/null)

if [ ${#EXECUTABLES[@]} -eq 0 ]; then
    echo "[dmg] No executables found in DMG" >&2
    echo "NO EXECUTABLES FOUND" > "$LOG_FILE"
    exit 0
fi

echo "[dmg] Found ${#EXECUTABLES[@]} executable(s) to trace" >&2

# Trace each executable
> "$LOG_FILE"
for exe in "${EXECUTABLES[@]}"; do
    echo "[dmg] Tracing: $exe" >&2
    case "$exe" in
        *.pkg|*.mpkg)
            # Package installers — use installer command on macOS,
            # but in Linux just trace the pkgutil extraction
            pkgutil --expand "$exe" /tmp/pkg_expand 2>/dev/null || true
            strace -t -f -e trace=all -yy -s 1000 -o /tmp/strace_pkg.log bash -c "ls -R /tmp/pkg_expand" 2>/dev/null || true
            cat /tmp/strace_pkg.log >> "$LOG_FILE" 2>/dev/null || true
            ;;
        *.sh|*.py|*.command)
            if [[ "$exe" == *.py ]]; then
                python3 "$exe" &>/dev/null || true
            else
                bash "$exe" &>/dev/null || true
            fi
            ;;
        *)
            # Native binary — run directly
            chmod +x "$exe" 2>/dev/null || true
            "$exe" &>/dev/null || true
            ;;
    esac
done

# If strace output was empty (executables didn't produce syscalls we could capture
# via direct execution), at least trace the extraction process itself
if [ ! -s "$LOG_FILE" ]; then
    echo "[dmg] No strace output from executables — tracing extraction" >&2
    strace -t -f -e trace=all -yy -s 1000 -o "$LOG_FILE" 7z l "$INPUT" 2>/dev/null || true
fi

echo "[dmg] Analysis complete — log: $LOG_FILE" >&2
"""

# --------------------------------------------------------------------------- #
#  EXE analysis script (runs inside the container)
# --------------------------------------------------------------------------- #

_EXE_ANALYZE_SCRIPT = r"""
set -euo pipefail

LOG_FILE="/tmp/strace.log"
INPUT="$1"

# Check wine64 availability
if ! command -v wine64 &>/dev/null; then
    echo "[exe] ERROR: wine64 is not installed in the sandbox" >&2
    echo "WINE64 NOT AVAILABLE" > "$LOG_FILE"
    exit 0
fi

# Verify the file exists and is readable
if [ ! -f "$INPUT" ]; then
    echo "[exe] ERROR: File not found: $INPUT" >&2
    echo "FILE NOT FOUND" > "$LOG_FILE"
    exit 0
fi

FILE_SIZE=$(stat -c%s "$INPUT" 2>/dev/null || echo "0")
if [ "$FILE_SIZE" -eq 0 ]; then
    echo "[exe] ERROR: File is empty: $INPUT" >&2
    echo "EMPTY FILE" > "$LOG_FILE"
    exit 0
fi

echo "[exe] Analyzing: $INPUT (${FILE_SIZE} bytes)" >&2

# Run the EXE under wine64 with strace tracing the full process tree.
# We use a timeout to prevent hanging on GUI apps that wait for user input.
# The -f flag traces child processes (important for installers that spawn helpers).
# We redirect wine's stderr (which is noisy) to a separate file so it doesn't
# pollute the strace log.
WINE_STDERR="/tmp/wine_stderr.log"
strace -t -f -e trace=all -yy -s 1000 \
    -o "$LOG_FILE" \
    timeout 30 wine64 "$INPUT" \
    2>"$WINE_STDERR" \
    || true

# Check if strace produced any output
if [ ! -s "$LOG_FILE" ]; then
    echo "[exe] WARNING: No strace output captured — EXE may have crashed immediately" >&2
    echo "[exe] Wine stderr output:" >&2
    cat "$WINE_STDERR" >&2
    echo "NO STRACE OUTPUT" > "$LOG_FILE"
fi

echo "[exe] Analysis complete — log: $LOG_FILE" >&2
"""

# --------------------------------------------------------------------------- #
#  Main sandbox runner
# --------------------------------------------------------------------------- #


def run_sandbox(target: str, target_type: str = "pip") -> str:
    """
    Executes the package/installer logic inside an isolated Docker container.
    Captures syscalls using strace.

    Supported target types:
      - pip: Downloads and installs a PyPI package offline
      - npm: Installs an npm package
      - dmg: Extracts and traces executables from a macOS DMG image
      - exe: Runs a Windows EXE under wine64 with syscall tracing

    Returns:
        Path to the strace log file, or empty string on failure.
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
            console.print("[dim]Building sandbox image (first run — may take a minute)...[/]")
            client.images.build(path=str(sandbox_dir), tag=image_tag, rm=True)
            console.print("[bold green]✔[/] Sandbox image built.")
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
strace -f -t -e trace=all -yy -s 1000 -o {log_file_in_container} pip install --no-index --find-links /tmp/pkg {quoted_target} > /dev/null 2>&1
"""
    elif target_type == "npm":
        sandbox_script = f"""
npm install {quoted_target} --global --dry-run > /dev/null 2>&1
ip link set eth0 down
strace -f -t -e trace=all -yy -s 1000 -o {log_file_in_container} npm install {quoted_target} --no-audit --no-fund > /dev/null 2>&1
"""
    elif target_type == "shell":
        volumes = {str(Path(target).parent): {"bind": "/samples", "mode": "ro"}}
        quoted_filename = shlex.quote(Path(target).name)
        sandbox_script = f"""
ip link set eth0 down 2>/dev/null || true
strace -f -t -e trace=all -yy -s 1000 -o {log_file_in_container} bash /samples/{quoted_filename} > /dev/null 2>&1 || true
"""
    elif target_type == "dmg":
        dmg_path = Path(target).absolute()
        if not dmg_path.exists():
            console.print(f"\n[bold red]Error:[/] DMG file not found: {dmg_path}")
            return ""
        volumes[str(dmg_path)] = {"bind": "/tmp/target.dmg", "mode": "ro"}
        # Pass the DMG path as an argument to the analysis script
        sandbox_script = _DMG_ANALYZE_SCRIPT + f'\n_analyze_dmg "/tmp/target.dmg"'
    elif target_type == "exe":
        exe_path = Path(target).absolute()
        if not exe_path.exists():
            console.print(f"\n[bold red]Error:[/] EXE file not found: {exe_path}")
            return ""
        volumes[str(exe_path)] = {"bind": "/tmp/target.exe", "mode": "ro"}
        sandbox_script = _EXE_ANALYZE_SCRIPT + f'\n_analyze_exe "/tmp/target.exe"'
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
            volumes=volumes,
        )

        timeout = 180 if target_type == "exe" else (120 if target_type == "dmg" else 60)
        start_time = time.time()
        while True:
            container.reload()
            if container.status == "exited":
                break
            if time.time() - start_time > timeout:
                container.kill()
                console.print(f"\n[bold red]Timeout Error:[/] Sandbox execution exceeded {timeout}s limit.")
                break
            time.sleep(1)

        # Check container exit code for errors
        container.reload()
        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
        if exit_code != 0 and target_type in ("dmg", "exe"):
            # Get stderr for diagnostics
            try:
                logs = container.logs(stderr=True, stdout=False).decode("utf-8", errors="replace")
                if logs.strip():
                    console.print(f"[dim]Sandbox stderr:[/] {logs[:500]}")
            except Exception:
                pass

        try:
            stream, _stat = container.get_archive(log_file_in_container)
            temp_tar = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
            with open(temp_tar.name, "wb") as f:
                for chunk in stream:
                    f.write(chunk)

            log_dir = Path.cwd() / "logs"
            log_dir.mkdir(exist_ok=True)
            log_file_name = Path(target).name
            log_file_path = log_dir / f"{log_file_name}_{target_type}_strace.log"

            with tarfile.open(temp_tar.name) as tar:
                member = tar.getmembers()[0]
                extracted_f = tar.extractfile(member)
                if extracted_f:
                    raw_data = extracted_f.read()
                    # For EXE: filter out wine initialization noise from strace log
                    if target_type == "exe":
                        raw_data = _filter_wine_noise(raw_data)
                    with open(log_file_path, "wb") as out_f:
                        out_f.write(raw_data)

            os.remove(temp_tar.name)

            # Check if the log has real content
            log_size = log_file_path.stat().st_size
            if log_size < 50:
                log_content = log_file_path.read_text(errors="replace").strip()
                if log_content in ("NO EXECUTABLES FOUND", "WINE64 NOT AVAILABLE",
                                    "FILE NOT FOUND", "EMPTY FILE", "NO STRACE OUTPUT"):
                    console.print(f"\n[bold yellow]Warning:[/] {log_content} — {target}")
                    return ""
                elif "ERROR" in log_content.upper():
                    console.print(f"\n[bold red]Analysis Error:[/] {log_content}")
                    return ""

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


def _filter_wine_noise(data: bytes) -> bytes:
    """
    Filter out wine64 initialization noise from strace output.

    Wine produces a lot of noise during initialization:
    - Loading wine's own DLLs (ntdll, kernel32, etc.)
    - Creating wine prefix directories
    - Loading system DLLs

    We keep everything but remove lines that are clearly wine boot noise
    (syscalls accessing wine-specific paths like /root/.wine, /usr/lib/wine, etc.).

    This is a light filter — we only remove the most obvious noise, not
    anything that could be suspicious.
    """
    lines = data.split(b"\n")
    filtered = []
    # Patterns that indicate wine initialization noise (not malicious behavior)
    wine_noise_patterns = [
        b"/root/.wine/",
        b"/usr/lib/wine/",
        b"/usr/share/wine/",
        b"wineboot",
        b"wineserver",
    ]

    for line in lines:
        # Keep lines that don't match any noise pattern
        if not any(pat in line for pat in wine_noise_patterns):
            filtered.append(line)
        # If a noise line contains something suspicious (connect, execve of
        # non-wine binary), keep it anyway
        elif b"connect" in line or b"execve" in line:
            # Check if it's connecting to a non-wine destination
            if b"127.0.0.1" not in line and b"wine" not in line.lower():
                filtered.append(line)

    return b"\n".join(filtered)
