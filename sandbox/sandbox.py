import os
import time
import tarfile
import tempfile
from pathlib import Path
from rich.console import Console
import subprocess

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
RESOURCE_FILE="/tmp/resources.json"
DST="/tmp/dmg_extracted"
INPUT="$1"

mkdir -p "$DST"

# Capture initial resource state
echo '{"initial": {' > "$RESOURCE_FILE"
echo "  \"mem_total_kb\": $(grep MemTotal /proc/meminfo | awk '{print $2}')," >> "$RESOURCE_FILE"
echo "  \"cpu_count\": $(nproc)" >> "$RESOURCE_FILE"
echo '}, "samples": []}' >> "$RESOURCE_FILE"

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
                strace -t -f -e trace=all -yy -s 1000 -o /tmp/strace_script.log python3 "$exe" 2>/dev/null || true
            else
                strace -t -f -e trace=all -yy -s 1000 -o /tmp/strace_script.log bash "$exe" 2>/dev/null || true
            fi
            cat /tmp/strace_script.log >> "$LOG_FILE" 2>/dev/null || true
            ;;
        *)
            # Native binary — run under strace
            chmod +x "$exe" 2>/dev/null || true
            strace -t -f -e trace=all -yy -s 1000 -o /tmp/strace_bin.log "$exe" 2>/dev/null || true
            cat /tmp/strace_bin.log >> "$LOG_FILE" 2>/dev/null || true
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
#  ZIP Malware analysis script (runs inside the container)
# --------------------------------------------------------------------------- #

_ZIP_MALWARE_ANALYZE_SCRIPT = r"""
set -uo pipefail

LOG_FILE="/tmp/strace.log"
RESOURCE_FILE="/tmp/resources.json"
EXTRACT_DIR="/tmp/malware_extracted"
INPUT="/tmp/target.zip"

mkdir -p "$EXTRACT_DIR"
> "$LOG_FILE"

echo '{"peak_memory_kb": 0, "disk_used_kb": 0, "file_count": 0}' > "$RESOURCE_FILE"

# ---------- Step 1: extract with known malware-repo passwords ----------
PASSWORDS=("infected" "malware" "virus" "infected!" "password" "Infected")
EXTRACTED=false
USED_PASSWORD=""

for PASS in "${PASSWORDS[@]}"; do
    if 7z x "$INPUT" -p"$PASS" -o"$EXTRACT_DIR" -y > /tmp/7z_out.txt 2>&1; then
        echo "[zip] Extracted with password: $PASS" >&2
        EXTRACTED=true
        USED_PASSWORD="$PASS"
        break
    fi
done

if [ "$EXTRACTED" = false ]; then
    if 7z x "$INPUT" -o"$EXTRACT_DIR" -y > /tmp/7z_out.txt 2>&1; then
        echo "[zip] Extracted without password" >&2
        EXTRACTED=true
        USED_PASSWORD="(none)"
    fi
fi

if [ "$EXTRACTED" = false ]; then
    echo "[zip] CRITICAL: Could not extract ZIP with any known password" >&2
    echo "ZIP_PASSWORD_UNKNOWN" > "$LOG_FILE"
    exit 0
fi

# ---------- Step 2: network down before any payload execution ----------
ip link set eth0 down 2>/dev/null || true
echo "[zip] Network interface eth0 brought down before payload execution" >&2

# ---------- Step 3: locate and execute payloads under strace with escape guard ----------
FOUND_PAYLOAD=false
ESCAPE_PATTERNS="ptrace.*PTRACE_ATTACH|unshare\(|setns\(|sysrq|/sys/kernel|capset\(.*0x[1-9a-f]|CLONE_NEWPID|CLONE_NEWNET|/proc/1/ns"

run_with_escape_guard() {
    local TRACE_LOG="$1"
    shift
    "$@" &
    CHILD_PID=$!
    while kill -0 "$CHILD_PID" 2>/dev/null; do
        if grep -qEi "$ESCAPE_PATTERNS" "$TRACE_LOG" 2>/dev/null; then
            echo "[SECURITY] Container escape attempt detected — killing payload PID $CHILD_PID" >&2
            echo "ESCAPE_ATTEMPT_DETECTED" >> "$TRACE_LOG"
            kill -9 "$CHILD_PID" 2>/dev/null || true
            kill -9 -"$CHILD_PID" 2>/dev/null || true
            return 1
        fi
        sleep 0.2
    done
    wait "$CHILD_PID" 2>/dev/null || true
    return 0
}

while IFS= read -r -d '' payload; do
    FILETYPE=$(file -b "$payload" 2>/dev/null || echo "unknown")
    echo "[zip] Payload: $(basename "$payload") | type: $FILETYPE" >&2
    PAYLOAD_LOG="/tmp/strace_payload_$$.log"
    > "$PAYLOAD_LOG"

    case "$FILETYPE" in
        *ELF*executable* | *ELF*shared* | *ELF*)
            chmod +x "$payload" 2>/dev/null || true
            run_with_escape_guard "$PAYLOAD_LOG" \
                strace -t -f -e trace=all -yy -s 1000 -o "$PAYLOAD_LOG" \
                timeout 25 "$payload" > /dev/null 2>&1
            ;;
        *PE32* | *PE32+* | *MS-DOS* | *Windows* | *Portable\ Executable*)
            if command -v wine64 &>/dev/null; then
                run_with_escape_guard "$PAYLOAD_LOG" \
                    strace -t -f -e trace=all -yy -s 1000 -o "$PAYLOAD_LOG" \
                    timeout 25 wine64 "$payload" > /dev/null 2>&1
            else
                strace -t -f -e trace=file -yy -s 200 -o "$PAYLOAD_LOG" \
                    timeout 10 file "$payload" > /dev/null 2>&1 || true
            fi
            ;;
        *Python* | *python*)
            run_with_escape_guard "$PAYLOAD_LOG" \
                strace -t -f -e trace=all -yy -s 1000 -o "$PAYLOAD_LOG" \
                timeout 25 python3 "$payload" > /dev/null 2>&1
            ;;
        *shell\ script* | *POSIX\ shell* | *Bourne*)
            run_with_escape_guard "$PAYLOAD_LOG" \
                strace -t -f -e trace=all -yy -s 1000 -o "$PAYLOAD_LOG" \
                timeout 25 bash "$payload" > /dev/null 2>&1
            ;;
        *)
            chmod +x "$payload" 2>/dev/null || true
            strace -t -f -e trace=all -yy -s 1000 -o "$PAYLOAD_LOG" \
                timeout 15 "$payload" > /dev/null 2>&1 || true
            ;;
    esac

    if [ -s "$PAYLOAD_LOG" ]; then
        cat "$PAYLOAD_LOG" >> "$LOG_FILE"
        FOUND_PAYLOAD=true
    fi

    if grep -q "ESCAPE_ATTEMPT_DETECTED" "$LOG_FILE" 2>/dev/null; then
        echo "[SECURITY] Escape confirmed — halting all further payload execution" >&2
        break
    fi

done < <(find "$EXTRACT_DIR" -type f ! -name "*.txt" ! -name "*.json" -print0 2>/dev/null)

if [ "$FOUND_PAYLOAD" = false ]; then
    echo "[zip] No executable payloads found" >&2
    find "$EXTRACT_DIR" -type f >&2
    echo "NO_PAYLOAD_FOUND" > "$LOG_FILE"
fi

MEM_USED=$(grep MemAvailable /proc/meminfo | awk '{print $2}' || echo "0")
FILE_COUNT=$(find "$EXTRACT_DIR" -type f 2>/dev/null | wc -l || echo "0")
echo '{"peak_memory_kb": '"$MEM_USED"', "disk_used_kb": 0, "file_count": '"$FILE_COUNT"'}' > "$RESOURCE_FILE"

echo "[zip] Analysis complete" >&2
"""

# --------------------------------------------------------------------------- #
#  Main sandbox runner
# --------------------------------------------------------------------------- #


def run_sandbox(target: str, target_type: str = "pip", workspace_root: str = None, env: dict = None, controlled_network: bool = False) -> str:
    """
    Execute a target package or script inside the isolated strace sandbox.

    Supported target types:
      - pip: Downloads and installs a python package
      - npm: Installs an npm package
      - dmg: Extracts and traces executables from a macOS DMG image
      - exe: Runs a Windows EXE under wine64 with syscall tracing

    Additional parameters:
      - env: Optional dict of environment variables to inject into the container.
            Example: {"AWS_ACCESS_KEY_ID": "fake", "SECRET_KEY": "test"}
      - controlled_network: If True, skips disconnecting eth0 within the container.

    Returns:
        Path to the strace log file, or empty string on failure.
    """
    mode = os.environ.get("TRACETREE_SANDBOX_MODE", "docker")

    if mode == "direct":
        # ⚠ WARNING: NO SANDBOX ISOLATION ⚠
        # Direct mode installs and executes the target package on the HOST machine
        # with full network access. There is NO container, NO network drop, and NO
        # filesystem isolation. Only use this in a throwaway CI VM or an ephemeral
        # cloud job where the entire environment is discarded after the run.
        # NEVER run direct mode on a developer workstation or shared machine.
        console.print(
            "[bold red]⚠ DIRECT MODE — NO ISOLATION ⚠[/]\n"
            "[red]Target package will be installed on the HOST with full network access.\n"
            "Only safe in a throwaway CI VM. Do NOT use on a workstation.[/]"
        )
        log_dir = Path.cwd() / "logs"
        log_dir.mkdir(exist_ok=True)
        log_file_path = log_dir / f"{Path(target).name}_{target_type}_strace.log"
        
        env_vars = os.environ.copy()
        if env:
            env_vars.update(env)
        env_vars["TARGET"] = target
        env_vars["TRACETREE_LOG_PATH"] = str(log_file_path)
        # Map target_type to script — log path injected via env, never formatted into script
        if target_type in ("pip", "mcp"):
            script = """
pip download "$TARGET" --dest /tmp/pkg > /dev/null 2>&1
strace -f -t -e trace=all -yy -s 1000 -o /tmp/strace.log pip install --no-index --find-links /tmp/pkg "$TARGET" > /dev/null 2>&1
cp /tmp/strace.log "$TRACETREE_LOG_PATH"
"""
        elif target_type == "npm":
            script = """
npm install "$TARGET" --global --dry-run > /dev/null 2>&1
strace -f -t -e trace=all -yy -s 1000 -o /tmp/strace.log npm install "$TARGET" --no-audit --no-fund > /dev/null 2>&1
cp /tmp/strace.log "$TRACETREE_LOG_PATH"
"""
        else:
            # Fallback for dmg/exe/shell — needs more complex mapping if supported in direct mode
            console.print(f"[yellow]Warning:[/] Direct mode only supports 'pip' and 'npm' currently.")
            return ""

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as tf:
                tf.write(script)
                tf.flush()
                script_path = tf.name
            os.chmod(script_path, 0o700)
            try:
                subprocess.run(["/bin/bash", script_path], env=env_vars, check=True)  # noscan — sandbox intentionally executes bash
            finally:
                os.unlink(script_path)
            return str(log_file_path)
        except Exception as e:
            console.print(f"[bold red]Direct Execution Error:[/] {e}")
            return ""

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
            try:
                client.images.build(path=str(sandbox_dir), tag=image_tag, rm=True)
            except Exception:
                # Build cache may be stale (e.g. Docker storage moved to new disk).
                # Retry without cache.
                console.print("[dim]Retrying build without cache...[/]")
                client.images.build(path=str(sandbox_dir), tag=image_tag, rm=True, nocache=True)
            console.print("[bold green]✔[/] Sandbox image built.")
        except Exception as e:
            console.print(f"\n[bold red]Build Error:[/] {e}")
            return ""

    log_file_in_container = "/tmp/strace.log"
    volumes = {}
    # Phase 1: Support for environment variable injection
    env_vars = {"TARGET": target}  # Pass target via environment variable, not string interpolation
    # Merge user-provided environment variables (if any)
    if env:
        for k, v in env.items():
            if k and v is not None:
                env_vars[k] = str(v)

    if target_type in ("pip", "mcp"):
        sandbox_script = """
# Honeypot Setup
mkdir -p ~/.aws
echo "[default]
aws_access_key_id = AKIAHONEPOTEXAMPLE
aws_secret_access_key = secret/honeypot/key/exfil/target
" > ~/.aws/credentials
echo "fake_db_password=honeypot_db_pass_123" > ~/.env
# Fake shadow file access check
echo "root:$6$honeypot$zXy...:19000:0:99999:7:::" > /tmp/fake_shadow

# Resource monitoring setup
RESOURCE_FILE="/tmp/resources.json"
echo '{"initial": {"mem_total_kb": '$(grep MemTotal /proc/meminfo | awk '{print $2}')', "cpu_count": '$(nproc)'}, "samples": []}' > "$RESOURCE_FILE"

pip download "$TARGET" --dest /tmp/pkg > /dev/null 2>&1
ip link set eth0 down

# Capture pre-install resources
MEM_BEFORE=$(grep MemAvailable /proc/meminfo | awk '{print $2}' || echo "0")
DISK_BEFORE=$(df /tmp --output=avail | tail -1)

strace -f -t -e trace=all -yy -s 1000 -o /tmp/strace.log pip install --no-index --find-links /tmp/pkg "$TARGET" > /dev/null 2>&1

# Capture post-install resources
MEM_AFTER=$(grep MemAvailable /proc/meminfo | awk '{print $2}' || echo "0")
DISK_AFTER=$(df /tmp --output=avail | tail -1)
FILE_COUNT=$(find /usr/local/lib/python* -type f 2>/dev/null | wc -l || echo "0")

MEM_USED=$((MEM_BEFORE - MEM_AFTER))
if [ "$MEM_USED" -lt 0 ]; then MEM_USED=0; fi
DISK_USED=$((DISK_BEFORE - DISK_AFTER))
if [ "$DISK_USED" -lt 0 ]; then DISK_USED=0; fi

echo '{"peak_memory_kb": '"$MEM_USED"', "disk_used_kb": '"$DISK_USED"', "file_count": '"$FILE_COUNT"'}' > "$RESOURCE_FILE"
"""
    elif target_type == "npm":
        sandbox_script = """
# Resource monitoring setup
RESOURCE_FILE="/tmp/resources.json"
echo '{"initial": {"mem_total_kb": '$(grep MemTotal /proc/meminfo | awk '{print $2}')', "cpu_count": '$(nproc)'}, "samples": []}' > "$RESOURCE_FILE"

npm install "$TARGET" --global --dry-run > /dev/null 2>&1
ip link set eth0 down

# Capture pre-install resources
MEM_BEFORE=$(grep MemAvailable /proc/meminfo | awk '{print $2}' || echo "0")
DISK_BEFORE=$(df /tmp --output=avail | tail -1)

strace -f -t -e trace=all -yy -s 1000 -o /tmp/strace.log npm install "$TARGET" --no-audit --no-fund > /dev/null 2>&1

# Capture post-install resources
MEM_AFTER=$(grep MemAvailable /proc/meminfo | awk '{print $2}' || echo "0")
DISK_AFTER=$(df /tmp --output=avail | tail -1)
FILE_COUNT=$(find "/usr/local/lib/node_modules/$TARGET" -type f 2>/dev/null | wc -l || echo "0")

MEM_USED=$((MEM_BEFORE - MEM_AFTER))
if [ "$MEM_USED" -lt 0 ]; then MEM_USED=0; fi
DISK_USED=$((DISK_BEFORE - DISK_AFTER))
if [ "$DISK_USED" -lt 0 ]; then DISK_USED=0; fi

echo '{"peak_memory_kb": '"$MEM_USED"', "disk_used_kb": '"$DISK_USED"', "file_count": '"$FILE_COUNT"'}' > "$RESOURCE_FILE"
"""
    elif target_type == "shell":
        target_path = Path(target).resolve()
        ws_root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
        # Reject mounts outside the workspace root to prevent path traversal
        try:
            target_path.relative_to(ws_root)
        except ValueError:
            console.print(f"\n[bold red]Error:[/] Shell target must be within workspace directory: {target}")
            return ""
        if not target_path.is_file():
            console.print(f"\n[bold red]Error:[/] Shell target not found: {target_path}")
            return ""
        # Mount only the single file, not the whole parent dir — prevents payload reading sibling files/secrets
        volumes[str(target_path)] = {"bind": f"/samples/{target_path.name}", "mode": "ro"}
        env_vars["TARGET_FILENAME"] = target_path.name
        sandbox_script = """
ip link set eth0 down 2>/dev/null || true
strace -f -t -e trace=all -yy -s 1000 -o /tmp/strace.log bash "/samples/$TARGET_FILENAME" > /dev/null 2>&1 || true
"""
    elif target_type == "dmg":
        dmg_path = Path(target).absolute().resolve()
        if not dmg_path.exists():
            console.print(f"\n[bold red]Error:[/] DMG file not found: {dmg_path}")
            return ""
        volumes[str(dmg_path)] = {"bind": "/tmp/target.dmg", "mode": "ro"}
        # Pass the DMG path as an argument to the analysis script
        sandbox_script = _DMG_ANALYZE_SCRIPT.replace('INPUT="$1"', 'INPUT="/tmp/target.dmg"')
    elif target_type == "exe":
        exe_path = Path(target).absolute().resolve()
        if not exe_path.exists():
            console.print(f"\n[bold red]Error:[/] EXE file not found: {exe_path}")
            return ""
        volumes[str(exe_path)] = {"bind": "/tmp/target.exe", "mode": "ro"}
        sandbox_script = _EXE_ANALYZE_SCRIPT.replace('INPUT="$1"', 'INPUT="/tmp/target.exe"')
    elif target_type == "zip-malware":
        zip_path = Path(target).absolute().resolve()
        if not zip_path.exists():
            console.print(f"\n[bold red]Error:[/] ZIP file not found: {zip_path}")
            return ""
        volumes[str(zip_path)] = {"bind": "/tmp/target.zip", "mode": "ro"}
        sandbox_script = _ZIP_MALWARE_ANALYZE_SCRIPT
    else:
        console.print(f"[bold red]Unsupported Type:[/] {target_type}")
        return ""

    container = None
    try:
        # Load seccomp profile if it exists
        security_opt = []
        seccomp_path = Path(__file__).parent / "deny.json"
        if seccomp_path.exists():
            try:
                with open(seccomp_path, "r") as f:
                    seccomp_content = f.read().strip()
                # Pass raw JSON string directly to Docker API
                security_opt.append(f"seccomp={seccomp_content}")
            except Exception as e:
                console.print(f"[yellow]⚠ Failed to load seccomp: {e}[/]")

        if controlled_network:
            sandbox_script = sandbox_script.replace("ip link set eth0 down", "echo 'Controlled network: keeping eth0 up'")
            sandbox_script = sandbox_script.replace("ip link set eth0 down 2>/dev/null || true", "echo 'Controlled network: keeping eth0 up'")

        try:
            container = client.containers.run(
                image=image_tag,
                command=["/bin/bash", "-c", sandbox_script],
                detach=True,
                remove=False,
                cap_add=["NET_ADMIN"],
                security_opt=security_opt,
                volumes=volumes,
                environment=env_vars,
                mem_limit="512m",
                cpu_period=100000,
                cpu_quota=25000,
                pids_limit=100
            )
        except Exception as e:
            console.print(f"\n[bold red]Execution Error:[/] {e}")
            return ""

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

            # For binary target types, pull extracted files to quarantine BEFORE
            # container teardown so StaticDisassemblyAnalyzer can reach them.
            # Only zip-malware supported now; dmg/exe can be added later.
            if target_type == "zip-malware":
                try:
                    quarantine_base = Path.cwd() / ".tracetree" / "quarantine"
                    quarantine_dir = quarantine_base / log_file_path.stem
                    quarantine_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                    quarantine_base.chmod(0o700)  # restrict base dir: owner-only
                    q_stream, _ = container.get_archive("/tmp/malware_extracted")
                    q_tar_tmp = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
                    with open(q_tar_tmp.name, "wb") as qf:
                        for chunk in q_stream:
                            qf.write(chunk)
                    with tarfile.open(q_tar_tmp.name) as qtar:
                        # nosec — extraction confined to quarantine_dir, no symlink follow
                        qtar.extractall(path=str(quarantine_dir), filter="data")
                    os.remove(q_tar_tmp.name)
                    # Write sidecar so perform_analysis() knows where to find the files
                    sidecar = log_file_path.with_suffix(".qdir")
                    sidecar.write_text(str(quarantine_dir), encoding="utf-8")
                    console.print(f"[dim]Retained extracted binary at {quarantine_dir} for static analysis[/]")
                except Exception as _qe:
                    log.warning("Quarantine extraction failed (non-fatal): %s", _qe)

            # Also try to retrieve resource monitoring data
            resource_data = {}
            try:
                res_stream, _ = container.get_archive("/tmp/resources.json")
                res_tar = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
                with open(res_tar.name, "wb") as f:
                    for chunk in res_stream:
                        f.write(chunk)
                with tarfile.open(res_tar.name) as tar:
                    member = tar.getmembers()[0]
                    extracted_f = tar.extractfile(member)
                    if extracted_f:
                        import json as _json
                        resource_data = _json.loads(extracted_f.read().decode("utf-8"))
                os.remove(res_tar.name)
            except Exception:
                pass  # Resource data is optional

            # Check if the log has real content
            log_size = log_file_path.stat().st_size
            if log_size < 50:
                log_content = log_file_path.read_text(errors="replace").strip()
                if log_content in ("NO EXECUTABLES FOUND", "WINE64 NOT AVAILABLE",
                                    "FILE NOT FOUND", "EMPTY FILE", "NO STRACE OUTPUT",
                                    "NO_PAYLOAD_FOUND"):
                    console.print(f"\n[bold yellow]Warning:[/] {log_content} — {target}")
                    return ""
                elif log_content == "ZIP_PASSWORD_UNKNOWN":
                    console.print(
                        f"\n[bold red]❌ ZIP Extract Failed:[/] Could not open [bold]{target}[/] "
                        f"with any known password.\n"
                        f"[dim]Tried: infected, malware, virus, infected!, password[/]\n"
                        f"[dim]Supply the password via --env ZIP_PASSWORD=<pass> if known.[/]"
                    )
                    return ""
                elif "ERROR" in log_content.upper():
                    console.print(f"\n[bold red]Analysis Error:[/] {log_content}")
                    return ""

            # Escape-attempt detection — check AFTER retrieving log from container.
            # Container is destroyed in the finally block regardless.
            log_text = log_file_path.read_text(errors="replace")
            if "ESCAPE_ATTEMPT_DETECTED" in log_text:
                console.print(
                    "\n[bold red on white]⚠ SECURITY ALERT: CONTAINER ESCAPE ATTEMPT DETECTED ⚠[/]\n"
                    f"[bold red]Target:[/] {target}\n"
                    "[red]The payload attempted to escape the sandbox (ptrace/namespace/sysrq/capability "
                    "escalation detected in syscall trace).\n"
                    "The process was killed and the container is being destroyed.[/]"
                )
                # Container already removed in finally block — log the event and return the log
                # so the ML pipeline can classify the escape attempt itself as malicious evidence.

            # If we have resource data, append it to the log as valid JSON
            if resource_data:
                import json as _json_out
                with open(log_file_path, "a") as f:
                    f.write(f"\n# TRACE_TREE_RESOURCE_DATA: {_json_out.dumps(resource_data)}\n")

            return str(log_file_path)

        except docker.errors.NotFound:
            console.print(f"\n[yellow]Warning:[/] No strace log was written for {target}.")
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
