#!/usr/bin/env python3
"""
TraceTree Unified Setup Wizard
An interactive setup wizard utilizing the Rich library to eliminate developer friction.
Checks system requirements sequentially, configures CLI/GUI modes, and installs hooks.
"""

import os
import sys
import time
import shutil
import platform
import subprocess
from pathlib import Path

# Dynamically adjust PATH to prioritize typical macOS/Linux binary directories (e.g. Homebrew)
for _p in ["/opt/homebrew/bin", "/usr/local/bin"]:
    if _p not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = f"{_p}{os.pathsep}{os.environ.get('PATH', '')}"

# Try importing requests for Ollama communication
try:
    import requests
except ImportError:
    print("Requests library not found. Please run 'pip install requests' first.")
    sys.exit(1)

# Try importing rich
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.status import Status
    from rich.text import Text
    from rich.align import Align
except ImportError:
    print("Rich library not found. Please run 'pip install rich' first.")
    sys.exit(1)

# Try importing docker
try:
    import docker
except ImportError:
    docker = None

# Configure Console
console = Console()

BANNER_ASCII = """
████████╗██████╗  █████╗  ██████╗███████╗████████╗██████╗ ███████╗███████╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝
   ██║   ██████╔╝███████║██║     █████╗     ██║   ██████╔╝█████╗  █████╗  
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝     ██║   ██╔══██╗██╔══╝  ██╔══╝  
   ██║   ██║  ██║██║  ██║╚██████╗███████╗   ██║   ██║  ██║███████╗███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
"""

MODEL_NAME = "qwen2.5-coder:7b"
OLLAMA_BASE = os.getenv("OLLAMA_HOST", "http://localhost:11434")
if not OLLAMA_BASE.startswith("http"):
    OLLAMA_BASE = f"http://{OLLAMA_BASE}"


def show_banner():
    lines = BANNER_ASCII.strip("\n").split("\n")
    colors = ["#FF9966", "#FFAA55", "#FFBB44", "#FFCC44", "#FFDD33", "#FFEE22"]
    
    styled_banner = Text()
    for i, line in enumerate(lines):
        color = colors[min(i, len(colors)-1)]
        styled_banner.append(line + "\n", style=f"bold {color}")

    console.print("\n")
    console.print(Align.center(styled_banner))
    console.print(Align.center(Text("Unified TraceTree Installer Wizard", style="bold italic #FFCC44")))
    console.print("\n")


def check_python_version() -> bool:
    """Verify python version is >= 3.9."""
    py_version = sys.version_info
    version_str = f"{py_version.major}.{py_version.minor}.{py_version.micro}"
    
    if py_version >= (3, 9):
        console.print(f"[green]✔ Python Version:[/] {version_str} (Compatible)")
        return True
    else:
        console.print(f"[red]❌ Python Version:[/] {version_str} (Incompatible. Version >= 3.9 is required.)")
        return False


def check_docker_socket() -> bool:
    """Verify if the Docker daemon is running and accessible."""
    # Try using Docker Python SDK
    if docker is not None:
        try:
            client = docker.from_env()
            if client.ping():
                console.print("[green]✔ Docker Daemon:[/] Accessible and active")
                return True
        except Exception:
            pass

    # Fallback: check docker CLI command
    docker_path = shutil.which("docker")
    if docker_path is not None:
        try:
            res = subprocess.run([docker_path, "ps"], env=os.environ, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            if res.returncode == 0:
                console.print("[green]✔ Docker Daemon:[/] Accessible and active (CLI)")
                return True
        except Exception:
            pass

    console.print("[yellow]⚠ Docker Daemon:[/] Unreachable or not installed. Sandboxed packaging analysis will not work.")
    return False


def check_ollama_status() -> bool:
    """Verify if Ollama is responsive."""
    try:
        response = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=2)
        if response.status_code == 200:
            console.print("[green]✔ Ollama Instance:[/] Responsive")
            return True
    except Exception:
        pass
    
    console.print("[yellow]⚠ Ollama Instance:[/] Unresponsive or not running.")
    return False


def run_preflight_checks() -> dict:
    """Run requirement checks sequentially."""
    console.print("[bold cyan]Running System Preflight Checks...[/]\n")
    
    results = {}
    
    with Status("[cyan]Checking Python version...[/]", console=console) as status:
        results["python"] = check_python_version()
        time.sleep(0.5)
        
    with Status("[cyan]Checking Docker socket...[/]", console=console) as status:
        results["docker"] = check_docker_socket()
        time.sleep(0.5)
        
    with Status("[cyan]Checking Ollama status...[/]", console=console) as status:
        results["ollama"] = check_ollama_status()
        time.sleep(0.5)
        
    console.print("")
    return results


def setup_cli_mode() -> bool:
    """Configure CLI Mode (shell hooks, git pre-commit hook, environment path)."""
    console.print(Panel("[bold green]CLI MODE SETUP[/]\nConfiguring shell hooks, Git hooks, and environment paths...", border_style="green"))
    
    project_root = Path(__file__).resolve().parent
    hooks_dir = project_root / "hooks"
    sys.path.insert(0, str(hooks_dir))
    
    try:
        from install_hook import install_hook as _do_install, _detect_shell_rc
    except ImportError as e:
        console.print(f"[bold red]Error:[/] Could not import hook installer: {e}")
        return False

    # 1. Install standard shell hooks and git hooks
    console.print("[cyan]Installing TraceTree shell and git hooks...[/]")
    hook_ok = _do_install()
    if not hook_ok:
        console.print("[bold red]⚠ Hook installation failed.[/]")
    
    # 2. Check and configure environment paths
    result = _detect_shell_rc()
    if result:
        shell_name, rc_path = result
        venv_bin = Path(sys.executable).parent
        
        # Check if venv_bin is in PATH or RC content
        try:
            content = Path(rc_path).read_text(encoding="utf-8")
        except Exception:
            content = ""
            
        is_in_path = str(venv_bin) in os.environ.get("PATH", "")
        is_in_rc = str(venv_bin) in content
        
        if is_in_path or is_in_rc:
            console.print(f"[green]✔ PATH environment already includes {venv_bin}[/]")
        else:
            if Confirm.ask(f"Add current virtual environment bin path ({venv_bin}) to {shell_name} profile ({rc_path})?"):
                marker = "# --- TraceTree Path Configuration (auto-installed) ---"
                export_line = f'export PATH="{venv_bin}:$PATH"'
                try:
                    with open(rc_path, "a", encoding="utf-8") as f:
                        f.write(f"\n{marker}\n{export_line}\n")
                    console.print(f"[green]✔ PATH updated. Please run 'source {rc_path}' to refresh environment.[/]")
                except Exception as e:
                    console.print(f"[red]❌ Failed to update PATH in {rc_path}: {e}[/]")
                    return False
    
    console.print("\n[bold green]✔ CLI Mode Setup Complete![/]")
    return True


def setup_gui_mode() -> bool:
    """Configure GUI Mode (Ollama, models, and npm installs)."""
    console.print(Panel("[bold magenta]GUI MODE SETUP[/]\nConfiguring background prerequisites, AI models, and web dependencies...", border_style="magenta"))
    
    # 1. Ensure Ollama is running or installed
    is_running = check_ollama_status()
    ollama_path = shutil.which("ollama")
    
    if is_running:
        console.print("[green]✔ Ollama Service:[/] Already active and running.")
    else:
        # If it's not running, let's see if it's installed
        if ollama_path is None:
            console.print("[bold yellow]⚠ Ollama is not installed.[/] Ollama is required for localized AI security checks.")
            sys_os = platform.system().lower()
            if sys_os == "darwin":
                brew_path = shutil.which("brew")
                if brew_path is None:
                    console.print("[bold red]Error:[/] Homebrew ('brew') was not found in your PATH.")
                    console.print("Please install Ollama manually from: [blue]https://ollama.com[/]")
                    return False
                
                if Confirm.ask("Would you like to install Ollama via Homebrew now?"):
                    try:
                        console.print(f"[cyan]Running: {brew_path} install ollama...[/]")
                        subprocess.run([brew_path, "install", "ollama"], env=os.environ, check=True)
                        console.print("[bold green]✔ Ollama installed successfully![/]")
                        ollama_path = shutil.which("ollama") or "/opt/homebrew/bin/ollama"
                    except Exception as e:
                        console.print(f"[bold red]Installation failed:[/] {e}. Please install manually from https://ollama.com")
                        return False
                else:
                    console.print("[yellow]Skipping Ollama installation. Local AI will be unavailable.[/]")
                    return False
            else:
                console.print("[bold yellow]Please install Ollama manually from https://ollama.com[/]")
                return False

        # If it is installed but not running, start it
        if ollama_path is not None:
            if Confirm.ask("Ollama service is not running. Would you like to start it in the background now?"):
                try:
                    subprocess.Popen([ollama_path, "serve"], env=os.environ, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    console.print("[cyan]Waiting for Ollama to wake up (checking status)...[/]")
                    for _ in range(15):
                        time.sleep(1)
                        if check_ollama_status():
                            is_running = True
                            break
                    if not is_running:
                        console.print("[bold red]❌ Ollama service failed to wake up in time.[/]")
                        return False
                except Exception as e:
                    console.print(f"[bold red]Failed to start Ollama service:[/] {e}")
                    return False

    # 3. Pull required AI Model
    if is_running:
        try:
            response = requests.get(f"{OLLAMA_BASE}/api/tags")
            models = [m["name"] for m in response.json().get("models", [])]
            
            # Check if model exists
            model_exists = False
            for m in models:
                if m == MODEL_NAME or m.startswith(f"{MODEL_NAME}:"):
                    model_exists = True
                    break
                    
            if model_exists:
                console.print(f"[green]✔ AI Model:[/] {MODEL_NAME} is already available.")
            else:
                console.print(f"[bold yellow]⚠ Model '{MODEL_NAME}' is not pulled.[/] (Size: ~4.7GB)")
                if Confirm.ask(f"Authorize setup to pull '{MODEL_NAME}' via Ollama now?"):
                    if ollama_path is not None:
                        console.print(f"[cyan]Pulling {MODEL_NAME}... this may take several minutes.[/]")
                        # Run subprocess with stdout to show progress directly
                        subprocess.run([ollama_path, "pull", MODEL_NAME], env=os.environ, check=True)
                        console.print(f"[bold green]✔ Model {MODEL_NAME} downloaded successfully![/]")
                    else:
                        console.print(f"[cyan]Pulling {MODEL_NAME} via Ollama API... this may take several minutes.[/]")
                        # pull via HTTP API
                        import json
                        with requests.post(f"{OLLAMA_BASE}/api/pull", json={"name": MODEL_NAME}, stream=True) as r:
                            r.raise_for_status()
                            for line in r.iter_lines():
                                if line:
                                    data = json.loads(line)
                                    status = data.get("status", "")
                                    completed = data.get("completed", 0)
                                    total = data.get("total", 0)
                                    if total > 0:
                                        percent = (completed / total) * 100
                                        console.print(f"[cyan]Progress:[/] {status} ({percent:.1f}%)   ", end="\r")
                                    else:
                                        console.print(f"[cyan]Progress:[/] {status}                 ", end="\r")
                        console.print(f"\n[bold green]✔ Model {MODEL_NAME} downloaded successfully![/]")
                else:
                    console.print("[yellow]Skipping model pull. Please run 'ollama pull qwen2.5-coder:7b' manually later.[/]")
        except Exception as e:
            console.print(f"[bold red]Failed to verify/pull AI models:[/] {e}")
            return False
            
    # 4. Check Node.js and frontend dependencies
    project_root = Path(__file__).resolve().parent
    frontend_dir = project_root / "frontend"
    node_modules = frontend_dir / "node_modules"
    
    if not node_modules.exists():
        console.print("[bold yellow]⚠ Frontend node_modules not found.[/]")
        npm_path = shutil.which("npm")
        if npm_path is None:
            console.print("[bold red]Error:[/] Node.js/npm is not installed. Please install Node.js (>= 18.0) to run the Web Dashboard.")
        else:
            if Confirm.ask("Install Next.js frontend package dependencies via 'npm install' now?"):
                console.print(f"[cyan]Running '{npm_path} install' in frontend workspace...[/]")
                try:
                    subprocess.run([npm_path, "install"], env=os.environ, cwd=str(frontend_dir), check=True)
                    console.print("[bold green]✔ Frontend dependencies installed successfully![/]")
                except Exception as e:
                    console.print(f"[bold red]npm install failed:[/] {e}")
                    return False
    else:
        console.print("[green]✔ Frontend Dependencies:[/] node_modules folder exists")

    console.print("\n[bold green]✔ GUI Mode Setup Complete![/]")
    return True


def main():
    show_banner()
    
    # 1. Run sequential checks
    checks = run_preflight_checks()
    
    # Abort if Python version is too old
    if not checks["python"]:
        console.print("[bold red]❌ Critical: Incompatible Python version. Aborting setup.[/]")
        sys.exit(1)
        
    # 2. Prompt Mode Selection
    console.print("[bold]Please select your TraceTree setup mode:[/]")
    console.print("  [1] [bold green]CLI Mode[/] - Configures Git/shell hooks, and updates system PATH.")
    console.print("  [2] [bold magenta]GUI Mode[/] - Ensures Docker/Ollama are active, pulls AI model, and installs web dependencies.")
    console.print("")
    
    mode = Prompt.ask("Choose setup mode", choices=["1", "2"], default="1")
    
    success = False
    if mode == "1":
        success = setup_cli_mode()
    elif mode == "2":
        success = setup_gui_mode()
        
    if success:
        console.print("\n[bold green]🎉 TraceTree setup completed successfully![/]\n")
        if mode == "2":
            console.print("Run [bold cyan]cascade-analyze analyze <package>[/] to start analyzing packages.\n")
            console.print("[dim]Note: the dashboard command is temporarily unavailable while a new one is being developed.[/]\n")
    else:
        console.print("\n[bold red]❌ TraceTree setup failed or was partially completed.[/]\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
