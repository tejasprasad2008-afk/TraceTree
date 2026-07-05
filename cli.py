import os
import sys
import socket
from pathlib import Path

# Add project root directory to sys.path so modules like orchestrator are always importable
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Dynamically adjust PATH to prioritize typical macOS/Linux binary directories (e.g. Homebrew)
for _p in ["/opt/homebrew/bin", "/usr/local/bin"]:
    if _p not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = f"{_p}{os.pathsep}{os.environ.get('PATH', '')}"

import time
import typer
import platform
from typing import Tuple, Optional, Dict, Any
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree
from rich.text import Text
from rich.align import Align

try:
    import docker
except ImportError:
    docker = None


def _is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check whether a TCP port is already bound on the given host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0

from rich.columns import Columns
from rich.layout import Layout
from rich.style import Style
from sandbox.sandbox import run_sandbox
import termios, tty

app = typer.Typer(help="TraceTree Security Analyzer")
console = Console()

def print_panel_with_trim(console_obj, content: str, title: str, border_style: str, max_lines: int = 10):
    lines = content.splitlines()
    if len(lines) <= max_lines:
        console_obj.print(Panel(content, title=title, border_style=border_style, expand=False))
        return

    trimmed_content = "\n".join(lines[:max_lines]) + "\n\n[dim]... Output trimmed ...[/dim]"
    console_obj.print(Panel(trimmed_content, title=title, border_style=border_style, expand=False))

    if sys.stdin.isatty():
        try:
            console_obj.print("[dim]Press Ctrl+O to view full output, or any other key to continue...[/dim]", end="\r")
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                ch = sys.stdin.read(1)
            except Exception:
                ch = ""
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            
            # Clear the hint line
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()

            if ch == '\x0f':  # Ctrl+O
                with console_obj.pager():
                    console_obj.print(Panel(content, title=title, border_style=border_style, expand=False))
        except ImportError:
            pass

BANNER_ASCII = """
████████╗██████╗  █████╗  ██████╗███████╗████████╗██████╗ ███████╗███████╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝
   ██║   ██████╔╝███████║██║     █████╗     ██║   ██████╔╝█████╗  █████╗  
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝     ██║   ██╔══██╗██╔══╝  ██╔══╝  
   ██║   ██║  ██║██║  ██║╚██████╗███████╗   ██║   ██║  ██║███████╗███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
"""

def show_welcome():
    # Peach to Yellow Gradient effect (manual gradient since text is per-line)
    lines = BANNER_ASCII.strip("\n").split("\n")
    colors = ["#FF9966", "#FFAA55", "#FFBB44", "#FFCC44", "#FFDD33", "#FFEE22"]
    
    styled_banner = Text()
    for i, line in enumerate(lines):
        color = colors[min(i, len(colors)-1)]
        styled_banner.append(line + "\n", style=f"bold {color}")

    console.print("\n")
    console.print(Align.center(styled_banner))
    console.print(Align.center(Text("Runtime behavioral analysis. No installs go unwatched.", style="italic dim #FFCC44")))
    console.print("\n")

    tips = Tree("[bold #FF9966]Getting Started[/]")
    tips.add("[bold cyan]Analyze a pip package:[/] cascade-analyze <package> --type pip")
    tips.add("[bold green]Analyze an npm package:[/] cascade-analyze <package> --type npm")
    tips.add("[bold blue]Analyze a DMG or EXE:[/]   cascade-analyze <file.dmg> --type dmg")
    tips.add("[bold yellow]Bulk scan files:[/]      cascade-analyze requirements.txt --type bulk")
    tips.add("[bold magenta]Watch a repo live:[/]    cascade-watch ./my-repo")
    tips.add("[bold red]Quick check a file:[/]      cascade-check setup.py")

    console.print(Align.center(Panel(
        tips,
        border_style="#FF9966",
        padding=(1, 4),
        title="[bold #FFCC44]TraceTree Quick Start[/]",
        expand=False
    )))
    console.print("\n")

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        show_welcome()

def check_docker_preflight():
    """Check if Docker is installed and running before starting analysis."""
    if docker is None:
        console.print(Panel(
            "[bold red]Docker SDK is not installed.[/]\n"
            "Please run: [bold cyan]pip install docker[/]\n\n"
            "[bold yellow]Quick Start:[/] Run [bold green]cascade-analyze <target>[/]",
            title="[bold yellow]Preflight Check Failed[/]",
            border_style="red"
        ))
        sys.exit(1)
        
    try:
        client = docker.from_env()
        client.ping()
    except Exception:
        sys_os = platform.system().lower()
        if sys_os == "darwin":
            install_cmd = "[bold cyan]brew install --cask docker[/]"
            launch_cmd = "open /Applications/Docker.app"
        elif sys_os == "windows":
            install_cmd = "Download Docker Desktop from [blue]https://docker.com/products/docker-desktop[/]"
            launch_cmd = "Start Docker Desktop from the Start menu"
        else:
            install_cmd = "[bold cyan]sudo apt-get install docker-ce docker-ce-cli containerd.io[/]"
            launch_cmd = "[bold cyan]sudo systemctl start docker[/]"
            
        console.print(Panel(
            "[bold red]Docker is not currently running or is unreachable.[/]\n\n"
            f"[bold]To install Docker on your OS (macOS/Linux/Windows):[/]\n{install_cmd}\n\n"
            "[bold]If already installed, please start the Docker daemon:[/]\n"
            f"{launch_cmd}",
            title="[bold yellow]Docker Preflight Error[/]",
            border_style="red",
            expand=False
        ))
        sys.exit(1)

def determine_target_type(target: str) -> str:
    path = Path(target)
    if path.is_file():
        ext = path.suffix.lower()
        if ext == ".dmg":
            return "dmg"
        elif ext in (".exe", ".msi"):
            return "exe"
        elif ext == ".json" and path.name == "package.json":
            return "bulk-npm"
        elif ext == ".txt" and path.name == "requirements.txt":
            return "bulk-pip"
    return "pip"


def _extract_resource_data(log_path: str) -> dict:
    """Extract resource monitoring data from strace log comments."""
    import json as _json
    try:
        content = Path(log_path).read_text(errors="replace")
        for line in content.splitlines():
            if line.startswith("# TRACE_TREE_RESOURCE_DATA:"):
                json_str = line.split(":", 1)[1].strip()
                return _json.loads(json_str)
    except Exception:
        pass
    return {}

def recursive_build_tree(tree_node: Tree, graph_json: dict, current_node_id: str):
    """Recursively walks the generated graph JSON to build the Rich Tree UI."""
    edges = [e for e in graph_json.get("edges", []) if e["data"]["source"] == current_node_id]
    
    # Resolve targets and their node types
    resolved_edges = []
    for edge in edges:
        target_id = edge["data"]["target"]
        target_node = next((n for n in graph_json.get("nodes", []) if n["data"]["id"] == target_id), None)
        if target_node:
            resolved_edges.append((edge, target_node))
            
    # Group by node type
    processes = []
    networks = []
    files = []
    others = []
    
    for edge, node in resolved_edges:
        ntype = node["data"].get("type")
        if ntype == "process":
            processes.append((edge, node))
        elif ntype == "network":
            networks.append((edge, node))
        elif ntype == "file":
            files.append((edge, node))
        else:
            others.append((edge, node))
            
    # 1. Process processes first (structural, show all, recursively walk)
    for edge, node in processes:
        label = edge["data"]["label"]
        node_label = node["data"]["label"]
        branch_text = f"[bold magenta]{node_label}[/] [dim]({label})[/]"
        child_branch = tree_node.add(branch_text)
        recursive_build_tree(child_branch, graph_json, node["data"]["id"])
        
    # 2. Process networks (limit to 5)
    max_network = 5
    for edge, node in networks[:max_network]:
        label = edge["data"]["label"]
        node_label = node["data"]["label"]
        branch_text = f"[bold red]{node_label}[/] [dim red]({label})[/]"
        tree_node.add(branch_text)
    if len(networks) > max_network:
        tree_node.add(f"[dim red]... and {len(networks) - max_network} more network connections[/]")
        
    # 3. Process files (limit to 5)
    max_file = 5
    for edge, node in files[:max_file]:
        label = edge["data"]["label"]
        node_label = node["data"]["label"]
        branch_text = f"[white]{node_label}[/] [dim white]({label})[/]"
        tree_node.add(branch_text)
    if len(files) > max_file:
        tree_node.add(f"[dim white]... and {len(files) - max_file} more file accesses[/]")
        
    # 4. Process other nodes (limit to 5)
    max_other = 5
    for edge, node in others[:max_other]:
        label = edge["data"]["label"]
        node_label = node["data"]["label"]
        branch_text = f"{node_label} ({label})"
        tree_node.add(branch_text)
    if len(others) > max_other:
        tree_node.add(f"[dim]... and {len(others) - max_other} other events[/]")


def build_cascade_tree(target: str, target_type: str, graph_json: dict) -> Tree:
    if target_type == "pip":
        root_text = f"[bold magenta]pip install {target}[/]"
    else:
        root_text = f"[bold white]Analyzing {target}[/]"

    tree = Tree(root_text)
    
    # We find root processes (those with no incoming clone/fork/execve edges)
    all_targets = set(e["data"]["target"] for e in graph_json.get("edges", []))
    roots = [n for n in graph_json.get("nodes", []) if n["data"]["type"] == "process" and n["data"]["id"] not in all_targets]
    
    if not roots and graph_json.get("nodes"):
        roots = [n for n in graph_json.get("nodes", []) if n["data"]["type"] == "process"]
        
    for root_node in roots:
        root_id = root_node["data"]["id"]
        label = root_node["data"]["label"]
        
        branch = tree.add(f"[bold magenta]{label}[/] [dim](root)[/]")
        recursive_build_tree(branch, graph_json, root_id)

    if not graph_json.get("nodes"):
        tree.add("[dim italic]No execution graph constructed (Log empty or analysis failed)[/]")
        
    return tree

def perform_analysis(target: str, target_type: str, progress, console, workspace_root: str = None, controlled_network: bool = False) -> Tuple[bool, float, dict, dict, list, list, list, dict]:
    """Helper to run the full sandbox → parse → graph → ML pipeline for a single target.

    Returns:
        (is_malicious, confidence, graph_data, parsed_data, signature_matches, temporal_patterns, yara_matches, ngram_data)
    """
    from sandbox.sandbox import run_sandbox
    from monitor.parser import parse_strace_log
    from monitor.signatures import load_signatures, match_signatures
    from monitor.timeline import detect_temporal_patterns
    from monitor.yara import scan_with_yara
    from monitor.ngrams import extract_ngrams, detect_suspicious_ngrams
    from graph.builder import build_cascade_graph
    from ml.detector import detect_anomaly

    log_path = None
    parsed_data = None
    graph_data = None
    is_malicious = False
    confidence = 0.0
    signature_matches: list = []
    temporal_patterns: list = []
    yara_matches: list = []
    ngram_data: dict = {}

    task1 = progress.add_task(f"[yellow]Sandboxing {target} ({target_type})...", total=None)
    log_path = run_sandbox(target, target_type, workspace_root=workspace_root, controlled_network=controlled_network)
    if log_path and Path(log_path).exists():
        progress.update(task1, description=f"[bold green]✔[/] [dim]Sandbox complete: {Path(log_path).name}[/]")
    else:
        progress.update(task1, description=f"[bold red]✖[/] [dim]Sandbox failed for {target}.[/]")
        return False, 0.0, {}, {}, [], [], {}, {}

    task2 = progress.add_task(f"[yellow]Parsing {target}...", total=None)
    try:
        parsed_data = parse_strace_log(log_path)
        progress.update(task2, description=f"[bold green]✔[/] [dim]Parsed {len(parsed_data.get('events', []))} events[/]")

        # Extract resource data from log comments
        resource_data = _extract_resource_data(log_path)
        if resource_data:
            parsed_data.setdefault("stats", {}).update(resource_data)
    except Exception as e:
        progress.update(task2, description=f"[bold red]✖[/] [dim]Parser failed: {e}[/]")
        return False, 0.0, {}, {}, [], [], {}, {}

    # ── Signature matching (best-effort, doesn't block on failure) ──
    try:
        sigs = load_signatures()
        if sigs:
            signature_matches = match_signatures(parsed_data, sigs)
            if signature_matches:
                console.print(f"[dim italic]  🎯 {len(signature_matches)} behavioral signature(s) matched[/]")
    except Exception as e:
        console.print(f"[dim]  Signature matching skipped: {e}[/]")

    # ── Temporal pattern detection (best-effort) ──
    try:
        if parsed_data.get("has_timestamps"):
            temporal_patterns = detect_temporal_patterns(parsed_data)
            if temporal_patterns:
                console.print(f"[dim italic]  ⏱️  {len(temporal_patterns)} temporal pattern(s) detected[/]")
    except Exception as e:
        console.print(f"[dim]  Temporal analysis skipped: {e}[/]")

    # ── YARA rule scanning (best-effort) ──
    try:
        yara_matches = scan_with_yara(log_path=log_path)
        if yara_matches:
            console.print(f"[dim italic]  🔍 {len(yara_matches)} YARA rule(s) matched[/]")
    except Exception as e:
        console.print(f"[dim]  YARA scanning skipped: {e}[/]")

    # ── Syscall N-gram Fingerprinting (best-effort) ──
    try:
        ngram_data = extract_ngrams(log_path, n=3)
        suspicious_ng = detect_suspicious_ngrams(ngram_data)
        if suspicious_ng:
            console.print(f"[dim italic]  🧬 {len(suspicious_ng)} suspicious n-gram pattern(s) detected[/]")
            # Inject into parsed_data stats for downstream use
            parsed_data.setdefault("stats", {})["suspicious_ngram_count"] = len(suspicious_ng)
            parsed_data.setdefault("stats", {})["ngram_fingerprint"] = ngram_data.get("fingerprint", "")
    except Exception as e:
        console.print(f"[dim]  N-gram fingerprinting skipped: {e}[/]")

    # Inject temporal pattern count into graph stats for the ML detector
    if parsed_data and "stats" not in parsed_data:
        parsed_data["stats"] = {}
    if parsed_data:
        parsed_data.setdefault("stats", {})["temporal_pattern_count"] = len(temporal_patterns)

    task3 = progress.add_task(f"[yellow]Graphing {target}...", total=None)
    try:
        graph_data = build_cascade_graph(parsed_data, signature_matches)
        progress.update(task3, description=f"[bold green]✔[/] [dim]Graph mapped[/]")
    except Exception as e:
        progress.update(task3, description=f"[bold red]✖[/] [dim]Graph failed: {e}[/]")
        return False, 0.0, {}, parsed_data, signature_matches, temporal_patterns, yara_matches, ngram_data

    task4 = progress.add_task(f"[yellow]Detecting {target}...", total=None)
    try:
        is_malicious, confidence = detect_anomaly(graph_data, parsed_data)
        progress.update(task4, description="[bold green]✔[/] [dim]Detection complete[/]")
    except Exception as e:
        progress.update(task4, description=f"[bold red]✖[/] [dim]ML failed: {e}[/]")
        return False, 0.0, graph_data, parsed_data, signature_matches, temporal_patterns, yara_matches, ngram_data

    return is_malicious, confidence, graph_data, parsed_data, signature_matches, temporal_patterns, yara_matches, ngram_data

def send_gui_telemetry(event: str, payload: dict):
    import urllib.request
    import json
    try:
        url = "http://localhost:3000/api/telemetry"
        data = json.dumps({"event": event, "payload": payload}).encode("utf-8")
        req = urllib.request.Request(
            url, 
            data=data, 
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=2) as response:
            pass
    except Exception:
        pass

@app.command()
def analyze(
    target: str = typer.Argument(..., help="Package name, bulk file, or installer"),
    type: str = typer.Option(None, "--type", "-t", help="Force 'pip', 'npm', 'dmg', 'exe', or 'bulk'"),
    url: str = typer.Option(None, "--url", "-u", help="Optional URL for private dependencies"),
    sarif: str = typer.Option(None, "--sarif", "-s", help="Output SARIF report to this file path"),
    gui: bool = typer.Option(False, "--gui", "-g", help="Send analysis telemetry to running GUI dashboard"),
    ai: bool = typer.Option(False, "--ai", help="Use local AI (Ollama + Qwen2.5-Coder) to verify findings."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Dry-run mode to print raw LLM prompts/responses"),
    controlled_network: bool = typer.Option(False, "--controlled-network", help="Enable controlled network/sinkhole mode (do not fully disconnect eth0)."),
):
    """Run a behavioral cascade analysis on a suspicious target."""
    check_docker_preflight()

    # Pre-flight: build orchestrator once and reuse it in the analysis block (Issue 1 fix)
    orchestrator = None
    if ai:
        try:
            from orchestrator.ai_mesh import AIMeshOrchestrator
            orchestrator = AIMeshOrchestrator(dry_run=dry_run, verbose=dry_run)
            orchestrator.check_connection_health()
        except Exception as e:
            # output a CONNECTION_ERROR block to the console
            console.print("\n")
            console.print(Panel(
                f"[bold red]❌ CONNECTION_ERROR[/]\n\n"
                f"Failed to connect to local Ollama API on port 11434.\n"
                f"Error: {e}\n\n"
                f"Please verify that Ollama is running and the model [bold]qwen2.5-coder:7b[/] is pulled.\n"
                f"Run: [bold]ollama serve[/] to start the server.",
                title="[bold red]Orchestrator Health Check Failed[/]",
                border_style="red",
                expand=False
            ))
            # instead of defaulting to a "MALICIOUS" verdict
            raise typer.Exit(1)

    target_type = type if type else determine_target_type(target)

    console.print(Panel.fit(
        f"[bold cyan]TraceTree Security Analyzer[/]\n"
        f"Target: [bold yellow]{target}[/]\n"
        f"Analyzer Type: [bold green]{target_type.upper()}[/]",
        border_style="cyan"
    ))

    targets_to_analyze = []
    if target_type == "bulk":
        if Path(target).exists():
            with open(target, 'r') as f:
                targets_to_analyze = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        else:
            console.print(f"[bold red]Error:[/] Bulk file {target} not found.")
            return
        # Guess sub-type for bulk items
        sub_type = "npm" if "package.json" in target else "pip"
    elif target_type in ("bulk-pip", "bulk-npm"):
        sub_type = "pip" if "pip" in target_type else "npm"
        with open(target, 'r') as f:
            targets_to_analyze = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        target_type = "bulk"
    else:
        targets_to_analyze = [target]
        sub_type = target_type

    for current_target in targets_to_analyze:
        if gui:
            send_gui_telemetry("investigation_started", {
                "prompt": f"CLI Analysis: {current_target}",
                "userId": "CLI"
            })
            send_gui_telemetry("step_started", {
                "sessionId": "cli-session",
                "stepId": "sandbox",
                "name": "Sandbox Execution"
            })

        with Progress(
            SpinnerColumn("dots2", style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=False,
        ) as progress:
            is_malicious, confidence, graph_data, parsed_data, sig_matches, temp_patterns, yara_matches, ngram_data = perform_analysis(current_target, sub_type, progress, console, workspace_root=str(Path.cwd()), controlled_network=controlled_network)
            verdict = confidence
            risk_score = float(verdict.risk_score if hasattr(verdict, "risk_score") else verdict)
            ml_probability = verdict.ml_probability if hasattr(verdict, "ml_probability") else None
            reasons = list(verdict.reasons) if hasattr(verdict, "reasons") else []

        if not graph_data:
            if gui:
                send_gui_telemetry("step_completed", {
                    "sessionId": "cli-session",
                    "stepId": "sandbox",
                    "status": "failed"
                })
                send_gui_telemetry("investigation_completed", {
                    "verdict": "ERROR",
                    "confidence_score": 0.0,
                    "durationMs": 0,
                    "error": "Analysis failed to produce graph data"
                })
            continue

        if gui:
            send_gui_telemetry("step_completed", {
                "sessionId": "cli-session",
                "stepId": "sandbox",
                "status": "completed"
            })
            send_gui_telemetry("step_started", {
                "sessionId": "cli-session",
                "stepId": "analysis",
                "name": "Behavioral Analysis"
            })

        console.print("\n")
        console.print(Panel(
            build_cascade_tree(current_target, sub_type, graph_data),
            title=f"[bold]Cascade Graph: {current_target}[/]",
            border_style="magenta",
            expand=False
        ))

        # ── Flagged Behaviors (raw parser flags) ──
        flags = parsed_data.get("flags", [])
        behaviors_str = "\n".join([f"[bold red]•[/] {f}" for f in flags]) if flags else "[dim green]No suspicious footprints flagged.[/]"
        print_panel_with_trim(console, behaviors_str, title="[bold]Flagged Behaviors[/]", border_style="red" if flags else "green")

        # ── Behavioral Signatures (matched patterns) ──
        if sig_matches:
            sig_lines = []
            for sig in sig_matches:
                sev = sig["severity"]
                sev_icon = "🔴" if sev >= 8 else "🟡" if sev >= 5 else "🟢"
                evid_summary = "; ".join(sig["evidence"][:2])
                if len(sig["evidence"]) > 2:
                    evid_summary += f" (+{len(sig['evidence']) - 2} more)"
                sig_lines.append(f"{sev_icon} [bold]{sig['name']}[/] (severity {sev}/10) — {sig['description']}")
                sig_lines.append(f"   [dim]{evid_summary}[/]")
            sig_text = "\n".join(sig_lines)
            console.print(Panel(
                sig_text,
                title="[bold]⚠ Behavioral Signatures Matched[/]",
                border_style="yellow",
                expand=False,
            ))

        # ── Temporal Execution Patterns ──
        if temp_patterns:
            from monitor.timeline import summarize_patterns
            console.print(Panel(
                Text.from_ansi(summarize_patterns(temp_patterns)),
                title="[bold]⏱️  Temporal Execution Patterns[/]",
                border_style="cyan",
                expand=False,
            ))

        # ── YARA Rule Matches ──
        if yara_matches:
            yara_lines = []
            for ym in yara_matches:
                sev_icon = "🔴" if ym["severity"] == "critical" else "🟡" if ym["severity"] == "high" else "🟢"
                yara_lines.append(f"{sev_icon} [bold]{ym['rule_name']}[/] ({ym['severity']}) — {ym['description']}")
                yara_lines.append(f"   [dim]File: {ym['file_path']} | Matches: {', '.join(ym['matched_strings'][:3])}[/]")
            yara_text = "\n".join(yara_lines)
            console.print(Panel(
                yara_text,
                title="[bold]🔍 YARA Rule Matches[/]",
                border_style="yellow",
                expand=False,
            ))

        # ── Syscall N-gram Fingerprints ──
        if ngram_data and ngram_data.get("top_ngrams"):
            from monitor.ngrams import detect_suspicious_ngrams
            suspicious_ng = detect_suspicious_ngrams(ngram_data)
            ng_lines = []
            ng_lines.append(f"[dim]Fingerprint: [/][bold cyan]{ngram_data.get('fingerprint', 'N/A')}[/]  "
                            f"[dim]| Total syscalls: [/][bold]{ngram_data.get('total_syscalls', 0)}[/]  "
                            f"[dim]| Unique trigrams: [/][bold]{ngram_data.get('unique_ngrams', 0)}[/]")
            if suspicious_ng:
                ng_lines.append("")
                ng_lines.append("[bold yellow]⚠ Suspicious n-gram patterns:[/]")
                for sg in suspicious_ng:
                    ng_lines.append(f"  🔴 {sg['ngram']} — {sg['description']} (count: {sg['count']})")
            ng_lines.append("")
            ng_lines.append("[dim]Top trigrams:[/]")
            for ng, cnt in ngram_data["top_ngrams"][:5]:
                ng_lines.append(f"  {ng} → {cnt}")
            ng_text = "\n".join(ng_lines)
            console.print(Panel(
                ng_text,
                title="[bold]🧬 Syscall N-gram Fingerprint[/]",
                border_style="magenta",
                expand=False,
            ))

        # ── AI-native Triage (Legs 1-4, 5 & 8) ──
        # Issues 1 & 2 fix: reuse pre-flight orchestrator; guard against silent verdict corruption.
        ai_triage_ran = False
        if ai and graph_data and orchestrator is not None:
            try:
                from orchestrator.ai_mesh import render_ai_triage_panel, TriageResult
                console.print("\n[bold cyan]🧠 Running AI-native triage logic (Qwen2.5-Coder)...[/]")
                # Reuse the already-health-checked orchestrator from the pre-flight block.
                # No second AIMeshOrchestrator construction; no second check_connection_health() call.

                # 1. Legs 1 & 2: Syscall Simplifier
                syscall_events = parsed_data.get("events", [])
                syscall_results = orchestrator.simplify_syscall_log(syscall_events)
                render_ai_triage_panel("Legs 1 & 2: Syscall Simplifier", syscall_results)

                # 2. Legs 3 & 4: Anomaly Feature Vector
                from ml.detector import map_features
                feature_vector = map_features(graph_data, parsed_data)
                sensor_names = [
                    "node_count", "edge_count", "network_connections", "file_reads",
                    "execve_count", "total_severity", "suspicious_networks",
                    "sensitive_files", "max_severity", "temporal_pattern_count"
                ]
                feature_dict = dict(zip(sensor_names, feature_vector))
                feature_results = orchestrator.describe_feature_vector(feature_dict)
                render_ai_triage_panel("Legs 3 & 4: Anomaly Feature Vector", feature_results)

                # 3. Legs 5 & 8: False Positive Jury
                all_sig_names = [m["name"] for m in sig_matches] if sig_matches else []
                matched_rule = {
                    "rule_name": all_sig_names[0] if all_sig_names else "ML_Anomaly_Detection",
                    "all_signatures": all_sig_names,
                    "temporal_patterns": [p.get("pattern", str(p)) for p in temp_patterns] if temp_patterns else [],
                    "severity": risk_score / 10.0 if risk_score else 5.0
                }
                package_metadata = {
                    "name": current_target,
                    "type": sub_type,
                    "total_severity": parsed_data.get("stats", {}).get("total_severity", 0.0),
                    "file_count": parsed_data.get("stats", {}).get("file_count", 0)
                }
                triage_results = orchestrator.triage_false_positive(matched_rule, package_metadata)

                render_ai_triage_panel("Legs 5 & 8: False Positive Jury", triage_results.__dict__)
                ai_triage_ran = True

                # Hard guard: LLM override only allowed when deterministic rules permit.
                # triage_false_positive() applies the primary guards; this is a defence-in-depth
                # check in case a new LLM or prompt change regresses the behaviour.
                if triage_results.is_false_positive():
                    console.print("[bold green]✔ AI False Positive Jury has OVERRIDDEN the verdict to CLEAN![/]")
                    is_malicious = False
                    risk_score = triage_results.confidence * 100.0
                    reasons.append(f"AI False Positive Jury override (confidence {triage_results.confidence * 100.0:.1f}%)")
            except Exception as e:
                import logging as _logging
                _logging.getLogger("tracetree.cli").exception("AI Triage failed")
                console.print(
                    f"[bold red]❌ AI Triage failed — verdict is based on static analysis only:[/] {e}"
                )

        # Issue 2 fix: surface a clear warning when --ai was requested but triage did not complete.
        if ai and not ai_triage_ran:
            console.print(
                "[bold yellow]⚠ WARNING: AI triage did not complete. "
                "Final verdict reflects static analysis only.[/]"
            )

        # ── Final Verdict ──
        if is_malicious:
            verdict_text = Text("\n  MALICIOUS  \n", style="bold white on red", justify="center")
            conf_style = "bold red"
        else:
            verdict_text = Text("\n  CLEAN  \n", style="bold white on green", justify="center")
            conf_style = "bold green"

        console.print(Align.center(Panel.fit(verdict_text, title="Final Verdict", border_style=conf_style.split()[-1])))
        if ml_probability is not None:
            console.print(Align.center(Text(f"ML Model Probability: {ml_probability:.1f}%", style="cyan")))
        console.print(Align.center(Text(f"Rule-based Risk Score: {risk_score:.1f}/100", style=conf_style)))
        
        if reasons:
            reasons_str = "\n".join([f"[bold red]•[/] {r}" for r in reasons])
            print_panel_with_trim(console, reasons_str, title="[bold]Verdict Logic / Risk Explanations[/]", border_style="yellow")

        # Summary line with both signatures and temporal patterns
        extras = []
        if sig_matches:
            extras.append(f"Signatures: {', '.join(m['name'] for m in sig_matches)}")
        if temp_patterns:
            extras.append(f"Temporal: {', '.join(p['pattern_name'] for p in temp_patterns)}")
        if yara_matches:
            extras.append(f"YARA: {', '.join(m['rule_name'] for m in yara_matches)}")
        if ngram_data and ngram_data.get("fingerprint"):
            extras.append(f"N-gram FP: {ngram_data['fingerprint']}")
        if extras:
            console.print(Align.center(Text(" | ".join(extras), style="dim yellow")))

        # ── SARIF Report Export ──
        if sarif:
            from monitor.sarif import generate_sarif_report
            sarif_path = sarif if len(targets_to_analyze) == 1 else f"{sarif}_{current_target}.json"
            try:
                sarif_json = generate_sarif_report(
                    target=current_target,
                    parsed_data=parsed_data,
                    graph_data=graph_data,
                    signature_matches=sig_matches,
                    temporal_patterns=temp_patterns,
                    yara_matches=yara_matches,
                    ngram_data=ngram_data,
                    is_malicious=is_malicious,
                    confidence=risk_score,
                    output_path=sarif_path,
                )
                console.print(f"[bold green]✔[/] [dim]SARIF report written to {sarif_path}[/]")
            except Exception as e:
                console.print(f"[bold red]✖[/] [dim]SARIF export failed: {e}[/]")

        console.print("\n" + "─" * console.width + "\n")

        # ── Container Resource Usage ──
        res_stats = parsed_data.get("stats", {})
        if res_stats.get("peak_memory_kb") or res_stats.get("disk_used_kb"):
            mem_mb = round(res_stats.get("peak_memory_kb", 0) / 1024, 1)
            disk_mb = round(res_stats.get("disk_used_kb", 0) / 1024, 1)
            file_count = res_stats.get("file_count", 0)
            res_text = (
                f"[dim]Peak memory:[/] [bold]{mem_mb} MB[/]  "
                f"[dim]| Disk used:[/] [bold]{disk_mb} MB[/]  "
                f"[dim]| Files installed:[/] [bold]{file_count}[/]"
            )
            console.print(Panel(
                res_text,
                title="[bold]📊 Container Resource Usage[/]",
                border_style="green",
                expand=False,
            ))

        if gui:
            import json as _json_helper
            from monitor.ngrams import detect_suspicious_ngrams
            suspicious_ng = detect_suspicious_ngrams(ngram_data) if (ngram_data and ngram_data.get("top_ngrams")) else []
            findings_dict = {
                "pid": current_target,
                "target_type": sub_type,
                "is_malicious": is_malicious,
                "confidence_score": risk_score,
                "total_severity": parsed_data.get("total_severity_score", 0.0),
                "flagged_behaviors": flags,
                "behavioral_signatures": [{
                    "name": s["name"],
                    "severity": s["severity"],
                    "description": s["description"],
                    "evidence": s["evidence"]
                } for s in sig_matches],
                "yara_matches": [{
                    "rule_name": y["rule_name"],
                    "severity": y["severity"],
                    "description": y["description"]
                } for y in yara_matches],
                "suspicious_ngrams": [s["ngram"] for s in suspicious_ng],
                "events": parsed_data.get("events", [])[:50],  # cap at 50 events
                "network_destinations": parsed_data.get("network_destinations", [])
            }
            send_gui_telemetry("step_completed", {
                "sessionId": "cli-session",
                "stepId": "analysis",
                "status": "completed",
                "findings": _json_helper.dumps(findings_dict)
            })
            send_gui_telemetry("investigation_completed", {
                "verdict": "MALICIOUS" if is_malicious else "CLEAN",
                "confidence_score": risk_score,
                "durationMs": 0
            })

def train_cli():
    """CLI entrypoint dynamically executing cascade-train"""
    from rich.prompt import Prompt
    from rich.text import Text
    from rich.align import Align
    import os
    import sys
    from pathlib import Path

    # Ensure project root is in path so we can dynamically import ingest scripts
    project_root = Path(__file__).parent.absolute()
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    console.print("\n")
    title = Text(" TRACETREE ONLINE TRAINING PIPELINE ", style="bold white on blue")
    desc = Text("\nConnect to MalwareBazaar, fetch live global malware, and train your behavioral model.", style="italic cyan")
    console.print(Align.center(Panel(title + desc, border_style="blue", expand=False)))
    console.print()

    auth_key = os.getenv("MALWAREBAZAAR_AUTH_KEY", "").strip()
    if not auth_key:
        console.print(Align.center(Panel(
            "[bold yellow]Authentication Required[/]\n\n"
            "To legitimately fetch live malware samples from the internet,\n"
            "you need a MalwareBazaar Auth Key.\n\n"
            "[dim]If you do not have one, you can press Enter to skip (model will train on the local malicious_packages.txt dataset only).[/]",
            border_style="yellow", expand=False
        )))
        console.print()
        
        auth_key = Prompt.ask("[bold magenta]Enter MalwareBazaar Auth Key[/]", password=True)
        if auth_key:
            os.environ["MALWAREBAZAAR_AUTH_KEY"] = auth_key
            console.print("\n[bold green]✔ Key accepted. Initiating online data ingestion...[/]\n")
        else:
            console.print("\n[dim italic]No key provided. Training on local malicious_packages.txt dataset...[/]\n")
    else:
        console.print("[bold green]✔ Found MALWAREBAZAAR_AUTH_KEY in environment. Initiating fetch...[/]\n")

    if auth_key:
        try:
            import ingest_malwarebazaar
            console.print(Panel("[bold cyan]Fetching Samples & Parsing Sandbox Footprints[/]", border_style="cyan", expand=False))
            ingest_malwarebazaar.main()
            console.print("\n[bold green]✔ Online sandbox ingestion complete![/]\n")
        except ImportError as e:
            console.print(f"[bold red]Could not find ingestion script:[/] {e}")
        except Exception as e:
            console.print(f"[bold red]Failed to fetch from MalwareBazaar:[/] {e}")

    console.print(Align.center(Panel("[bold magenta]Training Random Forest ML Model[/]", border_style="magenta", expand=False)))
    
    from ml.trainer import train_model
    train_model()


@app.command()
def mcp(
    npm: str = typer.Option(None, "--npm", "-n", help="NPM package name (e.g. @modelcontextprotocol/server-github)"),
    path: str = typer.Option(None, "--path", "-p", help="Local path to an MCP server project"),
    allow_network: bool = typer.Option(False, "--allow-network", help="Allow outbound network from the sandbox"),
    transport: str = typer.Option(None, "--transport", "-t", help="Force transport: 'stdio' or 'http'"),
    port: int = typer.Option(3000, "--port", help="Port for HTTP/SSE transport"),
    output: str = typer.Option("report", "--output", "-o", help="Output format: 'report' (Rich console) or 'json'"),
    tool_delay: float = typer.Option(2.0, "--delay", help="Seconds between tool calls during analysis"),
    timeout: int = typer.Option(60, "--timeout", help="Maximum seconds for the analysis session"),
):
    """
    Run an MCP (Model Context Protocol) server security analysis.

    Spins up the server inside a Docker sandbox, acts as a simulated MCP
    client, invokes every discovered tool with safe synthetic arguments and
    adversarial probes, then classifies the behavioral trace for threats.
    """
    check_docker_preflight()

    # Resolve target
    if npm:
        target = npm
        target_type = "npm"
    elif path:
        target = path
        target_type = "local"
        if not Path(path).exists():
            console.print(f"[bold red]Error:[/] Local path not found: {path}")
            raise typer.Exit(1)
    else:
        console.print("[bold red]Error:[/] Provide either --npm <package> or --path <directory>.")
        raise typer.Exit(1)

    console.print(Panel.fit(
        f"[bold cyan]TraceTree MCP Security Analyzer[/]\n"
        f"Target: [bold yellow]{target}[/]\n"
        f"Transport: [bold green]{(transport or 'auto').upper()}[/]\n"
        f"Network: [bold {'green' if allow_network else 'red'}]{'allowed' if allow_network else 'blocked'}[/]",
        border_style="cyan",
    ))
    console.print()

    from mcp.sandbox import run_mcp_sandbox
    from mcp.client import MCPClient
    from mcp.features import extract_mcp_features, detect_server_type
    from mcp.classifier import classify_mcp_threats, compute_risk_score
    from mcp.report import generate_mcp_report
    from monitor.parser import parse_strace_log
    from graph.builder import build_cascade_graph
    from ml.detector import detect_anomaly

    # Step 1 — Sandbox
    with Progress(
        SpinnerColumn("dots2", style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(f"[yellow]Sandboxing MCP server: {target}...", total=None)
        log_path = run_mcp_sandbox(
            target=target,
            target_type=target_type,
            allow_network=allow_network,
            port=port,
            transport=transport or "stdio",
            timeout=timeout,
        )
        if log_path and Path(log_path).exists():
            progress.update(task, description=f"[bold green]✔[/] [dim]Sandbox complete: {Path(log_path).name}[/]")
        else:
            progress.update(task, description=f"[bold red]✖[/] [dim]Sandbox failed.[/]")
            console.print("\n[bold red]Analysis aborted — sandbox did not produce a trace log.[/]")
            raise typer.Exit(1)

    # Step 2 — Parse strace (existing pipeline)
    with Progress(
        SpinnerColumn("dots2", style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("[yellow]Parsing strace log...", total=None)
        try:
            parsed_data = parse_strace_log(log_path)
            progress.update(task, description=f"[bold green]✔[/] [dim]Parsed {len(parsed_data.get('events', []))} events[/]")
        except Exception as e:
            progress.update(task, description=f"[bold red]✖[/] [dim]Parser failed: {e}[/]")
            parsed_data = {"events": [], "flags": [], "processes": {}}

    # Step 3 — Build graph (existing pipeline)
    graph_data = {}
    is_malicious = False
    ml_confidence = 0.0
    try:
        graph_data = build_cascade_graph(parsed_data)
        is_malicious, ml_confidence = detect_anomaly(graph_data, parsed_data)
    except Exception:
        pass

    # Step 4 — MCP client simulation (connect, discover tools, invoke, probe)
    console.print("\n")
    console.print(Panel("[bold magenta]Simulating MCP Client — Handshake, Tool Discovery & Invocation[/]", border_style="magenta", expand=False))

    mcp_client = MCPClient(
        transport=transport,
        port=port,
        tool_delay=tool_delay,
    )

    # Attempt connection and tool discovery
    connected = mcp_client.connect()
    if connected:
        tools = mcp_client.discover_tools()
        console.print(f"[bold green]✔[/] Discovered [bold]{len(tools)}[/] tool(s)")

        # Invoke all tools with safe synthetic arguments
        console.print("[cyan]Invoking tools with safe synthetic arguments...[/]")
        mcp_client.invoke_all_tools()
        console.print(f"[bold green]✔[/] Invoked [bold]{len(mcp_client.call_log)}[/] tool call(s)")

        # Run adversarial probes
        console.print("[yellow]Running adversarial injection probes...[/]")
        mcp_client.run_adversarial_probes()
        console.print(f"[bold green]✔[/] Sent [bold]{len(mcp_client.adversarial_log)}[/] adversarial probe(s)")
    else:
        console.print("[bold yellow]⚠ Could not connect to MCP server (expected in stdio sandbox mode). "
                       "Analysis based on strace trace only.[/]")
        tools = []

    mcp_client.close()

    # Step 5 — Extract MCP-specific features
    console.print("\n")
    console.print(Panel("[bold yellow]Extracting MCP-Specific Features from Syscall Trace[/]", border_style="yellow", expand=False))

    server_type = detect_server_type(target, [t.get("description", "") for t in tools])
    if server_type:
        console.print(f"[dim]Detected server type: [bold]{server_type}[/][/dim]")

    features = extract_mcp_features(
        log_path=log_path,
        call_log=mcp_client.call_log,
        adversarial_log=mcp_client.adversarial_log,
        server_type=server_type,
    )

    # Step 6 — Classify threats
    console.print("\n")
    console.print(Panel("[bold red]Running Rule-Based Threat Classification[/]", border_style="red", expand=False))

    threats = classify_mcp_threats(
        features=features,
        prompt_injection_findings=mcp_client.prompt_injection_findings,
        adversarial_log=mcp_client.adversarial_log,
        server_type=server_type,
    )
    risk_score = compute_risk_score(threats)

    baseline_comparison = features.get("baseline_comparison", {})

    # Step 7 — Generate report
    console.print("\n")
    report_output = generate_mcp_report(
        target=target,
        server_type=server_type,
        tools=tools,
        features=features,
        threats=threats,
        prompt_injection_findings=mcp_client.prompt_injection_findings,
        adversarial_log=mcp_client.adversarial_log,
        risk_score=risk_score,
        baseline_comparison=baseline_comparison,
        is_malicious=is_malicious,
        ml_confidence=ml_confidence,
        output_format=output,
    )

    if output == "json" and report_output:
        console.print(report_output)


# ------------------------------------------------------------------ #
#  Session guardian — watch & check commands
# ------------------------------------------------------------------ #

_SESSION_DIR = Path("/tmp/tracetree_sessions")


def _run_analysis_for_diff(target: str, target_type: str, progress, console, workspace_root: str = None) -> Dict[str, Any]:
    """Run analysis and return a dict suitable for diff comparison."""
    is_malicious, confidence, graph_data, parsed_data, sig_matches, temp_patterns, yara_matches, ngram_data = perform_analysis(target, target_type, progress, console, workspace_root=workspace_root)
    return {
        "parsed_data": parsed_data,
        "graph_data": graph_data,
        "signature_matches": sig_matches,
        "temporal_patterns": temp_patterns,
        "yara_matches": yara_matches,
        "ngram_data": ngram_data,
        "is_malicious": is_malicious,
        "confidence": confidence,
    }


def _get_session_lock_path(repo_path: Path) -> Path:
    """Return the lockfile path for a given repo directory."""
    import hashlib
    _SESSION_DIR.mkdir(parents=True, exist_ok=True)
    name_hash = hashlib.md5(str(repo_path.resolve()).encode()).hexdigest()[:12]
    return _SESSION_DIR / f"{name_hash}.pid"


def _acquire_session_lock(repo_path: Path) -> Optional[Path]:
    """
    Try to acquire a session lock using atomic file creation.
    Returns the lockfile path on success, or None if another session
    is already running for this repo.
    """
    lock = _get_session_lock_path(repo_path)

    # First check: if lock exists and process is alive, bail out
    if lock.exists():
        try:
            pid = int(lock.read_text().strip())
            os.kill(pid, 0)  # process still exists
            return None
        except (ProcessLookupError, ValueError, PermissionError):
            # Stale lockfile — clean it up and proceed to atomic acquire
            lock.unlink(missing_ok=True)

    # Atomic acquire: O_CREAT | O_EXCL ensures only one process succeeds
    try:
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(fd, 'w') as f:
            f.write(str(os.getpid()))
        return lock
    except FileExistsError:
        # Another process won the race — check if it's still alive
        try:
            pid = int(lock.read_text().strip())
            os.kill(pid, 0)
            return None
        except (ProcessLookupError, ValueError, PermissionError, FileNotFoundError):
            # Stale lock from the race winner — clean up and retry once
            lock.unlink(missing_ok=True)
            try:
                fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                with os.fdopen(fd, 'w') as f:
                    f.write(str(os.getpid()))
                return lock
            except FileExistsError:
                return None


def _release_session_lock(repo_path: Path) -> None:
    """Remove the session lockfile."""
    lock = _get_session_lock_path(repo_path)
    lock.unlink(missing_ok=True)


def _show_spider(console: Console, spider, state: str = "idle"):
    """Render the spider mascot in a small panel above the main output."""
    spider.set_state(state)
    art = spider.render().strip()
    console.print(Align.center(Panel(
        Text(art, style="cyan"),
        border_style="green",
        padding=(0, 2),
    )))
    console.print()


@app.command()
def watch(
    repo: str = typer.Argument(
        ...,
        help="Local repo path or Git URL to watch.",
    ),
    check: str = typer.Option(
        None,
        "--check", "-c",
        help="On-demand deep scan of a specific file or command.",
    ),
    output: str = typer.Option(
        "report",
        "--output", "-o",
        help="Output format: 'report' (Rich console) or 'json'.",
    ),
):
    """
    Run the TraceTree session guardian on a repository.

    Starts a background sandbox analysis and displays live status updates
    with the spider mascot keeping watch.  Press Ctrl+C to stop.
    """
    check_docker_preflight()

    # Resolve repo path
    repo_path = Path(repo)
    repo_url = None
    if not repo_path.exists():
        # Assume it's a URL — for now treat the URL itself as a label
        repo_url = repo
        repo_path = Path.cwd()
        console.print(f"[dim]Treating '{repo}' as remote label; watching current directory.[/]")

    # Acquire session lock
    lock_path = _acquire_session_lock(repo_path)
    if lock_path is None:
        console.print(Panel(
            f"[bold yellow]A watcher is already active for this directory.[/]\n"
            f"Path: [dim]{repo_path}[/]\n\n"
            f"Use [bold]cascade-check {check}[/] to send an on-demand scan, "
            f"or stop the existing watcher first.",
            title="[bold]Session Already Running[/]",
            border_style="yellow",
            expand=False,
        ))
        return

    from watcher.session import SessionWatcher
    from mascot.spider import SpiderMascot

    spider = SpiderMascot()
    watcher = SessionWatcher(str(repo_path), repo_url=repo_url)

    # Show spider mascot
    _show_spider(console, spider, "idle")

    console.print(Panel(
        f"[bold cyan]TraceTree is watching this session…[/]\n"
        f"Repo: [bold]{repo_path}[/]",
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()

    watcher.start()

    # Handle optional on-demand check
    if check is not None:
        spider.set_state("scanning")
        _show_spider(console, spider, "scanning")
        console.print(Panel(
            f"[bold yellow]On-demand scan:[/] {check}",
            border_style="yellow",
            expand=False,
        ))
        result = watcher.check_path(check)
        if result.get("error"):
            console.print(f"[bold red]Error:[/] {result['error']}")
        else:
            is_mal = result.get("malicious", False)
            conf = result.get("confidence", 0.0)
            threats = result.get("threats", [])

            if is_mal:
                verdict_text = Text("\n  MALICIOUS  \n", style="bold white on red", justify="center")
                conf_style = "bold red"
            else:
                verdict_text = Text("\n  CLEAN  \n", style="bold white on green", justify="center")
                conf_style = "bold green"

            console.print(Align.center(Panel.fit(verdict_text, title="Final Verdict", border_style=conf_style.split()[-1])))
            console.print(Align.center(Text(f"Confidence Score: {conf}%", style=conf_style)))

            if threats:
                behaviors_str = "\n".join([f"[bold red]•[/] {f}" for f in threats])
                print_panel_with_trim(console, behaviors_str, title="[bold]Flagged Behaviors[/]", border_style="red")

        console.print()

    # Main live-status loop
    try:
        while True:
            status = watcher.get_status()
            phase = status.get("phase", "unknown")

            if phase in ("done", "error", "stopped"):
                break

            phase_icons = {
                "idle": "⏸",
                "cloning": "📥",
                "sandboxing": "🔒",
                "analyzing": "🔍",
            }
            icon = phase_icons.get(phase, "⏳")

            threats_count = len(status.get("threats", []))
            conf = status.get("confidence", 0.0)
            mal = status.get("malicious", False)

            status_line = (
                f"[bold cyan]{icon}[/] Phase: [bold]{phase}[/]  "
                f"Threats: [bold]{threats_count}[/]  "
                f"Confidence: [bold]{conf:.1f}%[/]"
            )
            if mal:
                status_line += "  [bold red]⚠ MALICIOUS[/]"

            console.print(status_line)
            time.sleep(2)

    except KeyboardInterrupt:
        console.print("\n[dim]Stopping watcher…[/]")

    finally:
        watcher.stop()
        _release_session_lock(repo_path)

    # Final verdict
    final = watcher.get_status()
    phase = final.get("phase", "unknown")
    is_malicious = final.get("malicious", False)
    confidence = final.get("confidence", 0.0)
    threats = final.get("threats", [])

    if is_malicious:
        verdict_text = Text("\n  MALICIOUS  \n", style="bold white on red", justify="center")
        conf_style = "bold red"
        _show_spider(console, spider, "warning")
    else:
        verdict_text = Text("\n  CLEAN  \n", style="bold white on green", justify="center")
        conf_style = "bold green"
        _show_spider(console, spider, "success")

    console.print(Align.center(Panel.fit(verdict_text, title="Final Verdict", border_style=conf_style.split()[-1])))
    console.print(Align.center(Text(f"Confidence Score: {confidence}%", style=conf_style)))

    if threats:
        behaviors_str = "\n".join([f"[bold red]•[/] {f}" for f in threats])
        print_panel_with_trim(console, behaviors_str, title="[bold]Flagged Behaviors[/]", border_style="red" if threats else "green")

    if phase == "error":
        console.print(f"[bold red]Error:[/] {final.get('error', 'Unknown error')}")

    console.print("\n" + "─" * console.width + "\n")


@app.command(name="check")
def check(
    file_or_command: str = typer.Argument(..., help="File path or command to check."),
    output: str = typer.Option(
        "report",
        "--output", "-o",
        help="Output format: 'report' (Rich console) or 'json'.",
    ),
    controlled_network: bool = typer.Option(False, "--controlled-network", help="Enable controlled network/sinkhole mode (do not fully disconnect eth0)."),
):
    """
    Quick on-demand scan of a specific file or command.

    If a SessionWatcher is already running for the current directory
    (via lockfile), sends the check request to it.  Otherwise starts
    a quick one-off analysis.
    """
    check_docker_preflight()

    from mascot.spider import SpiderMascot

    spider = SpiderMascot()
    _show_spider(console, spider, "scanning")

    repo_path = Path.cwd()
    lock_path = _get_session_lock_path(repo_path)

    if lock_path.exists():
        console.print(
            Panel(
                f"[bold cyan]Forwarding check to active session watcher…[/]\n"
                f"Target: [bold]{file_or_command}[/]",
                border_style="cyan",
                expand=False,
            )
        )
        # In a full implementation we'd use IPC (e.g. a Unix socket or
        # a small HTTP endpoint) to send the check to the running watcher.
        # For now, fall through to a one-off scan.
        console.print("[dim italic](IPC not yet implemented — running one-off scan instead)[/]")

    console.print()
    console.print(Panel(
        f"[bold yellow]Quick check:[/] {file_or_command}",
        border_style="yellow",
        expand=False,
    ))

    # One-off analysis
    target_path = Path(file_or_command)
    if not target_path.is_absolute():
        target_path = repo_path / file_or_command

    ext = target_path.suffix.lower()
    if ext == ".dmg":
        target_type = "dmg"
    elif ext in (".exe", ".msi"):
        target_type = "exe"
    elif target_path.name == "requirements.txt":
        target_type = "pip"
    elif target_path.name == "package.json":
        target_type = "npm"
    elif ext in (".sh", ".bash") or (target_path.is_file() and not ext):
        target_type = "shell"
    else:
        target_type = "pip"

    log_path = run_sandbox(str(target_path), target_type, workspace_root=str(repo_path), controlled_network=controlled_network)
    if not log_path or not Path(log_path).exists():
        console.print("[bold red]Error:[/] Sandbox failed — check that Docker is running.")
        return

    from monitor.parser import parse_strace_log
    from graph.builder import build_cascade_graph
    from ml.detector import detect_anomaly

    parsed = parse_strace_log(log_path)
    graph = build_cascade_graph(parsed)
    verdict = detect_anomaly(graph, parsed)
    is_malicious = verdict.is_malicious
    risk_score = float(verdict.risk_score if hasattr(verdict, "risk_score") else verdict)
    ml_probability = verdict.ml_probability if hasattr(verdict, "ml_probability") else None
    reasons = list(verdict.reasons) if hasattr(verdict, "reasons") else []

    if is_malicious:
        verdict_text = Text("\n  MALICIOUS  \n", style="bold white on red", justify="center")
        conf_style = "bold red"
        spider.set_state("warning")
    else:
        verdict_text = Text("\n  CLEAN  \n", style="bold white on green", justify="center")
        conf_style = "bold green"
        spider.set_state("success")

    _show_spider(console, spider, spider.state)

    console.print(Align.center(Panel.fit(verdict_text, title="Final Verdict", border_style=conf_style.split()[-1])))
    if ml_probability is not None:
        console.print(Align.center(Text(f"ML Model Probability: {ml_probability:.1f}%", style="cyan")))
    console.print(Align.center(Text(f"Rule-based Risk Score: {risk_score:.1f}/100", style=conf_style)))
    if reasons:
        reasons_str = "\n".join([f"[bold red]•[/] {r}" for r in reasons])
        print_panel_with_trim(console, reasons_str, title="[bold]Verdict Logic / Risk Explanations[/]", border_style="yellow")

    flags = parsed.get("flags", [])
    if flags:
        behaviors_str = "\n".join([f"[bold red]•[/] {f}" for f in flags])
        print_panel_with_trim(console, behaviors_str, title="[bold]Flagged Behaviors[/]", border_style="red")

    console.print("\n" + "─" * console.width + "\n")


@app.command(name="install-hook")
def install_hook_cmd(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt")
):
    """
    Install the TraceTree shell hook.

    Automatically detects your shell (bash/zsh), copies the hook script
    to ~/.local/share/tracetree/hooks/, and appends a `source` line
    to ~/.bashrc or ~/.zshrc.
    """
    hooks_dir = Path(__file__).parent / "hooks"
    install_script = hooks_dir / "install_hook.py"

    if not install_script.exists():
        console.print(f"[bold red]Error:[/] Install script not found at {install_script}")
        raise typer.Exit(1)

    # Run the Python installer in-process
    sys.path.insert(0, str(hooks_dir))
    try:
        from install_hook import install_hook as _do_install
        ok = _do_install(yes=yes)
        if not ok:
            raise typer.Exit(1)
    except Exception as exc:
        console.print(f"[bold red]Install failed:[/] {exc}")
        raise typer.Exit(1)


@app.command(name="uninstall-hook")
def uninstall_hook_cmd(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt")
):
    """
    Uninstall the TraceTree shell hook.
    """
    hooks_dir = Path(__file__).parent / "hooks"
    sys.path.insert(0, str(hooks_dir))
    try:
        from install_hook import uninstall_hook as _do_uninstall
        ok = _do_uninstall(yes=yes)
        if not ok:
            raise typer.Exit(1)
    except Exception as exc:
        console.print(f"[bold red]Uninstall failed:[/] {exc}")
        raise typer.Exit(1)


@app.command(name="diff")
def diff_cmd(
    target_a: str = typer.Argument(..., help="Baseline package name or file."),
    target_b: str = typer.Argument(..., help="Candidate package name or file to compare against baseline."),
    type_a: str = typer.Option(None, "--type-a", help="Force type for baseline (pip/npm/dmg/exe)."),
    type_b: str = typer.Option(None, "--type-b", help="Force type for candidate (pip/npm/dmg/exe)."),
):
    """
    Compare the behavioral analysis of two packages.

    Runs both targets through the sandbox pipeline and produces a
    behavioral diff highlighting added/removed syscalls, network
    destinations, file accesses, and signature matches.
    """
    check_docker_preflight()

    type_a = type_a or determine_target_type(target_a)
    type_b = type_b or determine_target_type(target_b)

    console.print(Panel.fit(
        f"[bold cyan]TraceTree Behavioral Diff[/]\n"
        f"Baseline: [bold yellow]{target_a}[/] ({type_a})\n"
        f"Candidate: [bold yellow]{target_b}[/] ({type_b})",
        border_style="cyan",
    ))
    console.print()

    from monitor.diff import diff_analysis

    # Analyze baseline
    console.print(Panel("[bold magenta]Analyzing baseline...[/]", border_style="magenta", expand=False))
    with Progress(
        SpinnerColumn("dots2", style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        result_a = _run_analysis_for_diff(target_a, type_a, progress, console, workspace_root=str(Path.cwd()))

    if not result_a.get("graph_data"):
        console.print("[bold red]Error:[/] Baseline analysis failed.")
        raise typer.Exit(1)

    # Analyze candidate
    console.print("\n")
    console.print(Panel("[bold magenta]Analyzing candidate...[/]", border_style="magenta", expand=False))
    with Progress(
        SpinnerColumn("dots2", style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        result_b = _run_analysis_for_diff(target_b, type_b, progress, console, workspace_root=str(Path.cwd()))

    if not result_b.get("graph_data"):
        console.print("[bold red]Error:[/] Candidate analysis failed.")
        raise typer.Exit(1)

    # Compute diff
    console.print("\n")
    console.print(Panel("[bold yellow]Computing behavioral diff...[/]", border_style="yellow", expand=False))

    diff = diff_analysis(result_a, result_b, label_a=target_a, label_b=target_b)

    # Display diff
    console.print("\n")
    console.print(Panel(diff["summary"], border_style="red" if diff["verdict"] == "suspicious" else "yellow" if diff["verdict"] == "divergent" else "green", expand=False))

    console.print(f"[dim]N-gram similarity: [bold]{diff['ngram_similarity']:.4f}[/][/dim]")
    console.print()

    if diff["details"]:
        detail_lines = []
        for d in diff["details"]:
            detail_lines.append(d)
        console.print(Panel(
            "\n".join(detail_lines),
            title="[bold]Diff Observations[/]",
            border_style="cyan",
            expand=False,
        ))

    # Show severity comparison
    sev = diff["severity_diff"]
    sev_text = (
        f"[dim]Total severity:[/] {sev['total_a']:.1f} → {sev['total_b']:.1f}  "
        f"[dim]| Max severity:[/] {sev['max_a']:.1f} → {sev['max_b']:.1f}"
    )
    console.print(Panel(sev_text, title="[bold]Severity Comparison[/]", border_style="magenta", expand=False))

    console.print("\n" + "─" * console.width + "\n")


@app.command(name="scan")
def scan_cmd(
    path: str = typer.Argument(".", help="File or directory to scan for secrets."),
    exit_code: bool = typer.Option(True, "--exit-code/--no-exit-code", help="Return non-zero exit code if secrets found."),
    ai: bool = typer.Option(False, "--ai", help="Use local AI (Ollama + Qwen2.5-Coder) to verify findings."),
):
    """
    Security Guardian: Scan for hardcoded secrets and malicious patterns.
    
    Checks for API keys (NVIDIA, OpenAI, AWS), high-entropy strings, 
    'print/console.log' calls, and malicious code injections.
    
    Use --ai to perform deep contextual analysis using a local LLM.
    """
    from monitor.scanner import scan_directory, scan_file_for_secrets
    from rich.table import Table

    scan_path = Path(path)
    if not scan_path.exists():
        console.print(f"[bold red]Error:[/] Path not found: {path}")
        raise typer.Exit(1)

    console.print(Panel.fit(
        f"[bold cyan]TraceTree Security Guardian {'[AI-ENHANCED]' if ai else ''}[/]\n"
        f"Scanning: [bold yellow]{scan_path.resolve()}[/]",
        border_style="cyan"
    ))

    findings = []
    if scan_path.is_file():
        if "monitor" in scan_path.parts:
            console.print("\n[bold green]✔ Skipping monitor system file (self-scan exclusion).[/]\n")
            return
        for f in scan_file_for_secrets(scan_path):
            f["file_path"] = str(scan_path)
            findings.append(f)
    else:
        with Progress(
            SpinnerColumn("dots2", style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Scanning files...", total=None)
            findings = scan_directory(scan_path)

    if not findings:
        console.print("\n[bold green]✔ No issues detected.[/]\n")
        return

    # ── AI Assisted Verification ──
    if ai:
        from monitor.ai_analyzer import analyze_finding_with_ai, get_file_context, ensure_ollama_and_model
        
        # Interactively ensure the AI engine is ready
        if not ensure_ollama_and_model():
            console.print("[bold yellow]⚠ AI setup incomplete or cancelled. Skipping AI verification.[/]")
            ai = False
        else:
            console.print(f"[bold magenta]🧠 AI Reviewing {len(findings)} potential hit(s) for false positives...[/]")
            verified_findings = []
            
            with Progress(
                SpinnerColumn("dots", style="magenta"),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=False,
            ) as progress:
                for f in findings:
                    task = progress.add_task(f"Auditing: [dim]{f['file_path']}:{f['line_number']}[/]", total=None)
                    
                    context = get_file_context(Path(f["file_path"]), f["line_number"])
                    ai_result = analyze_finding_with_ai(
                        file_path=f["file_path"],
                        line_number=f["line_number"],
                        finding_type=f["type"],
                        rule_name=f["rule_name"],
                        content=f["content"],
                        full_context=context
                    )
                    
                    if "error" in ai_result:
                        f["ai_reason"] = f"AI Verification Failed: {ai_result['error']}"
                        f["ai_severity"] = 5 # Default medium
                        verified_findings.append(f)
                        progress.update(task, description=f"[bold yellow]⚠ UNVERIFIED:[/] [dim]{f['file_path']}[/]")
                    elif ai_result.get("is_vulnerable"):
                        f["ai_reason"] = ai_result.get("reason", "No reason provided")
                        f["ai_severity"] = ai_result.get("severity", 5)
                        verified_findings.append(f)
                        progress.update(task, description=f"[bold red]✖ CONFIRMED:[/] [dim]{f['file_path']}[/]")
                    else:
                        progress.update(task, description=f"[bold green]✔ DISMISSED:[/] [dim]{f['file_path']} (False Positive)[/]")
            
            findings = verified_findings

    if not findings:
        console.print("\n[bold green]✔ AI verified all hits as false positives (or no hits found). Project is CLEAN.[/]\n")
        return

    # Display findings
    table = Table(title="[bold red]Security Findings Report[/]", show_header=True, header_style="bold magenta")
    table.add_column("File", style="dim")
    table.add_column("Line", justify="right")
    table.add_column("Type", style="bold")
    table.add_column("Rule", style="yellow")
    if ai:
        table.add_column("AI Reasoning (The 'Why')", style="italic cyan")
    else:
        table.add_column("Content (Partial)", overflow="ellipsis")

    for f in findings:
        if ai and "ai_reason" in f:
            display_content = f.get("ai_reason", "")
            type_color = "red" if f.get("ai_severity", 0) >= 7 else "yellow"
        else:
            display_content = f["content"][:50] + "..." if len(f["content"]) > 50 else f["content"]
            if f["type"] == "secret":
                type_color = "red"
            elif f["type"] == "malicious":
                type_color = "bold red"
            else:
                type_color = "yellow"
        
        table.add_row(
            f["file_path"],
            str(f["line_number"]),
            f"[{type_color}]{f['type'].upper()}[/]",
            f"[{type_color}]{f['rule_name']}[/]" if f["type"] == "malicious" else f["rule_name"],
            display_content
        )

    console.print("\n")
    console.print(table)
    console.print(f"\n[bold red]✖ Found {len(findings)} verified security issue(s).[/]")
    
    if exit_code:
        raise typer.Exit(1)


# ------------------------------------------------------------------ #
#  Standalone entry-point wrappers for console_scripts
#  These create dedicated Typer apps so `cascade-watch <args>` works
#  as a top-level command instead of `cascade-analyze watch <args>`.
# ------------------------------------------------------------------ #

scan_app = typer.Typer(
    name="cascade-scan",
    help="Secret Guardian: Scan for hardcoded secrets and risky debug logging.",
)

@scan_app.command()
def _scan_cmd(
    path: str = typer.Argument(".", help="File or directory to scan for secrets."),
    exit_code: bool = typer.Option(True, "--exit-code/--no-exit-code", help="Return non-zero exit code if secrets found."),
    ai: bool = typer.Option(False, "--ai", help="Use local AI (Ollama + Qwen2.5-Coder) to verify findings."),
):
    """Security Guardian: Scan for hardcoded secrets and malicious patterns."""
    scan_cmd(path=path, exit_code=exit_code, ai=ai)

watch_app = typer.Typer(
    name="cascade-watch",
    help="Run the TraceTree session guardian on a repository.",
)

@watch_app.command()
def _watch_cmd(
    repo: str = typer.Argument(..., help="Local repo path or Git URL to watch."),
    check: str = typer.Option(None, "--check", "-c", help="On-demand deep scan of a specific file or command."),
    output: str = typer.Option("report", "--output", "-o", help="Output format: 'report' or 'json'."),
):
    """Run the TraceTree session guardian on a repository."""
    watch(repo=repo, check=check, output=output)


check_cli = typer.Typer(
    name="cascade-check",
    help="Quick on-demand scan of a specific file or command.",
)

@check_cli.command()
def _check_cmd(
    file_or_command: str = typer.Argument(..., help="File path or command to check."),
    output: str = typer.Option("report", "--output", "-o", help="Output format: 'report' or 'json'."),
):
    """Quick on-demand scan of a specific file or command."""
    check(file_or_command=file_or_command, output=output)


install_hook_cli = typer.Typer(
    name="cascade-install-hook",
    help="Install the TraceTree shell hook.",
)

@install_hook_cli.command()
def _install_hook_cmd(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt")
):
    """Install the TraceTree shell hook."""
    install_hook_cmd(yes=yes)


uninstall_hook_cli = typer.Typer(
    name="cascade-uninstall-hook",
    help="Uninstall the TraceTree shell hook.",
)

@uninstall_hook_cli.command()
def _uninstall_hook_cmd(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt")
):
    """Uninstall the TraceTree shell hook."""
    uninstall_hook_cmd(yes=yes)


def launch_dashboard():
    """
    Orchestrate and run both the API backend and the Frontend Next.js client concurrently.
    """
    import signal
    import threading
    import shutil
    import subprocess
    
    project_root = Path(__file__).resolve().parent
    frontend_dir = project_root / "frontend"
    
    # Pre-check npm
    if shutil.which("npm") is None:
        console.print(Panel(
            "[bold red]Node.js / npm not found in PATH.[/]\n\n"
            "TraceTree GUI Mode requires Node.js (>= 18) to be installed.\n"
            "Please download it from [blue]https://nodejs.org[/] and try again.",
            title="[bold red]Launch Error[/]",
            border_style="red",
            expand=False
        ))
        raise typer.Exit(1)

    console.print("[cyan]Starting TraceTree Services...[/]\n")
    
    api_proc = None
    frontend_proc = None
    orch_proc = None
    threads = []
    
    def cleanup(sig=None, frame=None):
        console.print("\n[yellow]Stopping services gracefully...[/]")
        for proc, name in [(api_proc, "API Engine"), (frontend_proc, "Frontend Client"), (orch_proc, "Orchestrator")]:
            if proc and proc.poll() is None:
                console.print(f"[dim]Terminating {name}...[/]")
                try:
                    if platform.system().lower() == "windows":
                        proc.terminate()
                    else:
                        proc.send_signal(signal.SIGINT)
                        try:
                            proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                except Exception:
                    pass
        console.print("[green]✔ Services stopped successfully.[/]")
        sys.exit(0)

    # Register signals for graceful termination
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    def stream_output(pipe, prefix, color):
        try:
            for line in iter(pipe.readline, ''):
                if not line:
                    break
                line_str = line.strip()
                if line_str:
                    console.print(f"[{color}]{prefix}[/] {line_str}")
        except Exception:
            pass

    # Determine API port
    api_port_str = os.environ.get("TRACETREE_API_PORT", "8000")
    try:
        api_port = int(api_port_str)
    except ValueError:
        api_port = 8000

    # Issue 4 fix: use module-level _is_port_in_use() — testable, not re-created per call.
    if _is_port_in_use(api_port):
        # Try to get the occupying PID
        occupying_pid = None
        try:
            import subprocess
            out = subprocess.check_output(["lsof", "-t", f"-i:{api_port}"], text=True)
            pids = [int(p.strip()) for p in out.strip().split("\n") if p.strip()]
            if pids:
                occupying_pid = pids[0]
        except Exception:
            pass

        pid_info = f" (PID {occupying_pid})" if occupying_pid else ""
        console.print(Panel(
            f"[bold red]Port {api_port} is already in use{pid_info}.[/]\n\n"
            f"The TraceTree API Gateway cannot start because another process is occupying port {api_port}.\n\n"
            f"[bold yellow]How to fix:[/]\n"
            f"1. Free the port: run [cyan]kill -9 {occupying_pid}[/] (if you want to terminate the process).\n"
            f"2. Run on a different port: set the [cyan]TRACETREE_API_PORT[/] environment variable:\n"
            f"   [cyan]export TRACETREE_API_PORT=8001[/] (or another free port) before running the command.",
            title="[bold red]Port Conflict[/]",
            border_style="red",
            expand=False
        ))
        raise typer.Exit(1)

    try:
        # Start API server (Uvicorn)
        # We prefer the virtual environment's Python if it exists, to ensure uvicorn is available
        python_exe = sys.executable
        venv_python = project_root / "venv" / "bin" / ("python.exe" if platform.system().lower() == "windows" else "python3")
        if venv_python.exists():
            python_exe = str(venv_python)
            
        api_cmd = [python_exe, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", str(api_port)]
        api_proc = subprocess.Popen(
            api_cmd,
            env=os.environ,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Start Orchestrator server
        orchestrator_dir = project_root / "orchestrator"
        npx_path = shutil.which("npx") or "npx"
        orch_cmd = [npx_path, "tsx", "src/server.ts"]
        orch_env = os.environ.copy()
        orch_env["PYTHON_PATH"] = python_exe
        orch_proc = subprocess.Popen(
            orch_cmd,
            env=orch_env,
            cwd=str(orchestrator_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Start Frontend server (Next.js via npm run dev on port 3001)
        npm_path = shutil.which("npm") or "npm"
        frontend_cmd = [npm_path, "run", "dev", "--", "-p", "3001"]
        frontend_proc = subprocess.Popen(
            frontend_cmd,
            env=os.environ,
            cwd=str(frontend_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Start logging threads
        t1 = threading.Thread(target=stream_output, args=(api_proc.stdout, "API Engine  ", "#FF8C00"), daemon=True)
        t2 = threading.Thread(target=stream_output, args=(frontend_proc.stdout, "Frontend    ", "#8A2BE2"), daemon=True)
        t3 = threading.Thread(target=stream_output, args=(orch_proc.stdout, "Orchestrator", "#00FFFF"), daemon=True)
        t1.start()
        t2.start()
        t3.start()
        threads.extend([t1, t2, t3])
        
    except Exception as e:
        console.print(f"[bold red]Failed to start processes:[/] {e}")
        cleanup()
        raise typer.Exit(1)
        
    # Wait for a brief moment to let servers initialize
    time.sleep(3)
    
    # Print the beautiful URL Panel
    url = "http://localhost:3001"
    orch_url = "http://localhost:3000"
    api_url = f"http://127.0.0.1:{api_port}"
    
    panel_content = (
        f"[bold green]🚀 TraceTree Dashboard is active![/]\n\n"
        f"  [bold]Web Client (GUI):[/]  [underline cyan]{url}[/]\n"
        f"  [bold]Orchestrator WS:[/]   [underline cyan]{orch_url}[/]\n"
        f"  [bold]API Gateway:[/]       [underline cyan]{api_url}[/]\n\n"
        f"[dim]Press Ctrl+C to stop all services and return to shell.[/]"
    )
    console.print(Panel(panel_content, border_style="bold green", expand=False))
    
    # Auto-open browser
    import webbrowser
    try:
        webbrowser.open(url)
    except Exception:
        pass
    # Spawn the interactive prompt thread in the background
    def prompt_loop():
        # Give some time for startup logs to settle
        time.sleep(2)
        while True:
            try:
                target = console.input("\n[bold yellow]Enter target path/package to analyze (or press Ctrl+C to exit): [/]")
                target = target.strip()
                if not target:
                    continue
                console.print(f"[cyan]Spawning scan for [bold]{target}[/] in GUI mode...[/]")
                
                python_exe = sys.executable
                venv_python = project_root / "venv" / "bin" / ("python.exe" if platform.system().lower() == "windows" else "python3")
                if venv_python.exists():
                    python_exe = str(venv_python)
                
                # Spawn a background process running 'python3 cli.py analyze <target> --gui'
                subprocess.Popen(
                    [python_exe, "cli.py", "analyze", target, "--gui"],
                    env=os.environ,
                    cwd=str(project_root)
                )
            except (KeyboardInterrupt, SystemExit):
                break
            except EOFError:
                # Stdin is not active/available (e.g. running in background task)
                time.sleep(10)
                continue
            except Exception as e:
                console.print(f"[bold red]Prompt thread error: {e}[/]")
                break

    prompt_thread = threading.Thread(target=prompt_loop, daemon=True)
    prompt_thread.start()

    # Keep the main thread alive and monitor processes
    try:
        while True:
            # Check if any process crashed
            if api_proc.poll() is not None:
                console.print("[bold red]❌ API Engine stopped unexpectedly.[/]")
                break
            if frontend_proc.poll() is not None:
                console.print("[bold red]❌ Frontend Client stopped unexpectedly.[/]")
                break
            if orch_proc.poll() is not None:
                console.print("[bold red]❌ Orchestrator stopped unexpectedly.[/]")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


@app.command(name="dashboard")
def dashboard_cmd():
    """Launch the TraceTree local web dashboard."""
    launch_dashboard()


dashboard_cli = typer.Typer(
    name="cascade-dashboard",
    help="Unified dashboard launcher.",
)

@dashboard_cli.command()
def _dashboard_cmd():
    """Launch the TraceTree local web dashboard."""
    launch_dashboard()


if __name__ == "__main__":
    app()
