import os
import sys
import time
import typer
import platform
from typing import Tuple, Optional
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

from rich.columns import Columns
from rich.layout import Layout
from rich.style import Style
from sandbox.sandbox import run_sandbox

app = typer.Typer(help="TraceTree Security Analyzer")
console = Console()

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
    
    for edge in edges:
        target_id = edge["data"]["target"]
        label = edge["data"]["label"]
        
        target_node = next((n for n in graph_json["nodes"] if n["data"]["id"] == target_id), None)
        if not target_node: continue
        
        node_type = target_node["data"]["type"]
        node_label = target_node["data"]["label"]
        
        if node_type == "process":
            branch_text = f"[bold magenta]{node_label}[/] [dim]({label})[/]"
        elif node_type == "network":
            branch_text = f"[bold red]{node_label}[/] [dim red]({label})[/]"
        elif node_type == "file":
            branch_text = f"[white]{node_label}[/] [dim white]({label})[/]"
        else:
            branch_text = f"{node_label} ({label})"
            
        child_branch = tree_node.add(branch_text)
        
        if node_type == "process":
            recursive_build_tree(child_branch, graph_json, target_id)


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

def perform_analysis(target: str, target_type: str, progress, console) -> Tuple[bool, float, dict, dict, list, list, list, dict]:
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
    log_path = run_sandbox(target, target_type)
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

@app.command()
def analyze(
    target: str = typer.Argument(..., help="Package name, bulk file, or installer"),
    type: str = typer.Option(None, "--type", "-t", help="Force 'pip', 'npm', 'dmg', 'exe', or 'bulk'"),
    url: str = typer.Option(None, "--url", "-u", help="Optional URL for private dependencies"),
    sarif: str = typer.Option(None, "--sarif", "-s", help="Output SARIF report to this file path"),
):
    """Run a behavioral cascade analysis on a suspicious target."""
    check_docker_preflight()
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
        with Progress(
            SpinnerColumn("dots2", style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=False,
        ) as progress:
            is_malicious, confidence, graph_data, parsed_data, sig_matches, temp_patterns, yara_matches, ngram_data = perform_analysis(current_target, sub_type, progress, console)

        if not graph_data:
            continue

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
        console.print(Panel(behaviors_str, title="[bold]Flagged Behaviors[/]", border_style="red" if flags else "green", expand=False))

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

        # ── Final Verdict ──
        if is_malicious:
            verdict_text = Text("\n  MALICIOUS  \n", style="bold white on red", justify="center")
            conf_style = "bold red"
        else:
            verdict_text = Text("\n  CLEAN  \n", style="bold white on green", justify="center")
            conf_style = "bold green"

        console.print(Align.center(Panel.fit(verdict_text, title="Final Verdict", border_style=conf_style.split()[-1])))
        console.print(Align.center(Text(f"Confidence Score: {confidence}%", style=conf_style)))

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
                    confidence=confidence,
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
            "[dim]If you do not have one, you can press Enter to skip and train only on local cached data.[/]",
            border_style="yellow", expand=False
        )))
        console.print()
        
        auth_key = Prompt.ask("[bold magenta]Enter MalwareBazaar Auth Key[/]", password=True)
        if auth_key:
            os.environ["MALWAREBAZAAR_AUTH_KEY"] = auth_key
            console.print("\n[bold green]✔ Key accepted. Initiating online data ingestion...[/]\n")
        else:
            console.print("\n[dim italic]No key provided. Yielding to local cached datasets...[/]\n")
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

def update_cli():
    """CLI entrypoint evaluating cascade-update natively"""
    from ml.detector import update_model_from_gcs
    update_model_from_gcs()


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


def _run_analysis_for_diff(target: str, target_type: str, progress, console) -> Dict[str, Any]:
    """Run analysis and return a dict suitable for diff comparison."""
    is_malicious, confidence, graph_data, parsed_data, sig_matches, temp_patterns, yara_matches, ngram_data = perform_analysis(target, target_type, progress, console)
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
                console.print(Panel(behaviors_str, title="[bold]Flagged Behaviors[/]", border_style="red", expand=False))

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
        console.print(Panel(behaviors_str, title="[bold]Flagged Behaviors[/]", border_style="red" if threats else "green", expand=False))

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
):
    """
    Quick on-demand scan of a specific file or command.

    If a SessionWatcher is already running for the current directory
    (via lockfile), sends the check request to it.  Otherwise starts
    a quick one-off analysis.
    """
    check_docker_preflight()

    from watcher.session import SessionWatcher
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

    log_path = run_sandbox(str(target_path), target_type)
    if not log_path or not Path(log_path).exists():
        console.print("[bold red]Error:[/] Sandbox failed — check that Docker is running.")
        return

    from monitor.parser import parse_strace_log
    from graph.builder import build_cascade_graph
    from ml.detector import detect_anomaly

    parsed = parse_strace_log(log_path)
    graph = build_cascade_graph(parsed)
    is_malicious, confidence = detect_anomaly(graph, parsed)

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
    console.print(Align.center(Text(f"Confidence Score: {confidence}%", style=conf_style)))

    flags = parsed.get("flags", [])
    if flags:
        behaviors_str = "\n".join([f"[bold red]•[/] {f}" for f in flags])
        console.print(Panel(behaviors_str, title="[bold]Flagged Behaviors[/]", border_style="red", expand=False))

    console.print("\n" + "─" * console.width + "\n")


@app.command(name="install-hook")
def install_hook_cmd():
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
        ok = _do_install()
        if not ok:
            raise typer.Exit(1)
    except Exception as exc:
        console.print(f"[bold red]Install failed:[/] {exc}")
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
        result_a = _run_analysis_for_diff(target_a, type_a, progress, console)

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
        result_b = _run_analysis_for_diff(target_b, type_b, progress, console)

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


# ------------------------------------------------------------------ #
#  Standalone entry-point wrappers for console_scripts
#  These create dedicated Typer apps so `cascade-watch <args>` works
#  as a top-level command instead of `cascade-analyze watch <args>`.
# ------------------------------------------------------------------ #

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
def _install_hook_cmd():
    """Install the TraceTree shell hook."""
    install_hook_cmd()


if __name__ == "__main__":
    app()
