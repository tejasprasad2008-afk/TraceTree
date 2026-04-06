import os
import sys
import time
import typer
import platform
from typing import Tuple
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
    if path.is_file() or "." in path.name:
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

def perform_analysis(target: str, target_type: str, progress, console) -> Tuple[bool, float, dict, dict]:
    """Helper to run the full sandbox -> parse -> graph -> ml pipeline for a single target."""
    from sandbox.sandbox import run_sandbox
    from monitor.parser import parse_strace_log
    from graph.builder import build_cascade_graph
    from ml.detector import detect_anomaly

    log_path = None
    parsed_data = None
    graph_data = None
    is_malicious = False
    confidence = 0.0

    task1 = progress.add_task(f"[yellow]Sandboxing {target} ({target_type})...", total=None)
    log_path = run_sandbox(target, target_type)
    if log_path and Path(log_path).exists():
        progress.update(task1, description=f"[bold green]✔[/] [dim]Sandbox complete: {Path(log_path).name}[/]")
    else:
        progress.update(task1, description=f"[bold red]✖[/] [dim]Sandbox failed for {target}.[/]")
        return False, 0.0, {}, {}

    task2 = progress.add_task(f"[yellow]Parsing {target}...", total=None)
    try:
        parsed_data = parse_strace_log(log_path)
        progress.update(task2, description=f"[bold green]✔[/] [dim]Parsed {len(parsed_data.get('events', []))} events[/]")
    except Exception as e:
        progress.update(task2, description=f"[bold red]✖[/] [dim]Parser failed: {e}[/]")
        return False, 0.0, {}, {}

    task3 = progress.add_task(f"[yellow]Graphing {target}...", total=None)
    try:
        graph_data = build_cascade_graph(parsed_data)
        progress.update(task3, description=f"[bold green]✔[/] [dim]Graph mapped[/]")
    except Exception as e:
        progress.update(task3, description=f"[bold red]✖[/] [dim]Graph failed: {e}[/]")
        return False, 0.0, {}, {}

    task4 = progress.add_task(f"[yellow]Detecting {target}...", total=None)
    try:
        is_malicious, confidence = detect_anomaly(graph_data, parsed_data)
        progress.update(task4, description="[bold green]✔[/] [dim]Detection complete[/]")
    except Exception as e:
        progress.update(task4, description=f"[bold red]✖[/] [dim]ML failed: {e}[/]")
        return False, 0.0, {}, {}

    return is_malicious, confidence, graph_data, parsed_data

@app.command()
def analyze(
    target: str = typer.Argument(..., help="Package name, bulk file, or installer"),
    type: str = typer.Option(None, "--type", "-t", help="Force 'pip', 'npm', 'dmg', 'exe', or 'bulk'"),
    url: str = typer.Option(None, "--url", "-u", help="Optional URL for private dependencies"),
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
            is_malicious, confidence, graph_data, parsed_data = perform_analysis(current_target, sub_type, progress, console)
        
        if not graph_data:
            continue

        console.print("\n")
        console.print(Panel(
            build_cascade_tree(current_target, sub_type, graph_data),
            title=f"[bold]Cascade Graph: {current_target}[/]",
            border_style="magenta",
            expand=False
        ))

        flags = parsed_data.get("flags", [])
        behaviors_str = "\n".join([f"[bold red]•[/] {f}" for f in flags]) if flags else "[dim green]No suspicious footprints flagged.[/]"
        console.print(Panel(behaviors_str, title="[bold]Flagged Behaviors[/]", border_style="red" if flags else "green", expand=False))

        if is_malicious:
            verdict_text = Text("\n  MALICIOUS  \n", style="bold white on red", justify="center")
            conf_style = "bold red"
        else:
            verdict_text = Text("\n  CLEAN  \n", style="bold white on green", justify="center")
            conf_style = "bold green"

        console.print(Align.center(Panel.fit(verdict_text, title="Final Verdict", border_style=conf_style.split()[-1])))
        console.print(Align.center(Text(f"Confidence Score: {confidence}%", style=conf_style)))
        console.print("\n" + "─" * console.width + "\n")

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


if __name__ == "__main__":
    app()
