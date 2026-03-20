import os
import sys
import time
import typer
import platform
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

app = typer.Typer(help="Cascading Behavioral Propagation Analyzer", no_args_is_help=True)
console = Console()

def check_docker_preflight():
    """Check if Docker is installed and running before starting analysis."""
    if docker is None:
        console.print(Panel(
            "[bold red]Docker SDK is not installed.[/]\n"
            "Please run: [bold cyan]pip install docker[/]",
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

@app.command()
def analyze(
    target: str = typer.Argument(..., help="Package name (e.g. requests), bulk file (requirements.txt), or installer (app.dmg)"),
    type: str = typer.Option(None, "--type", "-t", help="Force exactly 'pip', 'npm', 'dmg', 'exe', or 'bulk'"),
    url: str = typer.Option(None, "--url", "-u", help="Optional URL for private dependencies"),
):
    """
    Run a behavioral cascade analysis on a suspicious target.
    """
    check_docker_preflight()

    # Determine type
    target_type = type if type else determine_target_type(target)

    console.print(Panel.fit(
        f"[bold cyan]Cascading Behavioral Propagation Analyzer[/]\n"
        f"Target: [bold yellow]{target}[/]\n"
        f"Analyzer Type: [bold green]{target_type.upper()}[/]",
        border_style="cyan"
    ))

    from sandbox.sandbox import run_sandbox
    from monitor.parser import parse_strace_log
    from graph.builder import build_cascade_graph
    from ml.detector import detect_anomaly

    log_path = None
    parsed_data = None
    graph_data = None
    is_malicious = False
    confidence = 0.0

    with Progress(
        SpinnerColumn("dots2", style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        
        if target_type == "pip":
            task1 = progress.add_task("[yellow]Running isolated Docker sandbox & tracking strace...", total=None)
            log_path = run_sandbox(target)
            if log_path and Path(log_path).exists():
                progress.update(task1, description=f"[bold green]✔[/] [dim]Sandbox complete. Log: {log_path}[/]")
            else:
                progress.update(task1, description="[bold red]✖[/] [dim]Pip sandbox execution failed.[/]")
                return
        else:
            task1 = progress.add_task(f"[yellow]Simulation warning: Only 'pip' natively sandboxed yet for {target}...", total=None)
            time.sleep(1.5)
            progress.update(task1, description="[bold yellow]⚠[/] [dim]Mocking simulated analysis mode[/]")
            return

        task2 = progress.add_task("[yellow]Parsing system events & extracting behavior signatures...", total=None)
        try:
            parsed_data = parse_strace_log(log_path)
            flags_count = len(parsed_data.get("flags", []))
            progress.update(task2, description=f"[bold green]✔[/] [dim]Parsed {len(parsed_data.get('events', []))} events, found {flags_count} flags[/]")
        except Exception as e:
            progress.update(task2, description=f"[bold red]✖[/] [dim]Parser failed: {e}[/]")
            return

        task3 = progress.add_task("[yellow]Compiling NetworkX cascade graph...", total=None)
        try:
            graph_data = build_cascade_graph(parsed_data)
            stats = graph_data.get("stats", {})
            progress.update(task3, description=f"[bold green]✔[/] [dim]Graph mapped: {stats.get('node_count', 0)} nodes, {stats.get('edge_count', 0)} edges[/]")
        except Exception as e:
            progress.update(task3, description=f"[bold red]✖[/] [dim]Graph engine failed: {e}[/]")
            return

        task4 = progress.add_task("[yellow]Running scikit-learn IsolationForest anomaly detection...", total=None)
        try:
            is_malicious, confidence = detect_anomaly(graph_data, parsed_data)
            progress.update(task4, description="[bold green]✔[/] [dim]IsolationForest evaluation complete[/]")
        except Exception as e:
            progress.update(task4, description=f"[bold red]✖[/] [dim]ML Engine failed: {e}[/]")
            return

    console.print("\n")
    
    console.print(Panel(
        build_cascade_tree(target, target_type, graph_data),
        title="[bold]Behavioral Cascade Graph[/]",
        border_style="magenta",
        expand=False
    ))

    flags = parsed_data.get("flags", [])
    if flags:
        behaviors_str = "\n".join([f"[bold red]•[/] {f}" for f in flags])
    else:
        behaviors_str = "[dim green]No overtly suspicious regex footprints flagged.[/]"

    console.print(Panel(
        behaviors_str,
        title="[bold]Flagged Behaviors[/]",
        border_style="red" if flags else "green",
        expand=False
    ))

    console.print("\n")

    if is_malicious:
        verdict_text = Text("\n  MALICIOUS  \n", style="bold white on red", justify="center")
        border_style = "red"
        conf_style = "bold red"
    else:
        verdict_text = Text("\n  CLEAN  \n", style="bold white on green", justify="center")
        border_style = "green"
        conf_style = "bold green"

    verdict_panel = Panel.fit(verdict_text, title="[bold]Final Verdict[/]", border_style=border_style)
    confidence_text = Text(f"Confidence Score: {confidence}%", style=conf_style)
    
    console.print(Align.center(verdict_panel))
    console.print(Align.center(confidence_text))
    console.print("\n")

def train_cli():
    """CLI entrypoint dynamically executing cascade-train"""
    from ml.trainer import train_model
    train_model()

def update_cli():
    """CLI entrypoint evaluating cascade-update natively"""
    from ml.detector import update_model_from_gcs
    update_model_from_gcs()

if __name__ == "__main__":
    app()
