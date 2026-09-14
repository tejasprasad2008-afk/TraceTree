import sys, termios, tty
from rich.console import Console
from rich.panel import Panel

console = Console()

def print_panel_with_trim(console, content: str, title: str, border_style: str, max_lines: int = 10):
    lines = content.splitlines()
    if len(lines) <= max_lines:
        console.print(Panel(content, title=title, border_style=border_style, expand=False))
        return

    trimmed_content = "\n".join(lines[:max_lines]) + "\n\n[dim]... Output trimmed ...[/dim]"
    console.print(Panel(trimmed_content, title=title, border_style=border_style, expand=False))

    if sys.stdin.isatty():
        console.print("[dim]Press Ctrl+O to view full output, or any other key to continue...[/dim]", end="\r")
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        
        # Clear the hint line
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

        if ch == '\x0f':  # Ctrl+O
            with console.pager():
                console.print(Panel(content, title=title, border_style=border_style, expand=False))

content = "\n".join([f"Line {i}" for i in range(20)])
print_panel_with_trim(console, content, "Test Panel", "red")
