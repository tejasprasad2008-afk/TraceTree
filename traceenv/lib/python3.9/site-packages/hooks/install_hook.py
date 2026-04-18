#!/usr/bin/env python3
"""
Cross-platform installer for the TraceTree shell hook.

Detects the user's shell, copies the hook script to a standard location,
and appends a `source` line to the appropriate shell RC file.
Works on macOS and Linux.
"""

import os
import shutil
import sys
from pathlib import Path
from typing import Optional, Tuple

# ------------------------------------------------------------------ #
#  Constants
# ------------------------------------------------------------------ #

HOOK_FILE = "shell_hook.sh"
MARKER = "# --- TraceTree shell hook (auto-installed) ---"


def _project_root() -> Path:
    """Return the TraceTree project root (parent of this script's hooks/ dir)."""
    return Path(__file__).resolve().parent.parent


def _detect_shell_rc() -> Optional[Tuple[str, str]]:
    """
    Detect the user's shell config file.

    Returns (shell_name, rc_path) or None if detection fails.
    """
    # 1. Check environment variables first
    if os.environ.get("ZSH_VERSION"):
        return ("zsh", str(Path.home() / ".zshrc"))
    if os.environ.get("BASH_VERSION"):
        return ("bash", str(Path.home() / ".bashrc"))

    # 2. Check $SHELL
    shell_path = os.environ.get("SHELL", "")
    shell_name = Path(shell_path).name if shell_path else ""

    if shell_name == "zsh":
        return ("zsh", str(Path.home() / ".zshrc"))
    if shell_name == "bash":
        return ("bash", str(Path.home() / ".bashrc"))

    # 3. Fallback — try both, prefer the one that exists
    zshrc = Path.home() / ".zshrc"
    bashrc = Path.home() / ".bashrc"
    if zshrc.exists():
        return ("zsh", str(zshrc))
    if bashrc.exists():
        return ("bash", str(bashrc))

    # Last resort: default to .bashrc (will be created)
    return ("bash", str(bashrc))


def _already_installed(rc_path: str) -> bool:
    """Check if the hook source line is already in the shell config."""
    try:
        content = Path(rc_path).read_text(encoding="utf-8")
        return "tracetree/hooks/shell_hook.sh" in content
    except (OSError, UnicodeDecodeError):
        return False


def install_hook() -> bool:
    """
    Install the TraceTree shell hook.

    Returns True on success, False on failure.
    """
    project_root = _project_root()
    hook_src = project_root / "hooks" / HOOK_FILE

    if not hook_src.exists():
        print(f"[!] Hook script not found at {hook_src}")
        print("    Make sure you are running this from the TraceTree project root.")
        return False

    # Detect shell
    result = _detect_shell_rc()
    if result is None:
        print("[!] Could not detect your shell. Please install the hook manually:")
        print(f'    source "{hook_src}"')
        return False

    shell_name, rc_path = result

    # Check if already installed
    if _already_installed(rc_path):
        print(f"✅ TraceTree hook is already installed in {rc_path}")
        return True

    # Determine install target directory
    target_dir = Path.home() / ".local" / "share" / "tracetree" / "hooks"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_hook = target_dir / HOOK_FILE

    # Copy hook script
    shutil.copy2(str(hook_src), str(target_hook))
    target_hook.chmod(0o755)

    # Append to shellrc
    hook_line = f'source "$HOME/.local/share/tracetree/hooks/{HOOK_FILE}"'
    with open(rc_path, "a", encoding="utf-8") as f:
        f.write(f"\n{MARKER}\n{hook_line}\n")

    print(f"✅ TraceTree shell hook installed for {shell_name}!")
    print()
    print(f"   Added to: {rc_path}")
    print(f"   Script at: {target_hook}")
    print()
    print(f"   Run 'source {rc_path}' or open a new terminal to activate.")
    return True


def main() -> int:
    success = install_hook()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
