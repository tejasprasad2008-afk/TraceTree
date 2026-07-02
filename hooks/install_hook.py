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
MARKER_BEGIN = "# === BEGIN TRACETREE SHELL HOOK ==="
MARKER_END = "# === END TRACETREE SHELL HOOK ==="


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
        return MARKER_BEGIN in content
    except (OSError, UnicodeDecodeError):
        return False


def install_pre_commit_hook() -> bool:
    """Install the Secret Guardian Git pre-commit hook."""
    project_root = _project_root()
    git_hooks_dir = project_root / ".git" / "hooks"
    
    if not git_hooks_dir.exists():
        print("[!] Not a git repository or .git/hooks missing. Skipping pre-commit hook.")
        return False

    src_hook = project_root / "hooks" / "pre-commit.sh"
    target_hook = git_hooks_dir / "pre-commit"

    if not src_hook.exists():
        print(f"[!] Pre-commit source not found at {src_hook}")
        return False

    # Backup existing hook if it's not ours
    if target_hook.exists():
        content = target_hook.read_text(encoding="utf-8")
        if "TraceTree Secret Guardian" not in content:
            backup = target_hook.with_suffix(".bak")
            print(f"[dim]Backing up existing pre-commit hook to {backup}[/]")
            shutil.copy2(str(target_hook), str(backup))

    shutil.copy2(str(src_hook), str(target_hook))
    target_hook.chmod(0o755)

    print("✅ TraceTree Secret Guardian pre-commit hook installed!")
    return True


def install_hook(yes: bool = False) -> bool:
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
        install_pre_commit_hook()
        return True

    # Determine install target directory
    target_dir = Path.home() / ".local" / "share" / "tracetree" / "hooks"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_hook = target_dir / HOOK_FILE

    hook_line = f'source "$HOME/.local/share/tracetree/hooks/{HOOK_FILE}"'
    block_to_add = f"\n{MARKER_BEGIN}\n{hook_line}\n{MARKER_END}\n"

    print("\n" + "="*60)
    print("TraceTree Hook Installation")
    print(f"File to modify: {rc_path}")
    print("Block to add:")
    print("-" * 30)
    print(block_to_add.strip())
    print("-" * 30)
    print("="*60 + "\n")

    if not yes:
        # Prompt for confirmation
        try:
            confirm = input(f"Do you want to proceed with modifying {rc_path}? [y/N]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return False
        if confirm not in ("y", "yes"):
            print("Aborted.")
            return False

    # Copy hook script
    shutil.copy2(str(hook_src), str(target_hook))
    target_hook.chmod(0o755)

    # Append to shellrc
    with open(rc_path, "a", encoding="utf-8") as f:
        f.write(block_to_add)

    print(f"✅ TraceTree shell hook installed for {shell_name}!")
    print()
    print(f"   Added to: {rc_path}")
    print(f"   Script at: {target_hook}")
    print()
    print(f"   Run 'source {rc_path}' or open a new terminal to activate.")

    # Also install pre-commit hook
    install_pre_commit_hook()
    return True


def uninstall_hook(yes: bool = False) -> bool:
    """
    Uninstall the TraceTree shell hook.
    """
    result = _detect_shell_rc()
    if result is None:
        print("[!] Could not detect your shell RC file to uninstall from.")
        return False
        
    shell_name, rc_path = result
    rc_file = Path(rc_path)
    if not rc_file.exists():
        print(f"[-] Shell config file {rc_path} does not exist. Nothing to uninstall.")
        return True
        
    content = rc_file.read_text(encoding="utf-8")
    if MARKER_BEGIN not in content:
        print(f"[-] TraceTree hook block markers not found in {rc_path}. Already uninstalled?")
        return True
        
    idx_begin = content.find(MARKER_BEGIN)
    idx_end = content.find(MARKER_END)
    if idx_begin == -1 or idx_end == -1 or idx_end < idx_begin:
        print(f"[!] Invalid or corrupted TraceTree hook markers in {rc_path}. Cannot uninstall automatically.")
        return False
        
    block_to_remove = content[idx_begin : idx_end + len(MARKER_END)]
    print("\n" + "="*60)
    print(f"TraceTree Hook Uninstallation")
    print(f"File to modify: {rc_path}")
    print("Block to remove:")
    print("-" * 30)
    print(block_to_remove)
    print("-" * 30)
    print("="*60 + "\n")
    
    if not yes:
        try:
            confirm = input(f"Do you want to proceed with removing this block from {rc_path}? [y/N]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return False
        if confirm not in ("y", "yes"):
            print("Aborted.")
            return False
            
    new_content = content[:idx_begin].rstrip("\n") + "\n" + content[idx_end + len(MARKER_END):].lstrip("\n")
    rc_file.write_text(new_content, encoding="utf-8")
    print(f"✅ Successfully removed TraceTree shell hook from {rc_path}!")
    
    # Also clean up the target hook file
    target_hook = Path.home() / ".local" / "share" / "tracetree" / "hooks" / HOOK_FILE
    if target_hook.exists():
        try:
            target_hook.unlink()
            print(f"✅ Removed hook script: {target_hook}")
        except Exception as e:
            print(f"[!] Could not remove {target_hook}: {e}")
            
    # Also remove git pre-commit hook if it's ours
    project_root = _project_root()
    git_hooks_dir = project_root / ".git" / "hooks"
    target_hook = git_hooks_dir / "pre-commit"
    if target_hook.exists():
        content = target_hook.read_text(encoding="utf-8")
        if "TraceTree Secret Guardian" in content:
            try:
                target_hook.unlink()
                print("✅ Removed git pre-commit hook")
                backup = target_hook.with_suffix(".bak")
                if backup.exists():
                    shutil.move(str(backup), str(target_hook))
                    print("✅ Restored original pre-commit hook backup")
            except Exception as e:
                print(f"[!] Could not remove pre-commit hook: {e}")
                
    return True


def main() -> int:
    success = install_hook()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
