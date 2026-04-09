#!/usr/bin/env bash
# install_hook.sh — Appends the TraceTree shell hook to your shell config.
# Usage: bash install_hook.sh

set -euo pipefail

HOOK_LINE='source "$HOME/.local/share/tracetree/hooks/shell_hook.sh"'
MARKER='# --- TraceTree shell hook (auto-installed) ---'

# Detect shell config
if [ -n "${ZSH_VERSION:-}" ]; then
    SHELL_RC="$HOME/.zshrc"
    SHELL_NAME="zsh"
elif [ -n "${BASH_VERSION:-}" ]; then
    SHELL_RC="$HOME/.bashrc"
    SHELL_NAME="bash"
else
    # Fallback: check which shell is default
    case "${SHELL##*/}" in
        zsh)  SHELL_RC="$HOME/.zshrc";  SHELL_NAME="zsh" ;;
        bash) SHELL_RC="$HOME/.bashrc"; SHELL_NAME="bash" ;;
        *)
            echo "⚠  Could not detect your shell. Please source hooks/shell_hook.sh manually."
            exit 1
            ;;
    esac
fi

# Ensure the file exists
touch "$SHELL_RC"

# Check if already installed
if grep -qF "tracetree/hooks/shell_hook.sh" "$SHELL_RC" 2>/dev/null; then
    echo "✅ TraceTree hook is already installed in $SHELL_RC"
    exit 0
fi

# Determine install target
HOOK_SCRIPT_DIR="$HOME/.local/share/tracetree/hooks"
mkdir -p "$HOOK_SCRIPT_DIR"

# Copy the hook script there
HOOK_SOURCE="$(cd "$(dirname "$0")" && pwd)/shell_hook.sh"
cp "$HOOK_SOURCE" "$HOOK_SCRIPT_DIR/shell_hook.sh"
chmod +x "$HOOK_SCRIPT_DIR/shell_hook.sh"

# Append to shellrc
{
    echo ""
    echo "$MARKER"
    echo "$HOOK_LINE"
} >> "$SHELL_RC"

echo "✅ TraceTree shell hook installed for $SHELL_NAME!"
echo ""
echo "   Added to: $SHELL_RC"
echo "   Script at: $HOOK_SCRIPT_DIR/shell_hook.sh"
echo ""
echo "   Run 'source $SHELL_RC' or open a new terminal to activate."
