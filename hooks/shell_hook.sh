#!/usr/bin/env bash
# shell_hook.sh — Source this in your ~/.bashrc or ~/.zshrc
# Wraps `git clone` to auto-start TraceTree's session guardian.

_tracetree_git_hook_installed=false

_tracetree_init_hook() {
    if [ "$_tracetree_git_hook_installed" = true ]; then
        return
    fi
    _tracetree_git_hook_installed=true

    # Store reference to the real git binary
    local _tt_real_git
    _tt_real_git=$(command -v git 2>/dev/null)

    if [ -z "$_tt_real_git" ]; then
        return
    fi

    # Check that cascade is available
    if ! command -v cascade-watch &>/dev/null; then
        return
    fi

    # Define the wrapper function
    git() {
        # Only intercept `git clone …`
        if [ "$1" = "clone" ]; then
            # Shift past 'clone' to find the repo URL
            shift
            local _tt_repo=""
            local _tt_dir=""

            # Parse arguments: git clone [--option ...] <repo> [<dir>]
            while [ $# -gt 0 ]; do
                case "$1" in
                    --*|-*)
                        # Skip options (and their values if applicable)
                        if [ "$1" = "--depth" ] || [ "$1" = "-b" ] || [ "$1" = "--branch" ] || \
                           [ "$1" = "--origin" ] || [ "$1" = "-o" ] || [ "$1" = "--reference" ] || \
                           [ "$1" = "--template" ] || [ "$1" = "--config" ] || [ "$1" = "-c" ]; then
                            shift  # skip value
                        fi
                        shift
                        ;;
                    *)
                        if [ -z "$_tt_repo" ]; then
                            _tt_repo="$1"
                        else
                            _tt_dir="$1"
                        fi
                        shift
                        ;;
                esac
            done

            # Default dir name from repo URL
            if [ -z "$_tt_dir" ]; then
                _tt_dir=$(basename "$_tt_repo" | sed 's/\.git$//')
            fi

            # Run the real clone
            "$_tt_real_git" clone "$_tt_repo" "$_tt_dir"
            local _tt_status=$?

            if [ $_tt_status -eq 0 ] && [ -d "$_tt_dir" ]; then
                # Resolve to absolute path
                local _tt_abs_dir
                _tt_abs_dir=$(cd "$_tt_dir" && pwd)

                echo ""
                echo "🕷️  TraceTree is now watching $_tt_abs_dir"
                echo "   (background session guardian started)"
                echo ""

                # Start cascade-watch in background, detached
                nohup cascade-watch "$_tt_abs_dir" </dev/null >"/tmp/tracetree_$(basename "$_tt_dir").log" 2>&1 &
            fi

            return $_tt_status
        fi

        # All other commands pass through to real git
        "$_tt_real_git" "$@"
    }

    export -f git 2>/dev/null || true
}

# Auto-initialise when sourced
_tracetree_init_hook
