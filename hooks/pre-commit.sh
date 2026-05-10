#!/bin/bash
# --- TraceTree Secret Guardian (Git Pre-Commit Hook) ---
# Automatically blocks commits if secrets or risky logging patterns are found.

# Get list of staged files (Added, Copied, Modified)
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

# Run TraceTree Secret Guardian on staged files
# We use --exit-code to ensure the commit fails if findings exist.
# We also use python3 -m cli scan to ensure we use the local project version.

echo "🛡️ TraceTree Secret Guardian: Scanning staged files..."

# Try to use cascade-scan if available in PATH, else fall back to python3 cli.py
if command -v cascade-scan &> /dev/null; then
    for FILE in $STAGED_FILES; do
        cascade-scan "$FILE" --exit-code
        if [ $? -ne 0 ]; then exit 1; fi
    done
else
    for FILE in $STAGED_FILES; do
        python3 cli.py scan "$FILE" --exit-code
        if [ $? -ne 0 ]; then exit 1; fi
    done
fi

RESULT=$?

if [ $RESULT -ne 0 ]; then
    echo ""
    echo "❌ [SECRET GUARDIAN] Commit aborted. Please remediate the findings above."
    echo "💡 To bypass (NOT recommended): git commit --no-verify"
    exit 1
fi

exit 0
