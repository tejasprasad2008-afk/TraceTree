#!/usr/bin/env bash
# Create a self-contained TraceTree development environment on macOS or Linux.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"

if ! command -v python3 >/dev/null 2>&1; then
  echo "TraceTree requires Python 3.9 or newer. Install Python, then run this script again." >&2
  exit 1
fi

PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PYTHON_MAJOR="${PYTHON_VERSION%%.*}"
PYTHON_MINOR="${PYTHON_VERSION#*.}"
if [ "${PYTHON_MAJOR}" -lt 3 ] || { [ "${PYTHON_MAJOR}" -eq 3 ] && [ "${PYTHON_MINOR}" -lt 9 ]; }; then
  echo "TraceTree requires Python 3.9 or newer; found Python ${PYTHON_VERSION}." >&2
  exit 1
fi

echo "Creating virtual environment in ${VENV_DIR}..."
python3 -m venv "${VENV_DIR}"

# Some Python distributions create a venv without pip. Bootstrap it before the
# editable install so old system pip versions cannot fall back to setup.py develop.
"${VENV_DIR}/bin/python" -m ensurepip --upgrade
"${VENV_DIR}/bin/python" -m pip install --upgrade pip setuptools wheel
"${VENV_DIR}/bin/python" -m pip install -e "${ROOT_DIR}"

cat <<'EOF'

TraceTree is installed.

Activate this environment in future shells:
  source .venv/bin/activate

Then run:
  cascade-analyze --help
EOF
