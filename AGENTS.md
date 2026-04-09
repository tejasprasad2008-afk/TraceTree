# TraceTree Agent Guidelines

## Project Overview
TraceTree is a runtime behavioral analysis tool for detecting supply chain attacks in Python packages, npm modules, DMG and EXE files. It executes suspicious packages in isolated Docker sandboxes, monitors system calls, builds execution graphs, and uses ML to detect anomalous behavior.

## Repository Structure
```
.
├── api/                  # FastAPI backend
├── cli.py                # Main CLI entrypoint
├── sandbox/              # Docker container management
├── monitor/              # strace parsing and syscall tracking
├── graph/                # NetworkX graph construction
├── ml/                   # RandomForestClassifier for anomaly detection
├── data/                 # Training datasets (clean/malicious packages)
└── TraceTree/            # Duplicate module structure (legacy?)
```

## Build Commands
```bash
# Install the package in development mode
pip install -e .

# Build distribution packages
python setup.py sdist bdist_wheel

# Install from built package
pip install dist/cascade-analyzer-1.0.0.tar.gz
```

## Entry Points (CLI Commands)
```bash
# Analyze a package or dependency file
cascade-analyze <package_name>
cascade-analyze requirements.txt
cascade-analyze package.json
cascade-analyze malicious_app.dmg

# Update ML models from GCS
cascade-update

# Train new model locally
cascade-train
```

## Testing Guidelines
No formal test framework is currently implemented. However:

1. **Manual Testing Approach**:
   - Test with known clean packages: `cascade-analyze requests`
   - Test with dependency files: `cascade-analyze requirements.txt`
   - Verify Docker sandbox functionality
   - Check graph generation and ML scoring

2. **When Adding Tests**:
   - Create tests in a `tests/` directory mirroring package structure
   - Use pytest as suggested by references in data files
   - Mock Docker calls for unit testing
   - Test CLI commands with typer's testing utilities

## Code Style Guidelines

### Imports
```python
# Standard library imports
import os
import sys
import time
from typing import Tuple, Optional, Dict, Any, List
from pathlib import Path
import uuid

# Third-party imports
import typer
import docker
from rich.console import Console
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
import networkx as nx
from sklearn.ensemble import RandomForestClassifier

# Local application imports
from .sandbox import SandboxManager
from .monitor import StraceParser
from .graph import GraphBuilder
from .ml import AnomalyDetector
```

### Formatting
- Follow PEP 8 guidelines
- Maximum line length: 88 characters (Black default)
- Use 4 spaces per indentation level
- No trailing whitespace
- Blank lines: 2 between function/class definitions, 1 between method definitions

### Types
- Use type hints for all function signatures
- Prefer specific types over `Any` when possible
- Use `Optional[T]` for nullable values
- Use `List[T]`, `Dict[K, V]` for collections
- Return meaningful types instead of booleans when context matters

### Naming Conventions
- Modules: `snake_case`
- Classes: `PascalCase`
- Functions/Methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Variables: `snake_case`
- Private methods/variables: `_prefix`

### Error Handling
```python
# Handle optional dependencies gracefully
try:
    import docker
except ImportError:
    docker = None

# Specific exception handling
try:
    # operation that might fail
except SpecificError as e:
    logger.error(f"Specific error occurred: {e}")
    raise  # or handle appropriately
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    raise HTTPException(status_code=500, detail="Internal server error")

# Validate inputs early
if not package_name:
    raise typer.BadParameter("Package name is required")
```

### Documentation
- Module docstrings: Describe purpose and usage
- Function docstrings: Args, Returns, Raises sections
- Use descriptive variable names over comments
- Comment complex logic, not obvious code
- Keep comments updated when code changes

### Specific Patterns Observed
1. **CLI Pattern** (in cli.py):
   - Use typer for command-line interfaces
   - Separate CLI parsing from business logic
   - Use rich for terminal formatting
   - Progress indicators for long operations

2. **API Pattern** (in api/main.py):
   - Pydantic models for request/response validation
   - Background tasks for long-running operations
   - Proper HTTP status codes
   - CORS middleware for frontend integration

3. **Sandbox Pattern** (in sandbox/sandbox.py):
   - Docker container lifecycle management
   - Network restriction for safety
   - Resource cleanup with context managers

## Development Workflow
1. Create feature branch from main
2. Implement changes following existing patterns
3. Test manually with known packages
4. Ensure Docker sandbox works correctly
5. Verify ML model loads and predicts
6. Submit pull request with clear description

## Important Notes
- Docker must be running for sandbox functionality
- First run downloads ML model from GCS (~100MB)
- Training requires executing packages in sandbox (time-consuming)
- The TraceTree/ directory appears to be a duplicate structure - prefer root-level modules
- Data files contain package lists used for training
- Virtual environment paths in venv/ are machine-specific - don't commit virtual environments
- After pulling, recreate virtual environment with `pip install -e .`
- Model files are large (~100MB) and stored in cache - consider this in deployment planning