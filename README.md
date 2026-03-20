# TraceTree
> Runtime behavioral analysis for Python packages, npm modules, DMG and EXE files — catching supply chain attacks that install-time scanners miss.

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)

## How It Works
TraceTree executes suspicious packages inside an isolated Docker sandbox. Right after the initial download starts, it drops the container's network interface. This safely triggers and logs malicious outbound connection attempts without actually letting traffic escape.

A regex engine parses the `strace` output, tracks system calls (like `clone`, `execve`, `socket`, and `openat`), and builds a directed graph using `NetworkX`. Finally, a `RandomForestClassifier` trained on known malware evaluates the graph's topology to detect anomalous behavior.

## Installation
You need Python 3.9+ and Docker running on your machine.

```bash
git clone https://github.com/tejasprasad2008-afk/TraceTree.git
cd TraceTree

# Install the CLI tool
pip install -e .
```

## Usage
The pipeline is controlled via a Typer CLI.

```bash
# Analyze a PyPI package
cascade-analyze requests

# Evaluate standard dependency files
cascade-analyze requirements.txt
cascade-analyze package.json

# Analyze compiled installers
cascade-analyze malicious_app.dmg
cascade-analyze payload.exe
```

## Model Training
TraceTree uses a supervised `RandomForestClassifier` to map execution boundaries to an anomaly score. On the first run, `cascade-analyze` automatically downloads the latest trained model from a public Google Cloud Storage bucket.

If you want to train the model locally using the datasets in `data/`:

```bash
# Force download the latest model from GCS
cascade-update

# Run the 60-package dataset through the sandbox to train a new model
cascade-train
```

## Who Is This For
- **Security Researchers:** Hunting undocumented supply chain behavior.
- **DevOps / DevSecOps:** Validating the runtime safety of injected dependencies.
- **Software Engineers:** Profiling the exact syscall requirements of applications.

## Architecture
The pipeline is split into 5 core modules:
1. **`/sandbox`**: Manages the Docker container lifecycle and actively restricts networking during testing.
2. **`/monitor`**: Parses the `strace` log to track execution paths and network attempts.
3. **`/graph`**: Uses `networkx` to translate parent/child process relationships into an edge graph.
4. **`/ml`**: Feeds the extracted graph features into a `RandomForestClassifier` for anomaly detection.
5. **`/cli`**: The Typer entrypoint that orchestrates the pipeline and renders the terminal UI.

## Threat Model
In late 2024, the highly obfuscated **XZ Utils** backdoor bypassed standard static scanning. Advanced supply chain malware often hides malicious operations deep within legitimate-looking test code or delayed payload fetches. By analyzing the runtime execution graph, TraceTree bypasses code obfuscation entirely to see exactly what external files, commands, and sockets a package actually tries to open.

## Contributing
Pull requests are welcome. Please ensure new features remain decoupled across the existing architecture.

## License
MIT
