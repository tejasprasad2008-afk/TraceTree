# TraceTree
> Runtime behavioral analysis for Python packages, npm modules, DMG and EXE files — catching supply chain attacks that install-time scanners miss.

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)

![Header Banner](header%20banner.png)

## How It Works
TraceTree executes suspicious packages inside an isolated Docker sandbox. Right after the initial download starts, it drops the container's network interface. This safely triggers and logs malicious outbound connection attempts without actually letting traffic escape.

A regex engine parses the `strace` output, tracks system calls (like `clone`, `execve`, `socket`, and `openat`), and builds a directed graph using `NetworkX`. Finally, a `RandomForestClassifier` trained on known malware evaluates the graph's topology to detect anomalous behavior.

## Installation
You need Python 3.9+ and Docker running on your machine.

```bash
git clone https://github.com/tejasprasad2008-afk/TraceTree.git
cd TraceTree

# Install the CLI tool in editable mode
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

## Advanced Training & Dataset Ingestion
TraceTree features an **Online Training Pipeline** that can fetch live malware samples from [MalwareBazaar](https://malwarebazaar.abuse.ch/).

### Local Training
If you want to train the model locally using the datasets in `data/`:

```bash
# Start the interactive training pipeline
cascade-train
```

During `cascade-train`, you will be prompted for a MalwareBazaar Auth Key. If provided, the tool will:
1.  **Ingest:** Fetch the latest malicious Python samples from MalwareBazaar.
2.  **Sandbox:** Run them through the Docker pipeline to extract fresh behavioral footprints.
3.  **Train:** Re-calculate the Random Forest weights to include the new data.
4.  **Sync:** Automatically cache the new model locally.

### Model Synchronization
To fetch the latest pre-trained model directly from the global cloud storage:

```bash
# Force download the latest global model
cascade-update
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

![Banner](banner.png)

## Threat Model
In late 2024, the highly obfuscated **XZ Utils** backdoor bypassed standard static scanning. Advanced supply chain malware often hides malicious operations deep within legitimate-looking test code or delayed payload fetches. By analyzing the runtime execution graph, TraceTree bypasses code obfuscation entirely to see exactly what external files, commands, and sockets a package actually tries to open.

## Contributing
Pull requests are welcome. Please ensure new features remain decoupled across the existing architecture.

## License
MIT
