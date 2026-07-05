from setuptools import setup, find_packages
from setuptools.command.install import install

class PostInstallMessage(install):
    def run(self):
        install.run(self)
        print("\n" + "="*60)
        print("  TraceTree (cascade-analyzer) installed successfully!")
        print("  To begin behavioral analysis, run: cascade-analyze --help")
        print("="*60 + "\n")

setup(
    name="cascade-analyzer",
    version="1.0.0",
    description="Cascading Behavioral Propagation Analyzer for Python Packages",
    packages=find_packages(),
    py_modules=["cli"],
    package_data={
        "ml": ["model.skops", "metrics.json"],
    },
    install_requires=[
        "typer>=0.9.0",
        "rich>=13.4.0",
        "networkx>=3.0",
        "scikit-learn>=1.3.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "docker>=7.0.0",
        "google-cloud-storage>=2.10.0",
        "requests>=2.25.1",
        "skops>=0.10.0",
    ],
    entry_points={
        "console_scripts": [
            "cascade-analyze=cli:app",
            "cascade-train=cli:train_cli",
            "cascade-watch=cli:watch_app",
            "cascade-check=cli:check_cli",
            "cascade-scan=cli:scan_app",
            "cascade-install-hook=cli:install_hook_cli",
            "cascade-uninstall-hook=cli:uninstall_hook_cli",
        ],
    },
    cmdclass={
        'install': PostInstallMessage,
    },
)
