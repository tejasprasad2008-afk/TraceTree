from setuptools import setup, find_packages
from setuptools.command.install import install
import sys

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
    install_requires=[
        "typer>=0.9.0",
        "rich>=13.4.0",
        "networkx>=3.0",
        "scikit-learn>=1.3.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "docker>=7.0.0",
        "google-cloud-storage>=2.10.0"
    ],
    entry_points={
        "console_scripts": [
            "cascade-analyze=cli:app",
            "cascade-train=cli:train_cli",
            "cascade-update=cli:update_cli",
        ],
    },
    cmdclass={
        'install': PostInstallMessage,
    },
)
