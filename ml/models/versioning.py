"""
Model versioning system for TraceTree.

Manages multiple model versions for reproducibility and A/B testing.
"""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional


class ModelVersionManager:
    """Manages model versions."""
    
    MODELS_DIR = Path(__file__).parent / "models"
    MANIFEST_FILE = MODELS_DIR / "manifest.json"
    
    def __init__(self):
        self.models_dir = self.MODELS_DIR
        self.models_dir.mkdir(exist_ok=True)
        
        # Load or create manifest
        self.manifest = self._load_manifest()
    
    def _load_manifest(self) -> dict:
        """Load model version manifest."""
        if self.MANIFEST_FILE.exists():
            with open(self.MANIFEST_FILE, 'r') as f:
                return json.load(f)
        return {
            "versions": {},
            "latest": None,
            "default": "v1.0-baseline"
        }
    
    def _save_manifest(self):
        """Save model version manifest."""
        with open(self.MANIFEST_FILE, 'w') as f:
            json.dump(self.manifest, f, indent=2)
    
    def save_version(
        self,
        version: str,
        model_path: Path,
        metadata: dict = None
    ) -> str:
        """
        Save a new model version.
        
        Args:
            version: Version string (e.g., "v1.0", "v2.0-rc1")
            model_path: Path to the model file
            metadata: Optional metadata dict
            
        Returns:
            Version string
        """
        version_dir = self.models_dir / version
        version_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy model file
        dest_path = version_dir / "model.skops"
        shutil.copy2(model_path, dest_path)
        
        # Save metadata
        meta = {
            "version": version,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "filename": str(dest_path.name),
            "metadata": metadata or {}
        }
        
        meta_file = version_dir / "metadata.json"
        with open(meta_file, 'w') as f:
            json.dump(meta, f, indent=2)
        
        # Update manifest
        self.manifest["versions"][version] = meta
        self.manifest["latest"] = version
        self._save_manifest()
        
        return version
    
    def get_version(self, version: Optional[str] = None) -> Optional[Path]:
        """
        Get path to a model version.
        
        Args:
            version: Version string (None = latest)
            
        Returns:
            Path to model or None
        """
        if version is None:
            version = self.manifest.get("latest") or self.manifest.get("default")
        
        if not version:
            # Fall back to legacy location
            legacy = Path(__file__).parent / "model.skops"
            return legacy if legacy.exists() else None
        
        version_dir = self.models_dir / version
        model_path = version_dir / "model.skops"
        if not model_path.exists():
            legacy_path = version_dir / "model.pkl"
            if legacy_path.exists():
                return legacy_path
        
        return model_path if model_path.exists() else None
    
    def list_versions(self) -> list:
        """List all available versions."""
        versions = []
        for version, meta in self.manifest.get("versions", {}).items():
            versions.append({
                "version": version,
                "created_at": meta.get("created_at"),
                "metadata": meta.get("metadata", {})
            })
        return sorted(versions, key=lambda x: x["created_at"] or "", reverse=True)
    
    def get_default_version(self) -> str:
        """Get the default version."""
        return self.manifest.get("default", "v1.0-baseline")


# CLI integration
def add_model_version_flags(parser):
    """Add --model-version and --list-versions to CLI parser."""
    parser.add_argument(
        "--model-version", "-m",
        type=str,
        default=None,
        help="Model version to use (e.g., v1.0, v2.0-rc1). Default: latest"
    )
    parser.add_argument(
        "--list-versions",
        action="store_true",
        help="List all available model versions"
    )
    return parser


# Standalone entry point
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Model version manager")
    subparsers = parser.add_subparsers(dest="command")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List versions")
    
    # Save command
    save_parser = subparsers.add_parser("save", help="Save version")
    save_parser.add_argument("version", help="Version string")
    save_parser.add_argument("model_path", type=Path, help="Model file path")
    save_parser.add_argument("--metadata", type=json.loads, default={}, help="Metadata JSON")
    
    args = parser.parse_args()
    
    manager = ModelVersionManager()
    
    if args.command == "list" or args.command is None:
        for v in manager.list_versions():
            print(f"{v['version']}: {v['created_at']}")
    elif args.command == "save":
        manager.save_version(args.version, args.model_path, args.metadata)
        print(f"[+] Saved model version {args.version}")