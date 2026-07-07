"""
orchestrator/session.py

Session persistence layer for TraceTree scan history.
Every scan produces an isolated session directory under .tracetree/history/.
Nothing is overwritten — each session is append-only.
"""

import json
import uuid
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_PROJECT_ROOT = Path(__file__).parent.parent


def _history_root() -> Path:
    return _PROJECT_ROOT / ".tracetree" / "history"


def create_session(target: str) -> Tuple[str, Path]:
    """
    Create a new unique session directory. Returns (session_id, session_path).
    Format: session-{ISO-timestamp}-{8-hex-uuid} — sortable and unique.
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    short_id = uuid.uuid4().hex[:8]
    session_id = f"session-{ts}-{short_id}"
    session_path = _history_root() / session_id
    session_path.mkdir(parents=True, exist_ok=False)
    return session_id, session_path


def _confined(session_path: Path, filename: str) -> Path:
    """Resolve filename inside session_path; raise if it escapes the directory."""
    out = (session_path / filename).resolve()
    try:
        out.relative_to(session_path.resolve())
    except ValueError:
        raise ValueError(f"Path traversal blocked: {filename!r} escapes session directory")
    return out


def save_json(session_path: Path, filename: str, data: Any) -> Path:
    out = _confined(session_path, filename)
    with open(out, "w") as f:
        json.dump(data, f, indent=2)
    return out


def save_text(session_path: Path, filename: str, text: str) -> Path:
    out = _confined(session_path, filename)
    out.write_text(text, encoding="utf-8")
    return out


def save_metadata(session_path: Path, metadata: Dict[str, Any]) -> Path:
    return save_json(session_path, "metadata.json", metadata)


def copy_file(session_path: Path, src: Optional[str], dest_name: str) -> Optional[Path]:
    if not src:
        return None
    src_path = Path(src)
    if not src_path.exists():
        return None
    dest = _confined(session_path, dest_name)
    shutil.copy2(src_path, dest)
    return dest


def session_index_path() -> Path:
    return _history_root() / "index.json"


def append_index(session_id: str, session_path: Path, target: str, verdict: str) -> None:
    """Append entry to flat index file for quick history listing."""
    index_path = session_index_path()
    entries: List[Dict[str, Any]] = []
    if index_path.exists():
        try:
            entries = json.loads(index_path.read_text())
        except Exception:
            entries = []
    entries.append({
        "session_id": session_id,
        "path": str(session_path),
        "target": target,
        "verdict": verdict,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    with open(index_path, "w") as f:
        json.dump(entries, f, indent=2)
