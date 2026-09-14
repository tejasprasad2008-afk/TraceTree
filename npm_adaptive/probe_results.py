"""Parse bounded, redacted import-probe observations from adaptive runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def load_import_probe_results(output_dir: Path) -> List[Dict[str, Any]]:
    """Return valid import outcomes without treating malformed output as data."""

    path = Path(output_dir) / "import-results.ndjson"
    if not path.is_file():
        return []
    results: List[Dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines[:1000]:
        if len(line) > 8 * 1024:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict) or record.get("event") != "import_probe":
            continue
        if record.get("loader") not in {"import", "require"}:
            continue
        if record.get("outcome") not in {"ok", "error"}:
            continue
        # Return only the stable, presentation-safe schema. Error text was
        # already bounded in the probe and synthetic canaries were redacted by
        # the sandbox runner before this parser reads it.
        result: Dict[str, Any] = {
            "specifier": record.get("specifier") if isinstance(record.get("specifier"), str) else "unknown",
            "loader": record["loader"],
            "path": record.get("path") if isinstance(record.get("path"), str) else None,
            "outcome": record["outcome"],
        }
        if result["outcome"] == "error" and isinstance(record.get("error"), dict):
            error = record["error"]
            result["error"] = {
                "name": error.get("name") if isinstance(error.get("name"), str) else "Error",
                "message": error.get("message") if isinstance(error.get("message"), str) else "",
            }
        results.append(result)
    return results
