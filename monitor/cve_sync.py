"""
CVE threat intelligence sync for TraceTree.

Fetches from NVD API v2, CISA KEV, and OSV.dev every 24 hours.
AI (Ollama) parses each CVE into TraceTree-readable behavioral indicators.
Results stored in .tracetree/cve_audit/cve_audit_trail.json.

API key setup (add to your shell or .env):
  NVD_API_KEY  — https://nvd.nist.gov/developers/request-an-api-key  (optional, 10x rate limit)
  CISA KEV     — no key needed
  OSV.dev      — no key needed
"""

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Callable, Optional

# Hard cap on API response size to prevent memory exhaustion from rogue servers
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB
# Max CVE description length forwarded to AI (limits prompt injection surface)
_MAX_DESC_LEN = 400

log = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent
_AUDIT_DIR = _PROJECT_ROOT / ".tracetree" / "cve_audit"
_AUDIT_FILE = _AUDIT_DIR / "cve_audit_trail.json"
_SYNC_LOCK_FILE = _AUDIT_DIR / "last_sync.json"

SYNC_INTERVAL_HOURS = 24

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_API_URL = "https://api.osv.dev/v1/query"

# Packages TraceTree actively monitors through sandbox
TRACETREE_SURFACE = {
    "python", "pip", "setuptools", "pip-tools", "wheel",
    "npm", "node", "nodejs", "yarn",
    "fastapi", "uvicorn", "starlette",
    "docker", "requests", "urllib3", "httpx", "aiohttp",
    "cryptography", "paramiko", "flask", "django",
    "pydantic", "sqlalchemy", "celery",
}


# --------------------------------------------------------------------------- #
#  Persistence
# --------------------------------------------------------------------------- #

def _ensure_audit_dir() -> None:
    _AUDIT_DIR.mkdir(parents=True, exist_ok=True)


def check_needs_sync() -> bool:
    """True if 24h have elapsed since last successful sync."""
    if not _SYNC_LOCK_FILE.exists():
        return True
    try:
        data = json.loads(_SYNC_LOCK_FILE.read_text())
        last = datetime.fromisoformat(data["last_sync"])
        return datetime.now(timezone.utc) - last > timedelta(hours=SYNC_INTERVAL_HOURS)
    except Exception:
        return True


def _update_sync_timestamp() -> None:
    _ensure_audit_dir()
    _SYNC_LOCK_FILE.write_text(json.dumps({
        "last_sync": datetime.now(timezone.utc).isoformat(),
    }))


def load_audit_trail() -> dict:
    if not _AUDIT_FILE.exists():
        return {"last_sync": None, "total_count": 0, "cves": []}
    try:
        return json.loads(_AUDIT_FILE.read_text())
    except Exception:
        return {"last_sync": None, "total_count": 0, "cves": []}


def save_audit_trail(trail: dict) -> None:
    """Atomic write via tmp + os.replace — safe against concurrent sync threads."""
    _ensure_audit_dir()
    tmp = _AUDIT_FILE.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(trail, f, indent=2)
    os.replace(tmp, _AUDIT_FILE)  # POSIX-atomic: no partial-read window


# --------------------------------------------------------------------------- #
#  Fetchers
# --------------------------------------------------------------------------- #

def _fetch_cisa_kev() -> list:
    """CISA Known Exploited Vulnerabilities — no API key needed."""
    import urllib.request
    try:
        with urllib.request.urlopen(CISA_KEV_URL, timeout=15) as r:
            data = json.loads(r.read(_MAX_RESPONSE_BYTES))
        result = []
        for v in data.get("vulnerabilities", []):
            result.append({
                "id": v.get("cveID", ""),
                "description": v.get("shortDescription", ""),
                "severity": "CRITICAL",
                "cvss_score": 9.0,
                "epss_score": None,
                "affected_products": [
                    v.get("product", "").lower(),
                    v.get("vendorProject", "").lower(),
                ],
                "cisa_kev": True,
                "published": v.get("dateAdded", ""),
                "required_action": v.get("requiredAction", ""),
                "source": "cisa_kev",
            })
        return result
    except Exception as e:
        log.warning("CISA KEV fetch failed: %s", e)
        return []


def _fetch_nvd_delta(api_key: Optional[str] = None, hours: int = 24) -> list:
    """NVD API v2 — CVEs published in the last N hours."""
    import urllib.request
    import urllib.parse

    pub_start = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {"pubStartDate": pub_start, "pubEndDate": pub_end, "resultsPerPage": 100}
    url = NVD_API_URL + "?" + urllib.parse.urlencode(params)
    # Sanitize key: strip whitespace and newlines to prevent HTTP header injection
    clean_key = re.sub(r"[\r\n\t]", "", api_key.strip())[:200] if api_key else None
    headers = {"apiKey": clean_key} if clean_key else {}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read(_MAX_RESPONSE_BYTES))

        result = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "",
            )
            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    m = metrics[key][0].get("cvssData", {})
                    cvss_score = m.get("baseScore")
                    severity = m.get("baseSeverity", "UNKNOWN")
                    break

            affected = []
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        parts = match.get("criteria", "").split(":")
                        if len(parts) > 4:
                            affected.append(parts[4].lower())

            result.append({
                "id": cve_id,
                "description": desc,
                "severity": severity,
                "cvss_score": cvss_score,
                "epss_score": None,
                "affected_products": list(set(affected)),
                "cisa_kev": False,
                "published": cve.get("published", ""),
                "source": "nvd",
            })
        return result
    except Exception as e:
        log.warning("NVD fetch failed: %s", e)
        return []


def _fetch_osv_delta() -> list:
    """OSV.dev — recent vulnerabilities for PyPI and npm ecosystems."""
    import urllib.request

    result = []
    for ecosystem in ("PyPI", "npm"):
        try:
            payload = json.dumps({"query": {"package": {"ecosystem": ecosystem}}}).encode()
            req = urllib.request.Request(
                OSV_API_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read(_MAX_RESPONSE_BYTES))

            for v in data.get("vulns", [])[:50]:
                affected_names = [
                    p.get("package", {}).get("name", "").lower()
                    for p in v.get("affected", [])
                ]
                result.append({
                    "id": v.get("id", ""),
                    "description": v.get("summary", ""),
                    "severity": "MEDIUM",
                    "cvss_score": None,
                    "epss_score": None,
                    "affected_products": affected_names,
                    "cisa_kev": False,
                    "published": v.get("published", ""),
                    "source": f"osv_{ecosystem.lower()}",
                })
        except Exception as e:
            log.warning("OSV %s fetch failed: %s", ecosystem, e)

    return result


# --------------------------------------------------------------------------- #
#  AI parsing
# --------------------------------------------------------------------------- #

def _sanitize_for_prompt(text: str) -> str:
    """Strip control characters and truncate to limit prompt injection surface."""
    # Remove control chars that could break prompt structure or inject instructions
    cleaned = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", str(text))
    return cleaned[:_MAX_DESC_LEN]


def _parse_cves_with_ai(cves: list) -> list:
    """Send CVEs to Ollama (qwen2.5-coder) for behavioral indicator extraction."""
    import urllib.request

    batch = cves[:20]

    # Sanitize all untrusted fields before embedding in prompt
    sanitized_batch = [
        {
            "id": re.sub(r"[^A-Za-z0-9\-]", "", str(c.get("id", "")))[:20],
            "description": _sanitize_for_prompt(c.get("description", "")),
            "affected_products": [
                re.sub(r"[^a-z0-9\-_\.]", "", str(p))[:50]
                for p in c.get("affected_products", [])[:10]
            ],
        }
        for c in batch
    ]

    prompt = (
        "You are a security analyst. For each CVE in the JSON array below, "
        "add exactly three fields and return a JSON array of the same length.\n"
        'Field 1: "suggested_action" — one defender action, max 20 words\n'
        'Field 2: "tracetree_indicators" — list of behavioral indicators '
        "(syscall names, file paths, network patterns)\n"
        'Field 3: "mitre_technique" — MITRE ATT&CK ID (e.g. T1055) or empty string\n\n'
        "Return ONLY the JSON array. No prose, no markdown fences.\n\n"
        "CVEs:\n"
        + json.dumps(sanitized_batch, indent=1)
    )

    try:
        payload = json.dumps({
            "model": "qwen2.5-coder:7b",
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }).encode()
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=90) as r:
            resp = json.loads(r.read(_MAX_RESPONSE_BYTES))

        parsed = json.loads(resp.get("response", "[]"))
        if isinstance(parsed, list) and len(parsed) == len(batch):
            for i, enrichment in enumerate(parsed):
                batch[i]["suggested_action"] = enrichment.get("suggested_action", "")
                batch[i]["tracetree_indicators"] = enrichment.get("tracetree_indicators", [])
                batch[i]["mitre_technique"] = enrichment.get("mitre_technique", "")
        return batch
    except Exception as e:
        log.warning("AI CVE parsing failed (%s) — using raw CVEs", e)
        for cve in cves:
            cve.setdefault("suggested_action", "Review and patch affected software.")
            cve.setdefault("tracetree_indicators", [])
            cve.setdefault("mitre_technique", "")
        return cves


# --------------------------------------------------------------------------- #
#  Relevance filtering
# --------------------------------------------------------------------------- #

def _filter_relevant(cves: list) -> list:
    """Keep CVEs relevant to TraceTree's detection surface."""
    result = []
    for cve in cves:
        if not cve.get("id"):
            continue
        affected = {p.lower() for p in cve.get("affected_products", [])}
        cvss = cve.get("cvss_score")
        if (
            cve.get("cisa_kev")
            or (affected & TRACETREE_SURFACE)
            or (cvss and float(cvss) >= 9.0)
        ):
            result.append(cve)
    return result


# --------------------------------------------------------------------------- #
#  Public sync entry point
# --------------------------------------------------------------------------- #

def sync_cves(
    nvd_api_key: Optional[str] = None,
    use_ai: bool = True,
    on_progress: Optional[Callable[[str], None]] = None,
) -> dict:
    """
    Full sync: fetch → deduplicate → filter → AI-parse → merge into audit trail.
    Returns the updated audit trail dict.
    """
    def emit(msg: str) -> None:
        if on_progress:
            on_progress(msg)
        log.info(msg)

    emit("Fetching CISA KEV...")
    kev = _fetch_cisa_kev()
    emit(f"  CISA KEV: {len(kev)} entries")

    emit("Fetching NVD delta (24h)...")
    nvd = _fetch_nvd_delta(api_key=nvd_api_key)
    emit(f"  NVD: {len(nvd)} new CVEs")

    emit("Fetching OSV (PyPI + npm)...")
    osv = _fetch_osv_delta()
    emit(f"  OSV: {len(osv)} entries")

    # Deduplicate by ID
    seen: set = set()
    deduped = []
    for c in kev + nvd + osv:
        if c["id"] and c["id"] not in seen:
            seen.add(c["id"])
            deduped.append(c)

    emit(f"Total unique: {len(deduped)} → filtering for relevance...")
    relevant = _filter_relevant(deduped)
    emit(f"Relevant to TraceTree surface: {len(relevant)}")

    if use_ai and relevant:
        emit(f"Parsing {min(len(relevant), 20)} CVEs with AI (Ollama)...")
        relevant = _parse_cves_with_ai(relevant)
        emit("AI parsing complete.")

    # Merge with existing trail — new entries prepended, no duplicates dropped
    trail = load_audit_trail()
    existing_ids = {c["id"] for c in trail.get("cves", [])}
    new_cves = [c for c in relevant if c["id"] not in existing_ids]

    trail["cves"] = new_cves + trail.get("cves", [])
    trail["last_sync"] = datetime.now(timezone.utc).isoformat()
    trail["total_count"] = len(trail["cves"])

    save_audit_trail(trail)
    _update_sync_timestamp()

    emit(f"Audit trail updated: {len(new_cves)} new CVEs added ({trail['total_count']} total)")
    return trail


# --------------------------------------------------------------------------- #
#  CVE matching (called during analyze / scan / watch)
# --------------------------------------------------------------------------- #

def match_cves_for_target(
    target: str,
    target_type: str,
    events: list,
    audit_trail: Optional[dict] = None,
) -> list:
    """
    Find CVEs relevant to a scanned target.
    Returns up to 10 matching CVE dicts sorted by relevance score.
    """
    if audit_trail is None:
        audit_trail = load_audit_trail()

    cves = audit_trail.get("cves", [])
    if not cves:
        return []

    pkg_name = (
        target.lower()
        .split("==")[0]
        .split("@")[0]
        .split("[")[0]
        .strip()
    )

    matches = []
    for cve in cves:
        score = 0
        reasons = []

        affected = [p.lower() for p in cve.get("affected_products", [])]
        has_name_match = pkg_name in affected or any(pkg_name in p for p in affected)
        has_surface_match = (
            (target_type == "pip" and any(p in TRACETREE_SURFACE for p in affected))
            or (target_type == "npm" and any("node" in p or "npm" in p for p in affected))
        )

        # Require a package-specific relevance signal before including this CVE.
        # Without this gate, all 1,644 CISA KEV entries score > 0 on every scan
        # because CVSS ≥ 9.0 adds score alone, making the list effectively constant
        # and unrelated to the actual target.
        if not (has_name_match or has_surface_match):
            continue

        if has_name_match:
            score += 10
            reasons.append(f"Package name match: {pkg_name}")

        if has_surface_match:
            score += 3
            if target_type == "pip":
                reasons.append("Affects pip ecosystem surface package")
            else:
                reasons.append("Affects npm ecosystem")

        cvss = cve.get("cvss_score")
        if cvss and float(cvss) >= 9.0:
            score += 3

        if cve.get("cisa_kev"):
            score += 5
            reasons.append("CISA KEV — actively exploited in the wild")

        if score > 0:
            entry = dict(cve)
            entry["_match_score"] = score
            entry["_match_reasons"] = reasons
            matches.append(entry)

    matches.sort(
        key=lambda c: (c["_match_score"], c.get("cvss_score") or 0),
        reverse=True,
    )
    return matches[:10]


# --------------------------------------------------------------------------- #
#  Background auto-sync (non-blocking)
# --------------------------------------------------------------------------- #

def auto_sync_background(nvd_api_key: Optional[str] = None) -> Optional[threading.Thread]:
    """
    Start a background daemon sync thread if 24h have elapsed.
    Returns the thread (already started) or None if sync not needed.
    """
    if not check_needs_sync():
        return None

    def _run() -> None:
        try:
            sync_cves(nvd_api_key=nvd_api_key, use_ai=True)
        except Exception as e:
            log.warning("Background CVE sync failed: %s", e)

    t = threading.Thread(target=_run, daemon=True, name="tracetree-cve-sync")
    t.start()
    return t
