from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from monitor.analyzers.base import AnalysisFinding, AnalyzerActions, SampleAnalyzer

log = logging.getLogger(__name__)

# Checked once at module import. Hard-fail at analysis time if missing.
_R2_BIN: str | None = shutil.which("r2")
MAX_DISASSEMBLY_BYTES = 50 * 1024 * 1024
MAX_INSTRUCTIONS = 256


def _require_r2() -> str:
    if _R2_BIN is None:
        raise RuntimeError(
            "radare2 not found on PATH. Install with: brew install radare2  "
            "StaticDisassemblyAnalyzer cannot run without it."
        )
    return _R2_BIN


def _resolve_offset(r2, target_offset: int | None, file_path: str) -> int | None:
    """Return a usable physical address.

    r2's aflj assigns offset=0 to all functions in macOS PIE Mach-O dylibs.
    Use isj (symbol table) to get real paddrs, which work as seek targets.
    If target_offset is given and non-zero, use it directly (caller sourced
    it from a YARA match offset, which is a file-relative byte offset).
    """
    if target_offset is not None and target_offset > 0:
        return target_offset

    syms_raw = r2.cmd("isj")
    try:
        syms: list[dict] = json.loads(syms_raw) if syms_raw.strip() else []
    except json.JSONDecodeError:
        return None

    # Prefer entry-like symbols; fall back to first FUNC symbol with non-zero paddr
    preferred = ("main", "entry0", "_start", "sym.main")
    for name in preferred:
        for s in syms:
            if s.get("name", "").endswith(name) and s.get("paddr", 0) > 0:
                return s["paddr"]

    for s in syms:
        if s.get("type") == "FUNC" and s.get("paddr", 0) > 0:
            return s["paddr"]

    return None


def disassemble_at(file_path: str, offset: int | None = None, max_insns: int = 32) -> dict[str, Any]:
    """Run r2 headless and return structured disassembly.

    Returns dict with keys:
        file_path, offset_used, function_name, instructions (list of dicts),
        error (str | None)
    """
    _require_r2()
    try:
        import r2pipe  # noqa: PLC0415
    except ImportError:
        raise RuntimeError("r2pipe not installed. Run: pip install r2pipe")

    result: dict[str, Any] = {
        "file_path": file_path,
        "offset_used": offset,
        "function_name": None,
        "instructions": [],
        "error": None,
    }

    sample_path = Path(file_path)
    if not sample_path.exists():
        result["error"] = f"file not found: {file_path}"
        return result
    if sample_path.stat().st_size > MAX_DISASSEMBLY_BYTES:
        result["error"] = f"file exceeds disassembly limit of {MAX_DISASSEMBLY_BYTES} bytes"
        return result
    max_insns = max(1, min(max_insns, MAX_INSTRUCTIONS))

    # Check magic bytes — r2 will "disassemble" text files as garbage without this.
    # ELF: \x7fELF, PE: MZ, Mach-O: \xfe\xed\xfa (32-bit), \xfe\xed\xfa\xcf (64-bit),
    # fat Mach-O: \xca\xfe\xba\xbe
    BINARY_MAGIC = (b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
    with open(file_path, "rb") as fh:
        header = fh.read(8)
    if not any(header.startswith(m) for m in BINARY_MAGIC):
        result["error"] = (
            f"not a supported binary (ELF/PE/Mach-O) — got header {header[:4]!r}. "
            "Disassembly does not apply to script files."
        )
        return result

    try:
        r2 = r2pipe.open(file_path, flags=["-2"])

        resolved = _resolve_offset(r2, offset, file_path)
        if resolved is None:
            result["error"] = "could not resolve a disassembly offset (no symbols, no YARA offset)"
            r2.quit()
            return result

        result["offset_used"] = resolved

        # Request only the bounded instruction window. Do not run whole-program
        # analysis or request complete function JSON for untrusted binaries.
        pdj_raw = r2.cmd(f"pdj {max_insns} @ {resolved}")
        if pdj_raw.strip():
            try:
                insns = json.loads(pdj_raw)
                result["instructions"] = [
                    {
                        "offset": insn.get("offset", resolved),
                        "disasm": insn.get("disasm", ""),
                        "type": insn.get("type", ""),
                        "bytes": insn.get("bytes", ""),
                    }
                    for insn in insns[:max_insns]
                ]
            except json.JSONDecodeError as e:
                result["error"] = f"pdj parse error: {e}"

        r2.quit()
    except Exception as e:
        result["error"] = str(e)

    return result


class StaticDisassemblyAnalyzer(SampleAnalyzer):
    """Thin r2pipe wrapper. Annotates — does not classify.

    Takes a binary file path + optional byte offset (from a YARA matched_offset).
    Emits one AnalysisFinding per file with verdict=None and evidence=disasm lines.

    inputs required:
        file_path   str   path to the binary file to disassemble
    inputs optional:
        offset      int   byte offset from YARA matched_offsets[0]["offset"]
                          if None, r2 resolves from symbol table
        max_insns   int   cap on instructions returned (default 32)

    Does NOT classify — finding.verdict is "ANNOTATED", confidence=0.0.
    Downstream consumers should treat this as supplementary evidence only.
    """

    name = "static_disassembly"

    def __init__(self) -> None:
        _require_r2()  # fail loudly at construction, not silently at analysis time

    def analyze(self, sample_id: str, inputs: dict, actions: AnalyzerActions) -> None:
        file_path: str = inputs["file_path"]
        offset: int | None = inputs.get("offset")
        max_insns: int = inputs.get("max_insns", 32)

        disasm = disassemble_at(file_path, offset=offset, max_insns=max_insns)

        if disasm["error"]:
            log.warning("StaticDisassemblyAnalyzer: %s — %s", file_path, disasm["error"])
            actions.raise_finding(AnalysisFinding(
                analyzer_name=self.name,
                sample_id=sample_id,
                verdict="ANNOTATED",
                confidence=0.0,
                evidence=[f"error: {disasm['error']}"],
                model_version="r2-headless",
                tags=["static", "error"],
                raw_output=disasm,
            ))
            return

        fn_name = disasm.get("function_name") or f"offset_{hex(disasm.get('offset_used', 0))}"
        evidence = [f"{fn_name} @ {hex(disasm.get('offset_used', 0))}:"]
        evidence += [
            f"  {hex(i['offset'])}  {i['disasm']}"
            for i in disasm["instructions"]
        ]

        actions.raise_finding(AnalysisFinding(
            analyzer_name=self.name,
            sample_id=sample_id,
            verdict="ANNOTATED",
            confidence=0.0,
            evidence=evidence,
            model_version="r2-headless",
            tags=["static", "disassembly"],
            raw_output=disasm,
        ))
