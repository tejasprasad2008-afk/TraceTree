"use client";
import { useState, useRef, useCallback, useEffect } from "react";
import { RawWell } from "./RawWell";
import { SeverityTag, cvssToLevel } from "./SeverityTag";

interface CVEResult {
  id: string;
  summary: string;
  severity: string;
  score: number;
  url: string;
}

const PRESETS = [
  { label: "Analyze Package", cmd: "analyze", args: "urllib33 --type pip" },
  { label: "Watch Downloads", cmd: "watch", args: "" },
  { label: "Check File",      cmd: "check",   args: "/path/to/file" },
  { label: "Scan File",       cmd: "scan",    args: "/path/to/file --type dmg" },
  { label: "MCP Server",      cmd: "analyze", args: "/path/to/server.py --type mcp --ai" },
];

function shellQuotePath(p: string): string {
  return p.includes(" ") ? `"${p.replace(/"/g, '\\"')}"` : p;
}

interface CommandConsoleProps {
  apiKey: string;
  onScanComplete?: () => void;
}

const CVE_RE = /CVE-\d{4}-\d{4,}/g;

function parseCVEsFromLines(lines: string[]): string[] {
  const found = new Set<string>();
  for (const line of lines) {
    const matches = line.match(CVE_RE);
    if (matches) matches.forEach((m) => found.add(m));
  }
  return Array.from(found);
}

export function CommandConsole({ apiKey, onScanComplete }: CommandConsoleProps) {
  const [selectedPreset, setSelectedPreset] = useState<string | null>("analyze");
  const [cmd, setCmd] = useState("analyze");
  const [args, setArgs] = useState("urllib33 --type pip");
  const [lines, setLines] = useState<string[]>([
    "TraceTree Command Console ready.",
    "Select a preset or type a command.",
  ]);
  const [running, setRunning] = useState(false);
  const [cves, setCves] = useState<CVEResult[]>([]);
  const abortRef = useRef<AbortController | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const isElectron = typeof window !== "undefined" && !!(window as any).electron;

  const fetchCVEs = useCallback(async (pkgName: string) => {
    try {
      const res = await fetch("https://api.osv.dev/v1/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package: { name: pkgName, ecosystem: "PyPI" } }),
      });
      if (!res.ok) return;
      const data = await res.json();
      const vulns: CVEResult[] = (data.vulns || []).slice(0, 10).map((v: any) => {
        const sev = v.severity?.[0];
        const score = sev?.score ?? 0;
        return {
          id: v.id,
          summary: v.summary || v.details?.slice(0, 120) || "",
          severity: sev?.type || "UNKNOWN",
          score,
          url: `https://osv.dev/vulnerability/${v.id}`,
        };
      });
      setCves(vulns);
    } catch {
      // OSV unavailable, skip
    }
  }, []);

  const extractPkgName = (outputLines: string[]): string => {
    for (const line of outputLines) {
      const m = line.match(/Analyzing:\s+(\S+)/i);
      if (m) return m[1];
    }
    const firstArg = args.split(/\s+/)[0];
    return firstArg || "unknown";
  };

  const handleRun = useCallback(async () => {
    if (running) return;
    const fullCmd = `${cmd} ${args}`.trim();
    if (!fullCmd) return;

    setRunning(true);
    setCves([]);
    setLines((prev) => [...prev, `> ${fullCmd}`, "Starting..."]);

    abortRef.current = new AbortController();
    const collected: string[] = [];

    try {
      const res = await fetch("http://127.0.0.1:8000/api/execute", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey,
        },
        body: JSON.stringify({ command: fullCmd }),
        signal: abortRef.current.signal,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        setLines((prev) => [...prev, `Error: ${err.detail || res.statusText}`]);
        setRunning(false);
        return;
      }

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      if (!reader) {
        setLines((prev) => [...prev, "Error: no response stream"]);
        setRunning(false);
        return;
      }

      let buf = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const chunks = buf.split("\n\n");
        buf = chunks.pop() || "";
        for (const chunk of chunks) {
          if (chunk.startsWith("data: ")) {
            const line = chunk.slice(6).trimEnd();
            if (line) {
              collected.push(line);
              // Dim env/config dump lines instead of polluting main output
              const isEnvLine = /^(TRACETREE_|AI_ENABLED|CONTROLLED_NETWORK|API_KEYS|MODEL_PATH|OLLAMA_|YARA_|SANDBOX_)\S*[:=]/i.test(line)
                || /^[A-Z_]{4,}:\s+(true|false|not set|enabled|disabled|\d+)/i.test(line);
              if (!isEnvLine) {
                setLines((prev) => [...prev, line]);
              }
            }
          }
        }
      }

      // Parse CVE IDs directly from output lines
      const cveIds = parseCVEsFromLines(collected);
      if (cveIds.length > 0) {
        const directCves: CVEResult[] = cveIds.map((id) => ({
          id,
          summary: "Detected in scan output",
          severity: "CVSS_V3",
          score: 0,
          url: `https://osv.dev/vulnerability/${id}`,
        }));
        setCves(directCves);
        // Also try OSV lookup for the first CVE
        for (const id of cveIds.slice(0, 1)) {
          try {
            const res = await fetch("https://api.osv.dev/v1/query", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ query: id }),
            });
            if (res.ok) {
              const data = await res.json();
              if (data.vulns?.length) {
                const enriched: CVEResult[] = data.vulns.slice(0, 10).map((v: any) => {
                  const sev = v.severity?.[0];
                  return {
                    id: v.id,
                    summary: v.summary || v.details?.slice(0, 120) || "",
                    severity: sev?.type || "UNKNOWN",
                    score: sev?.score ?? 0,
                    url: `https://osv.dev/vulnerability/${v.id}`,
                  };
                });
                setCves(enriched);
              }
            }
          } catch { /* skip */ }
        }
      } else {
        // Fall back to package-name lookup for pip packages
        const pkgName = extractPkgName(collected);
        if (pkgName && pkgName !== "unknown" && (cmd === "analyze" || cmd === "scan")) {
          fetchCVEs(pkgName);
        }
      }
      onScanComplete?.();
    } catch (e: any) {
      if (e?.name !== "AbortError") {
        setLines((prev) => [...prev, `Connection error: ${e.message}`]);
      }
    } finally {
      setRunning(false);
    }
  }, [running, cmd, args, apiKey, fetchCVEs, onScanComplete]);

  const handleStop = () => {
    abortRef.current?.abort();
    setRunning(false);
    setLines((prev) => [...prev, "[stopped by user]"]);
  };

  return (
    <div style={{ display: "flex", height: "100%", background: "var(--bg-app)" }}>
      {/* Sidebar */}
      <div
        style={{
          width: 160,
          minWidth: 160,
          borderRight: "1px solid var(--border)",
          background: "var(--bg-panel)",
          overflow: "auto",
        }}
      >
        {PRESETS.map((p) => {
          const active = selectedPreset === p.cmd;
          return (
            <button
              key={p.cmd}
              onClick={() => {
                setSelectedPreset(p.cmd);
                setCmd(p.cmd);
                setArgs(p.args);
              }}
              style={{
                display: "block",
                width: "100%",
                textAlign: "left",
                height: 28,
                padding: "0 8px",
                background: active ? "var(--bg-selected)" : "transparent",
                borderLeft: active ? "2px solid var(--accent)" : "2px solid transparent",
                border: "none",
                borderLeftWidth: 2,
                borderLeftStyle: "solid",
                borderLeftColor: active ? "var(--accent)" : "transparent",
                color: active ? "var(--text-primary)" : "var(--text-muted)",
                fontSize: 12,
                fontFamily: "var(--font-ui)",
                cursor: "pointer",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {p.label}
            </button>
          );
        })}
      </div>

      {/* Center: terminal */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        {/* Top bar */}
        <div
          style={{
            height: 36,
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-panel-alt)",
            display: "flex",
            alignItems: "center",
            gap: 6,
            padding: "0 8px",
          }}
        >
          <span
            style={{
              fontSize: 11,
              color: "var(--text-disabled)",
              fontFamily: "var(--font-mono)",
              whiteSpace: "nowrap",
            }}
          >
            cascade-{cmd}
          </span>
          <input
            value={args}
            onChange={(e) => setArgs(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleRun()}
            placeholder={isElectron ? "drag file from Finder or type args" : "type full path or use Browse button"}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              const file = e.dataTransfer.files[0];
              if (!file) return;
              // file.path = Electron only; undefined in Chrome
              const fullPath: string | undefined = (file as any).path;
              if (!fullPath) {
                // Browser fallback: can't get OS path — show name and warn
                setLines((prev) => [
                  ...prev,
                  `[browser] Cannot read full path in Chrome. Use Browse button or type the path manually.`,
                  `[filename only] ${file.name}`,
                ]);
                setArgs(file.name);
                return;
              }
              // Only dmg/exe need explicit --type; zip/.zip auto-detects as zip-malware
              const ext = fullPath.split(".").pop()?.toLowerCase() ?? "";
              const supportsType = cmd === "analyze" || cmd === "scan";
              const explicitTypeMap: Record<string, string> = {
                dmg: "dmg", pkg: "dmg",
                exe: "exe", msi: "exe",
                whl: "pip",
              };
              const inferredType = explicitTypeMap[ext];
              let next = shellQuotePath(fullPath);
              if (inferredType && supportsType) next += ` --type ${inferredType}`;
              setArgs(next);
            }}
            style={{
              flex: 1,
              background: "var(--bg-inset)",
              border: "1px solid var(--border)",
              color: "var(--text-primary)",
              fontSize: 12,
              fontFamily: "var(--font-mono)",
              padding: "0 6px",
              height: 24,
              outline: "none",
            }}
          />
          <button
            onClick={running ? handleStop : handleRun}
            style={{
              height: 24,
              padding: "0 12px",
              background: running ? "var(--sev-danger)" : "var(--accent)",
              border: "none",
              color: "#000",
              fontSize: 11,
              fontFamily: "var(--font-ui)",
              fontWeight: 700,
              cursor: "pointer",
              whiteSpace: "nowrap",
            }}
          >
            {running ? "Stop" : "Run"}
          </button>
          {/* Browse button — opens native file picker; shows path in Electron, name-only in Chrome */}
          <button
            onClick={() => fileInputRef.current?.click()}
            title="Browse file (full path requires Electron)"
            style={{
              height: 24,
              padding: "0 8px",
              background: "var(--bg-hover)",
              border: "1px solid var(--border)",
              color: "var(--text-muted)",
              fontSize: 11,
              cursor: "pointer",
              whiteSpace: "nowrap",
            }}
          >
            Browse
          </button>
          <input
            ref={fileInputRef}
            type="file"
            style={{ display: "none" }}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              const fullPath: string | undefined = (file as any).path;
              const ext = (fullPath || file.name).split(".").pop()?.toLowerCase() ?? "";
              const supportsType = cmd === "analyze" || cmd === "scan";
              const explicitTypeMap: Record<string, string> = {
                dmg: "dmg", pkg: "dmg", exe: "exe", msi: "exe", whl: "pip",
              };
              const inferredType = explicitTypeMap[ext];
              let next = shellQuotePath(fullPath || file.name);
              if (inferredType && supportsType) next += ` --type ${inferredType}`;
              setArgs(next);
              e.target.value = ""; // reset so same file can be re-selected
            }}
          />
        </div>

        {/* Terminal output */}
        <div style={{ flex: 1, overflow: "hidden" }}>
          <RawWell lines={lines} autoScroll height="100%" />
        </div>
      </div>

      {/* Right: CVE panel */}
      <div
        style={{
          width: 240,
          minWidth: 240,
          borderLeft: "1px solid var(--border)",
          background: "var(--bg-panel)",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div
          style={{
            height: 28,
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-panel-alt)",
            display: "flex",
            alignItems: "center",
            padding: "0 8px",
          }}
        >
          <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-ui)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
            CVE Enrichment
          </span>
        </div>
        <div style={{ flex: 1, overflow: "auto", padding: 6 }}>
          {cves.length === 0 ? (
            <div style={{ fontSize: 11, color: "var(--text-disabled)", fontFamily: "var(--font-ui)", padding: "8px 0" }}>
              {running ? "Scanning..." : "No known CVEs"}
            </div>
          ) : (
            cves.map((cve) => (
              <div
                key={cve.id}
                style={{
                  marginBottom: 8,
                  padding: 6,
                  background: "var(--bg-inset)",
                  border: "1px solid var(--border)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 3 }}>
                  <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--sev-danger)" }}>{cve.id}</span>
                  <SeverityTag level={cvssToLevel(cve.score)} />
                  <span style={{ fontSize: 10, color: "var(--text-disabled)", fontFamily: "var(--font-mono)", marginLeft: "auto" }}>
                    {cve.score.toFixed(1)}
                  </span>
                </div>
                <p style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-ui)", margin: 0, overflow: "hidden", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>
                  {cve.summary}
                </p>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
