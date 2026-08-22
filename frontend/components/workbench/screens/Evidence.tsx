"use client";
import { useState, useEffect } from "react";
import { DataTable, Column } from "../DataTable";
import { SplitPane } from "../SplitPane";
import { Panel } from "../Panel";
import { SeverityLevel } from "../SeverityTag";

export interface SyscallEvent {
  id: number;
  syscall: string;
  pid: number;
  target: string;
  severity: "LOW" | "MED" | "HIGH";
  flag: boolean;
}

interface EvidenceProps {
  events: SyscallEvent[];
  apiKey?: string;
}

const SEV_TO_LEVEL: Record<string, SeverityLevel> = {
  HIGH: "danger",
  MED: "caution",
  LOW: "info",
};

const SIGNAL_LABELS: Record<string, string> = {
  temporal_pattern: "Rapid Process Burst",
  process_count: "Processes Spawned",
  file_write_count: "Files Written",
  external_connect_count: "External Connections",
  sensitive_file_read_count: "Sensitive File Reads",
};

const SIGNAL_DESC: Record<string, string> = {
  temporal_pattern: "Multiple processes spawned in rapid succession — common in droppers and unpackers",
  process_count: "Total subprocesses launched during sandbox execution",
  file_write_count: "Total files written to disk during sandbox execution",
  external_connect_count: "Outbound network connections attempted (0 = no C2 contact)",
  sensitive_file_read_count: "Reads to sensitive system paths (credentials, keychains, etc.)",
};

const COLUMNS: Column<SyscallEvent>[] = [
  { key: "id", label: "#", width: 36 },
  { key: "syscall", label: "Behavior Signal", width: 200,
    render: (v) => <span style={{ fontFamily: "var(--font-ui)", fontSize: 11 }}>{SIGNAL_LABELS[v as string] || String(v)}</span>
  },
  { key: "target", label: "Value / Detail" },
  {
    key: "severity",
    label: "Risk",
    width: 46,
    render: (v) => (
      <span style={{
        fontSize: 10, fontFamily: "var(--font-ui)",
        color: v === "HIGH" ? "var(--sev-danger)" : v === "MED" ? "var(--sev-caution)" : "var(--text-muted)",
        fontWeight: 600,
      }}>
        {v}
      </span>
    ),
  },
  {
    key: "flag",
    label: "Alert",
    width: 44,
    render: (v) => (v ? <span style={{ color: "var(--sev-danger)", fontSize: 10, fontWeight: 700 }}>FLAGGED</span> : ""),
  },
];

interface YaraFinding {
  rule_name: string;
  severity: string;
  description: string;
  file_path: string;
  matched_strings: string[];
  matched_offsets: { text: string; offset: number }[];
}

interface DisassemblyResult {
  file_path: string;
  offset_used: number | null;
  function_name: string | null;
  instructions: { offset: number; disasm: string; type: string; bytes: string }[];
  error: string | null;
}

interface SessionScan {
  id: string;
  target: string;
  verdict: string;
  type: string;
  timestamp: string;
  findings?: string;
  yara_findings?: YaraFinding[];
}

export function Evidence({ events: propEvents, apiKey }: EvidenceProps) {
  const [sevFilters, setSevFilters] = useState<string[]>([]);
  const [selected, setSelected] = useState<SyscallEvent | null>(null);
  const [sessionEvents, setSessionEvents] = useState<SyscallEvent[]>([]);
  const [sessionMeta, setSessionMeta] = useState<{ target: string; verdict: string; timestamp: string } | null>(null);
  const [yaraFindings, setYaraFindings] = useState<YaraFinding[]>([]);
  const [disasmResult, setDisasmResult] = useState<DisassemblyResult | null>(null);
  const [disasmLoading, setDisasmLoading] = useState(false);
  const [disasmError, setDisasmError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!apiKey) return;
    setLoading(true);
    fetch("http://127.0.0.1:8000/api/scans", { headers: { "X-API-Key": apiKey } })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data?.scans?.length) return;
        const latest: SessionScan = data.scans[0];
        setSessionMeta({ target: latest.target, verdict: latest.verdict, timestamp: latest.timestamp });
        if (latest.yara_findings?.length) {
          setYaraFindings(latest.yara_findings);
        }
        if (latest.findings) {
          try {
            const ob = JSON.parse(latest.findings);
            const rows: SyscallEvent[] = [];
            (ob.matched_signatures || []).forEach((sig: any, i: number) => {
              rows.push({ id: i + 1, syscall: sig.name || "signature", pid: 0, target: sig.evidence || sig.name || "", severity: sig.severity === "HIGH" ? "HIGH" : sig.severity === "MED" ? "MED" : "LOW", flag: true });
            });
            (ob.matched_temporal_patterns || []).forEach((pat: string) => {
              rows.push({ id: rows.length + 1, syscall: "temporal_pattern", pid: 0, target: pat, severity: "MED", flag: true });
            });
            if (ob.process_count != null) rows.push({ id: rows.length + 1, syscall: "process_count", pid: 0, target: String(ob.process_count), severity: ob.process_count > 5 ? "HIGH" : "LOW", flag: ob.process_count > 5 });
            if (ob.file_write_count != null) rows.push({ id: rows.length + 1, syscall: "file_write_count", pid: 0, target: String(ob.file_write_count), severity: ob.file_write_count > 10 ? "MED" : "LOW", flag: false });
            if (ob.external_connect_count != null) rows.push({ id: rows.length + 1, syscall: "external_connect_count", pid: 0, target: String(ob.external_connect_count), severity: ob.external_connect_count > 0 ? "HIGH" : "LOW", flag: ob.external_connect_count > 0 });
            if (ob.sensitive_file_read_count != null) rows.push({ id: rows.length + 1, syscall: "sensitive_file_read_count", pid: 0, target: String(ob.sensitive_file_read_count), severity: ob.sensitive_file_read_count > 0 ? "HIGH" : "LOW", flag: ob.sensitive_file_read_count > 0 });
            if (rows.length > 0) setSessionEvents(rows);
          } catch { /* malformed */ }
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [apiKey]);

  const events = propEvents.length > 0 ? propEvents : sessionEvents;
  const filteredEvents = sevFilters.length ? events.filter((e) => !sevFilters.includes(e.severity)) : events;

  const toggleFilter = (sev: string) => {
    setSevFilters((p) => p.includes(sev) ? p.filter((x) => x !== sev) : [...p, sev]);
  };

  const requestDisasm = async (finding: YaraFinding) => {
    const firstOffset = finding.matched_offsets?.[0];
    // Only attempt disassembly for binary-file hits (file_path is inside quarantine dir)
    if (!finding.file_path.includes(".tracetree/quarantine")) return;
    setDisasmResult(null);
    setDisasmError(null);
    setDisasmLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/analyze/disassembly", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": apiKey ?? "" },
        body: JSON.stringify({
          file_path: finding.file_path,
          offset: firstOffset?.offset ?? null,
          max_insns: 32,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        setDisasmError(err.detail ?? "disassembly failed");
        return;
      }
      const data: DisassemblyResult = await res.json();
      setDisasmResult(data);
    } catch (e: any) {
      setDisasmError(String(e));
    } finally {
      setDisasmLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {sessionMeta && (
        <div style={{ height: 22, background: "var(--bg-panel)", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 8, padding: "0 8px" }}>
          <span style={{ fontSize: 10, color: "var(--text-disabled)", fontFamily: "var(--font-ui)" }}>Latest scan:</span>
          <span style={{ fontSize: 10, color: "var(--text-primary)", fontFamily: "var(--font-mono)" }}>{sessionMeta.target}</span>
          <span style={{ fontSize: 10, color: sessionMeta.verdict === "danger" ? "var(--sev-danger-text)" : sessionMeta.verdict === "caution" ? "var(--sev-caution)" : "var(--sev-safe)", fontFamily: "var(--font-ui)", fontWeight: 700 }}>{sessionMeta.verdict.toUpperCase()}</span>
          <span style={{ fontSize: 10, color: "var(--text-disabled)", fontFamily: "var(--font-ui)", marginLeft: "auto" }}>{sessionMeta.timestamp}</span>
        </div>
      )}
      <div style={{ height: 28, borderBottom: "1px solid var(--border)", background: "var(--bg-panel-alt)", display: "flex", alignItems: "center", gap: 8, padding: "0 8px" }}>
        <span style={{ fontSize: 10, color: "var(--text-disabled)", fontFamily: "var(--font-ui)", marginRight: 4 }}>RISK:</span>
        {(["HIGH", "MED", "LOW"] as const).map((sev) => (
          <button key={sev} onClick={() => toggleFilter(sev)} style={{
            fontSize: 10, fontFamily: "var(--font-ui)", padding: "2px 8px",
            background: sevFilters.includes(sev) ? "var(--bg-inset)" : "transparent",
            border: "1px solid var(--border)",
            color: sev === "HIGH" ? "var(--sev-danger)" : sev === "MED" ? "var(--sev-caution)" : "var(--text-muted)",
            cursor: "pointer", textDecoration: sevFilters.includes(sev) ? "line-through" : "none",
          }}>
            {sev}
          </button>
        ))}
        <span style={{ fontSize: 11, color: "var(--text-disabled)", fontFamily: "var(--font-ui)", marginLeft: 4 }}>
          {loading ? "Loading..." : `${filteredEvents.length} signals`}
        </span>
      </div>

      {yaraFindings.length > 0 && (
        <div style={{ borderBottom: "1px solid var(--border)", background: "var(--bg-panel-alt)", padding: "6px 8px" }}>
          <div style={{ fontSize: 10, color: "var(--text-disabled)", fontFamily: "var(--font-ui)", marginBottom: 4 }}>
            YARA RULE MATCHES
          </div>
          {yaraFindings.map((yf, i) => {
            const isBinary = yf.file_path.includes(".tracetree/quarantine");
            const hasOffset = yf.matched_offsets?.length > 0;
            return (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                <span style={{
                  fontSize: 10, fontFamily: "var(--font-ui)", fontWeight: 700,
                  color: yf.severity === "critical" ? "var(--sev-danger)" : yf.severity === "high" ? "var(--sev-caution)" : "var(--text-muted)",
                }}>
                  {yf.severity.toUpperCase()}
                </span>
                <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text-primary)" }}>
                  {yf.rule_name}
                </span>
                <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-ui)" }}>
                  {yf.description}
                </span>
                {isBinary && hasOffset && (
                  <button
                    onClick={() => requestDisasm(yf)}
                    disabled={disasmLoading}
                    style={{
                      marginLeft: "auto", fontSize: 10, fontFamily: "var(--font-ui)",
                      padding: "2px 8px", background: "var(--bg-inset)",
                      border: "1px solid var(--border)", color: "var(--text-primary)",
                      cursor: disasmLoading ? "wait" : "pointer",
                    }}
                  >
                    {disasmLoading ? "…" : "VIEW DISASM"}
                  </button>
                )}
              </div>
            );
          })}
          {(disasmResult || disasmError) && (
            <div style={{ marginTop: 6, padding: "6px 8px", background: "var(--bg-inset)", border: "1px solid var(--border)", maxHeight: 200, overflow: "auto" }}>
              {disasmError && (
                <div style={{ fontSize: 11, color: "var(--sev-danger)", fontFamily: "var(--font-mono)" }}>
                  {disasmError}
                </div>
              )}
              {disasmResult && (
                <>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-ui)", marginBottom: 4 }}>
                    {disasmResult.function_name ?? `offset ${disasmResult.offset_used}`} · {disasmResult.instructions.length} insns · {disasmResult.file_path.split("/").pop()}
                  </div>
                  {disasmResult.instructions.map((ins, j) => (
                    <div key={j} style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text-primary)", lineHeight: 1.6 }}>
                      <span style={{ color: "var(--text-muted)", marginRight: 12 }}>{ins.offset ? `0x${ins.offset.toString(16)}` : ""}</span>
                      <span style={{ color: ins.type === "call" ? "var(--sev-caution)" : ins.type === "jmp" ? "var(--accent)" : "var(--text-primary)" }}>
                        {ins.disasm}
                      </span>
                    </div>
                  ))}
                </>
              )}
            </div>
          )}
        </div>
      )}

      <div style={{ flex: 1, overflow: "hidden" }}>
        <SplitPane
          left={
            <div style={{ height: "100%", overflow: "auto" }}>
              <DataTable
                columns={COLUMNS}
                rows={filteredEvents}
                getRowId={(r) => String(r.id)}
                getRowSeverity={(r) => SEV_TO_LEVEL[r.severity]}
                selectedId={selected ? String(selected.id) : undefined}
                onRowClick={setSelected}
              />
            </div>
          }
          right={
            selected ? (
              <Panel title={`Signal: ${SIGNAL_LABELS[selected.syscall] || selected.syscall}`} style={{ height: "100%" }}>
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  {SIGNAL_DESC[selected.syscall] && (
                    <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-ui)", lineHeight: 1.5, padding: "6px 8px", background: "var(--bg-inset)", border: "1px solid var(--border)" }}>
                      {SIGNAL_DESC[selected.syscall]}
                    </div>
                  )}
                  <div style={{ fontSize: 12, fontFamily: "var(--font-mono)", color: "var(--text-primary)", display: "flex", flexDirection: "column", gap: 6 }}>
                    <div style={{ display: "flex", gap: 8 }}>
                      <span style={{ color: "var(--text-muted)", minWidth: 90 }}>signal</span>
                      <span>{SIGNAL_LABELS[selected.syscall] || selected.syscall}</span>
                    </div>
                    <div style={{ display: "flex", gap: 8 }}>
                      <span style={{ color: "var(--text-muted)", minWidth: 90 }}>value</span>
                      <span>{selected.target}</span>
                    </div>
                    <div style={{ display: "flex", gap: 8 }}>
                      <span style={{ color: "var(--text-muted)", minWidth: 90 }}>risk level</span>
                      <span style={{ color: selected.severity === "HIGH" ? "var(--sev-danger)" : selected.severity === "MED" ? "var(--sev-caution)" : "var(--text-muted)", fontWeight: 600 }}>{selected.severity}</span>
                    </div>
                    <div style={{ display: "flex", gap: 8 }}>
                      <span style={{ color: "var(--text-muted)", minWidth: 90 }}>alert</span>
                      <span style={{ color: selected.flag ? "var(--sev-danger)" : "var(--text-muted)" }}>{selected.flag ? "Flagged as suspicious" : "Within normal range"}</span>
                    </div>
                  </div>
                </div>
              </Panel>
            ) : (
              <div style={{ padding: 16, fontSize: 11, color: "var(--text-disabled)", fontFamily: "var(--font-ui)" }}>
                Select a behavior signal to inspect
              </div>
            )
          }
          defaultSplit={60}
          storageKey="evidence-split"
        />
      </div>
    </div>
  );
}
