"use client";
import { useEffect, useState } from "react";
import { SplitPane } from "../SplitPane";
import { SearchBar } from "../SearchBar";
import { FilterBar } from "../FilterBar";
import { DataTable, Column } from "../DataTable";
import { Panel } from "../Panel";
import { RawWell } from "../RawWell";
import { SeverityTag, SeverityLevel } from "../SeverityTag";
import { parseQuery, matchRow } from "../search";

export interface ScanRow {
  id: string;
  target: string;
  verdict: "danger" | "caution" | "safe" | "pending";
  confidence: number;
  type: string;
  timestamp: string;
  sha256?: string;
  findings?: string;
}

const MOCK: ScanRow[] = [
  { id: "1", target: "urllib33", verdict: "danger", confidence: 92, type: "pip", timestamp: "2026-07-14 10:01", sha256: "abc123" },
  { id: "2", target: "requests", verdict: "safe", confidence: 5, type: "pip", timestamp: "2026-07-14 09:55", sha256: "def456" },
  { id: "3", target: "numpy", verdict: "safe", confidence: 3, type: "pip", timestamp: "2026-07-14 09:40", sha256: "ghi789" },
  { id: "4", target: "boto3-exfil", verdict: "danger", confidence: 99, type: "pip", timestamp: "2026-07-14 09:20" },
];

const FIELD_MAP = { verdict: "verdict", type: "type", file: "target", sha256: "sha256" } as const;

const COLUMNS: Column<ScanRow>[] = [
  { key: "target", label: "Target", width: 160 },
  { key: "type", label: "Type", width: 50 },
  {
    key: "verdict",
    label: "Verdict",
    width: 80,
    render: (v) => <SeverityTag level={v as SeverityLevel} />,
  },
  { key: "confidence", label: "Conf%", width: 55, render: (v) => `${v}%` },
  { key: "sha256", label: "SHA256", width: 90, render: (v) => v ? String(v).slice(0, 8) + "..." : "" },
  { key: "timestamp", label: "Time" },
];

interface ScanHistoryProps {
  apiKey: string;
}

export function ScanHistory({ apiKey }: ScanHistoryProps) {
  const [scans, setScans] = useState<ScanRow[]>(MOCK);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<ScanRow | null>(null);
  const [activeFilters, setActiveFilters] = useState<string[]>([]);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/scans", { headers: { "X-API-Key": apiKey } })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data?.scans) {
          const rows: ScanRow[] = data.scans.map((s: any) => ({
            id: s.id,
            target: s.target || s.package_name || "unknown",
            verdict: (s.verdict || "pending").toLowerCase() as ScanRow["verdict"],
            confidence: Math.round((s.confidence || 0) * (s.confidence <= 1 ? 100 : 1)),
            type: s.type || "pip",
            timestamp: s.createdAt || s.timestamp || "",
            sha256: s.sha256,
            findings: typeof s.findings === "string" ? s.findings : JSON.stringify(s.findings),
          }));
          if (rows.length) setScans(rows);
        }
      })
      .catch(() => {});
  }, [apiKey]);

  const parsed = parseQuery(query);
  const filtered = scans.filter((r) =>
    matchRow(r, parsed, FIELD_MAP as any)
  );

  const clearFilter = (f: string) => {
    setActiveFilters((p) => p.filter((x) => x !== f));
  };

  return (
    <SplitPane
      left={
        <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
          <SearchBar value={query} onChange={setQuery} />
          <FilterBar filters={activeFilters} onClear={clearFilter} />
          <div style={{ flex: 1, overflow: "auto" }}>
            <DataTable
              columns={COLUMNS}
              rows={filtered}
              getRowId={(r) => r.id}
              getRowSeverity={(r) => r.verdict as SeverityLevel}
              selectedId={selected?.id}
              onRowClick={setSelected}
            />
          </div>
        </div>
      }
      right={
        <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
          {selected ? (
            <Panel title={`Receipt: ${selected.target}`} style={{ flex: 1, height: "100%" } as any}>
              <RawWell
                lines={
                  selected.findings
                    ? JSON.stringify(JSON.parse(selected.findings), null, 2).split("\n")
                    : [`Target: ${selected.target}`, `Verdict: ${selected.verdict}`, `Confidence: ${selected.confidence}%`, `SHA256: ${selected.sha256 || "n/a"}`]
                }
                height="100%"
              />
            </Panel>
          ) : (
            <div style={{ padding: 16, fontSize: 11, color: "var(--text-disabled)", fontFamily: "var(--font-ui)" }}>
              Select a scan to view receipt
            </div>
          )}
        </div>
      }
      storageKey="scan-history-split"
      defaultSplit={45}
    />
  );
}
