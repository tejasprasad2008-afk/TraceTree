"use client";
import { Panel } from "../Panel";
import { DataTable, Column } from "../DataTable";
import { SeverityTag, SeverityLevel } from "../SeverityTag";

export interface ScanRow {
  id: string;
  target: string;
  verdict: "danger" | "caution" | "safe" | "pending";
  confidence: number;
  type: string;
  timestamp: string;
}

interface DashboardProps {
  stats: {
    scanned: number;
    threats: number;
    uptime_seconds: number;
    model_type: string;
    ollama_online: boolean;
    api_online: boolean;
  };
  recentScans: ScanRow[];
  onNavigate: (screen: string) => void;
}

function formatUptime(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

const COLUMNS: Column<ScanRow>[] = [
  { key: "target", label: "Target", width: 180 },
  { key: "type", label: "Type", width: 60 },
  {
    key: "verdict",
    label: "Verdict",
    width: 90,
    render: (v) => <SeverityTag level={v as SeverityLevel} />,
  },
  {
    key: "confidence",
    label: "Conf%",
    width: 60,
    render: (v) => `${v}%`,
  },
  { key: "timestamp", label: "Time" },
];

export function Dashboard({ stats, recentScans, onNavigate }: DashboardProps) {
  const statCards = [
    { label: "Total Scanned", value: stats.scanned, color: "var(--text-primary)" },
    {
      label: "Threats Found",
      value: stats.threats,
      color: stats.threats > 0 ? "var(--sev-danger)" : "var(--text-primary)",
    },
    { label: "Model", value: stats.model_type || "RF", color: "var(--text-muted)" },
    { label: "Uptime", value: formatUptime(stats.uptime_seconds), color: "var(--text-muted)" },
  ];

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 8,
        padding: 8,
        height: "100%",
        overflow: "auto",
        boxSizing: "border-box",
      }}
    >
      {/* Stat cards row */}
      <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
        {statCards.map((card) => (
          <div key={card.label} style={{ flex: 1 }}>
            <Panel title={card.label}>
              <div
                style={{
                  fontSize: 22,
                  fontFamily: "var(--font-mono)",
                  color: card.color,
                  fontWeight: 700,
                  padding: "4px 0",
                }}
              >
                {card.value}
              </div>
            </Panel>
          </div>
        ))}
      </div>

      {/* Recent activity table */}
      <div style={{ flex: 1, overflow: "hidden" }}>
        <Panel title="Recent Activity">
          <div style={{ overflow: "auto" }}>
            <DataTable
              columns={COLUMNS}
              rows={recentScans}
              getRowId={(r) => r.id}
              getRowSeverity={(r) => r.verdict as SeverityLevel}
              onRowClick={() => onNavigate("scan-history")}
            />
          </div>
        </Panel>
      </div>
    </div>
  );
}
