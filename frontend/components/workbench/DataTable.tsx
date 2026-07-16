"use client";
import { ReactNode, useState, useCallback } from "react";
import { SeverityLevel } from "./SeverityTag";

export interface Column<T> {
  key: string;
  label: string;
  width?: number;
  render?: (val: any, row: T) => ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  onRowClick?: (row: T) => void;
  selectedId?: string;
  getRowId: (row: T) => string;
  getRowSeverity?: (row: T) => SeverityLevel | undefined;
}

const SEV_BORDER: Record<string, string> = {
  danger: "var(--sev-danger)",
  caution: "var(--sev-caution)",
  safe: "var(--sev-safe)",
};

export function DataTable<T extends Record<string, any>>({
  columns,
  rows,
  onRowClick,
  selectedId,
  getRowId,
  getRowSeverity,
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [focusIdx, setFocusIdx] = useState<number>(0);

  const handleHeaderClick = useCallback(
    (key: string) => {
      if (sortKey === key) {
        setSortDir((d) => (d === "asc" ? "desc" : "asc"));
      } else {
        setSortKey(key);
        setSortDir("asc");
      }
    },
    [sortKey]
  );

  const sorted = sortKey
    ? [...rows].sort((a, b) => {
        const av = a[sortKey];
        const bv = b[sortKey];
        const cmp = String(av ?? "").localeCompare(String(bv ?? ""));
        return sortDir === "asc" ? cmp : -cmp;
      })
    : rows;

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = Math.min(focusIdx + 1, sorted.length - 1);
      setFocusIdx(next);
      if (onRowClick && sorted[next]) onRowClick(sorted[next]);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const prev = Math.max(focusIdx - 1, 0);
      setFocusIdx(prev);
      if (onRowClick && sorted[prev]) onRowClick(sorted[prev]);
    } else if (e.key === "Enter") {
      if (onRowClick && sorted[focusIdx]) onRowClick(sorted[focusIdx]);
    }
  };

  return (
    <div
      tabIndex={0}
      onKeyDown={handleKeyDown}
      style={{ outline: "none", width: "100%", overflow: "auto" }}
    >
      <table style={{ width: "100%", borderCollapse: "collapse", tableLayout: "fixed" }}>
        <thead>
          <tr
            style={{
              height: 24,
              background: "var(--bg-panel-alt)",
              borderBottom: "1px solid var(--border)",
            }}
          >
            {columns.map((col) => (
              <th
                key={col.key}
                onClick={() => handleHeaderClick(col.key)}
                style={{
                  width: col.width,
                  padding: "0 6px",
                  textAlign: "left",
                  fontSize: 11,
                  fontFamily: "var(--font-ui)",
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  fontWeight: 500,
                  cursor: "pointer",
                  userSelect: "none",
                  whiteSpace: "nowrap",
                }}
              >
                {col.label}
                {sortKey === col.key && (
                  <span style={{ marginLeft: 4, color: "var(--accent)" }}>
                    {sortDir === "asc" ? "▲" : "▼"}
                  </span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row, i) => {
            const id = getRowId(row);
            const isSelected = id === selectedId;
            const sev = getRowSeverity ? getRowSeverity(row) : undefined;
            const sevColor = sev ? SEV_BORDER[sev] : undefined;
            return (
              <tr
                key={id}
                onClick={() => {
                  setFocusIdx(i);
                  onRowClick && onRowClick(row);
                }}
                style={{
                  height: 24,
                  background: isSelected
                    ? "var(--bg-selected)"
                    : i % 2 === 0
                    ? "var(--bg-panel)"
                    : "var(--bg-inset)",
                  cursor: onRowClick ? "pointer" : "default",
                  borderLeft: sevColor ? `2px solid ${sevColor}` : "2px solid transparent",
                }}
                onMouseEnter={(e) => {
                  if (!isSelected)
                    (e.currentTarget as HTMLElement).style.background = "var(--bg-hover)";
                }}
                onMouseLeave={(e) => {
                  if (!isSelected)
                    (e.currentTarget as HTMLElement).style.background =
                      i % 2 === 0 ? "var(--bg-panel)" : "var(--bg-inset)";
                }}
              >
                {columns.map((col) => (
                  <td
                    key={col.key}
                    style={{
                      padding: "0 6px",
                      fontSize: 12,
                      fontFamily: "var(--font-ui)",
                      color: "var(--text-primary)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      verticalAlign: "middle",
                    }}
                  >
                    {col.render ? col.render(row[col.key], row) : String(row[col.key] ?? "")}
                  </td>
                ))}
              </tr>
            );
          })}
          {sorted.length === 0 && (
            <tr>
              <td
                colSpan={columns.length}
                style={{
                  padding: "16px 8px",
                  textAlign: "center",
                  fontSize: 11,
                  color: "var(--text-disabled)",
                  fontFamily: "var(--font-ui)",
                }}
              >
                No data
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
