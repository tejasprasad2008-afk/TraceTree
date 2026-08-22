"use client";
import { CSSProperties, ReactNode } from "react";

interface PanelProps {
  title?: string;
  children: ReactNode;
  actions?: ReactNode;
  className?: string;
  style?: CSSProperties;
}

export function Panel({ title, children, actions, className = "", style }: PanelProps) {
  return (
    <div
      className={className}
      style={{
        background: "var(--bg-panel)",
        border: "1px solid var(--border)",
        display: "flex",
        flexDirection: "column",
        ...style,
      }}
    >
      {title && (
        <div
          style={{
            height: 28,
            minHeight: 28,
            background: "var(--bg-panel-alt)",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "0 8px",
          }}
        >
          <span
            style={{
              fontSize: 11,
              color: "var(--text-muted)",
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              fontFamily: "var(--font-ui)",
            }}
          >
            {title}
          </span>
          {actions && (
            <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
              {actions}
            </div>
          )}
        </div>
      )}
      <div style={{ padding: 8, flex: 1, overflow: "hidden" }}>{children}</div>
    </div>
  );
}
