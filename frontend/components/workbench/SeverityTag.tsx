"use client";

export type SeverityLevel = "danger" | "caution" | "safe" | "pending" | "info";

const TAG_STYLES: Record<SeverityLevel, { bg: string; color: string }> = {
  danger:  { bg: "var(--sev-danger)",  color: "#fff" },
  caution: { bg: "var(--sev-caution)", color: "var(--accent-text)" },
  safe:    { bg: "var(--sev-safe)",    color: "#fff" },
  pending: { bg: "var(--bg-hover)",    color: "var(--text-muted)" },
  info:    { bg: "var(--sev-info)",    color: "#fff" },
};

export function SeverityTag({ level }: { level: SeverityLevel }) {
  const s = TAG_STYLES[level] ?? TAG_STYLES.pending;
  return (
    <span
      style={{
        background: s.bg,
        color: s.color,
        fontSize: "10px",
        letterSpacing: "0.06em",
        textTransform: "uppercase",
        padding: "2px 6px",
        fontFamily: "var(--font-ui)",
        fontWeight: 600,
        display: "inline-block",
        lineHeight: "1.4",
        flexShrink: 0,
      }}
    >
      {level}
    </span>
  );
}

export function cvssToLevel(score: number): SeverityLevel {
  if (score >= 7) return "danger";
  if (score >= 4) return "caution";
  return "safe";
}
