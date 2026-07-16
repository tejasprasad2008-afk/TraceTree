"use client";

interface FilterBarProps {
  filters: string[];
  onClear: (filter: string) => void;
}

export function FilterBar({ filters, onClear }: FilterBarProps) {
  return (
    <div
      style={{
        height: 28,
        minHeight: 28,
        background: "var(--bg-panel-alt)",
        borderBottom: "1px solid var(--border)",
        display: "flex",
        alignItems: "center",
        padding: "0 8px",
        gap: 6,
        overflow: "hidden",
      }}
    >
      <span
        style={{
          fontSize: 11,
          color: filters.length > 0 ? "var(--text-muted)" : "var(--text-disabled)",
          fontFamily: "var(--font-ui)",
          whiteSpace: "nowrap",
          flexShrink: 0,
        }}
      >
        {filters.length > 0
          ? `Filter: hiding ${filters.length} filter${filters.length > 1 ? "s" : ""}`
          : "Filter: showing all items"}
      </span>
      {filters.map((f) => (
        <span
          key={f}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 3,
            background: "var(--bg-inset)",
            border: "1px solid var(--border)",
            padding: "0 5px",
            height: 18,
            fontSize: 11,
            color: "var(--text-primary)",
            fontFamily: "var(--font-ui)",
            whiteSpace: "nowrap",
          }}
        >
          {f}
          <button
            onClick={() => onClear(f)}
            style={{
              background: "none",
              border: "none",
              color: "var(--text-muted)",
              cursor: "pointer",
              padding: 0,
              fontSize: 10,
              lineHeight: 1,
              display: "flex",
              alignItems: "center",
            }}
          >
            x
          </button>
        </span>
      ))}
    </div>
  );
}
