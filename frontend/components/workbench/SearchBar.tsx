"use client";
import { useState, useRef, useEffect } from "react";
import { parseQuery, HTTPQL_COMPLETIONS, HTTPQL_FIELDS } from "./search";

interface SearchBarProps {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}

export function SearchBar({ value, onChange, placeholder = "verdict:danger type:exe ..." }: SearchBarProps) {
  const [completions, setCompletions] = useState<string[]>([]);
  const [compField, setCompField] = useState<string>("");
  const [compIdx, setCompIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const parsed = parseQuery(value);

  useEffect(() => {
    if (!value) {
      setCompletions([]);
      return;
    }
    const lastWord = value.split(" ").pop() || "";
    const colonIdx = lastWord.lastIndexOf(":");
    if (colonIdx > 0) {
      const field = lastWord.slice(0, colonIdx).replace(/^-/, "");
      if (HTTPQL_FIELDS.includes(field as any) && HTTPQL_COMPLETIONS[field]) {
        const typed = lastWord.slice(colonIdx + 1).toLowerCase();
        const matches = HTTPQL_COMPLETIONS[field].filter((c) =>
          c.startsWith(typed)
        );
        setCompletions(matches);
        setCompField(field);
        setCompIdx(0);
        return;
      }
    }
    setCompletions([]);
    setCompField("");
  }, [value]);

  const applyCompletion = (comp: string) => {
    const parts = value.split(" ");
    const last = parts[parts.length - 1] || "";
    const colonIdx = last.lastIndexOf(":");
    const prefix = last.slice(0, colonIdx + 1);
    parts[parts.length - 1] = prefix + comp;
    onChange(parts.join(" ") + " ");
    setCompletions([]);
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (completions.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setCompIdx((i) => Math.min(i + 1, completions.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setCompIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter" || e.key === "Tab") {
      e.preventDefault();
      applyCompletion(completions[compIdx]);
    } else if (e.key === "Escape") {
      setCompletions([]);
    }
  };

  return (
    <div style={{ position: "relative", display: "flex", alignItems: "center", width: "100%" }}>
      <span
        style={{
          fontSize: 10,
          color: "var(--text-disabled)",
          fontFamily: "var(--font-ui)",
          padding: "0 6px",
          whiteSpace: "nowrap",
          letterSpacing: "0.06em",
          textTransform: "uppercase",
        }}
      >
        Filter
      </span>

      <div style={{ flex: 1, position: "relative", display: "flex", alignItems: "center", flexWrap: "wrap", gap: 2, background: "var(--bg-inset)", border: "1px solid var(--border)", padding: "0 4px", minHeight: 28 }}>
        {parsed.tokens.map((tok, i) => (
          <span
            key={i}
            style={{
              display: "inline-flex",
              alignItems: "center",
              background: "var(--bg-hover)",
              border: "1px solid var(--border)",
              fontSize: 10,
              color: tok.negated ? "var(--sev-danger)" : "var(--accent)",
              fontFamily: "var(--font-mono)",
              padding: "1px 4px",
              whiteSpace: "nowrap",
            }}
          >
            {tok.negated ? "-" : ""}
            {tok.field}:{tok.value}
          </span>
        ))}
        <input
          ref={inputRef}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={parsed.tokens.length === 0 ? placeholder : ""}
          style={{
            flex: 1,
            minWidth: 80,
            background: "transparent",
            border: "none",
            outline: "none",
            fontSize: 12,
            fontFamily: "var(--font-mono)",
            color: "var(--text-primary)",
            height: 26,
            padding: "0 2px",
          }}
        />
      </div>

      {value && (
        <button
          onClick={() => onChange("")}
          style={{
            background: "none",
            border: "none",
            color: "var(--text-disabled)",
            cursor: "pointer",
            fontSize: 11,
            padding: "0 6px",
            height: 28,
          }}
        >
          x
        </button>
      )}

      {completions.length > 0 && (
        <div
          style={{
            position: "absolute",
            top: 28,
            left: 0,
            right: 0,
            background: "var(--bg-panel)",
            border: "1px solid var(--border)",
            zIndex: 100,
          }}
        >
          {completions.slice(0, 6).map((c, i) => (
            <div
              key={c}
              onMouseDown={(e) => {
                e.preventDefault();
                applyCompletion(c);
              }}
              style={{
                padding: "4px 10px",
                fontSize: 12,
                fontFamily: "var(--font-mono)",
                color: i === compIdx ? "var(--accent)" : "var(--text-primary)",
                background: i === compIdx ? "var(--bg-hover)" : "transparent",
                cursor: "pointer",
              }}
            >
              {compField}:{c}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
