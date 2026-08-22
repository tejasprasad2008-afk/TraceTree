"use client";
import { useEffect, useRef } from "react";

interface RawWellProps {
  lines: string[];
  autoScroll?: boolean;
  height?: string;
  highlightPattern?: RegExp;
}

export function RawWell({ lines, autoScroll = false, height = "100%", highlightPattern }: RawWellProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "instant" });
    }
  }, [lines, autoScroll]);

  return (
    <div
      style={{
        background: "var(--bg-inset)",
        border: "1px solid var(--border)",
        overflow: "auto",
        height,
        padding: "6px 8px",
        fontFamily: "var(--font-mono)",
        fontSize: "12px",
        lineHeight: "1.5",
        color: "var(--text-primary)",
      }}
    >
      {lines.map((line, i) => {
        const isFlagged = highlightPattern ? highlightPattern.test(line) : false;
        const isSyscall = /^\s*\d+\s+\w+\(/.test(line);
        return (
          <div
            key={i}
            style={{
              color: isFlagged
                ? "var(--sev-danger-text)"
                : isSyscall
                ? "var(--sev-info)"
                : "var(--text-primary)",
              whiteSpace: "pre",
            }}
          >
            <span style={{ color: "var(--text-disabled)", userSelect: "none", marginRight: 8 }}>
              {String(i + 1).padStart(4, " ")}
            </span>
            {line}
          </div>
        );
      })}
      <div ref={bottomRef} />
    </div>
  );
}
