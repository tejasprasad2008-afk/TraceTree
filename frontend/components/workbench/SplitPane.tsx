"use client";
import { ReactNode, useRef, useState, useEffect, useCallback } from "react";

interface SplitPaneProps {
  left: ReactNode;
  right: ReactNode;
  defaultSplit?: number;
  storageKey?: string;
  minLeft?: number;
  minRight?: number;
}

export function SplitPane({
  left,
  right,
  defaultSplit = 40,
  storageKey,
  minLeft = 15,
  minRight = 15,
}: SplitPaneProps) {
  const [split, setSplit] = useState<number>(() => {
    if (storageKey && typeof window !== "undefined") {
      const stored = localStorage.getItem(`splitpane:${storageKey}`);
      if (stored) return Number(stored);
    }
    return defaultSplit;
  });

  const containerRef = useRef<HTMLDivElement>(null);
  const dragging = useRef(false);

  const onMouseMove = useCallback(
    (e: MouseEvent) => {
      if (!dragging.current || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const pct = ((e.clientX - rect.left) / rect.width) * 100;
      const clamped = Math.max(minLeft, Math.min(100 - minRight, pct));
      containerRef.current.style.setProperty("--split", `${clamped}%`);
    },
    [minLeft, minRight]
  );

  const onMouseUp = useCallback(
    (e: MouseEvent) => {
      if (!dragging.current || !containerRef.current) return;
      dragging.current = false;
      const rect = containerRef.current.getBoundingClientRect();
      const pct = ((e.clientX - rect.left) / rect.width) * 100;
      const clamped = Math.max(minLeft, Math.min(100 - minRight, pct));
      setSplit(clamped);
      if (storageKey) localStorage.setItem(`splitpane:${storageKey}`, String(clamped));
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    },
    [minLeft, minRight, storageKey]
  );

  useEffect(() => {
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    return () => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
    };
  }, [onMouseMove, onMouseUp]);

  return (
    <div
      ref={containerRef}
      style={{
        display: "flex",
        width: "100%",
        height: "100%",
        overflow: "hidden",
        ["--split" as any]: `${split}%`,
      }}
    >
      <div style={{ width: "var(--split)", overflow: "hidden", minWidth: 0 }}>{left}</div>
      <div
        onMouseDown={() => {
          dragging.current = true;
          document.body.style.cursor = "col-resize";
          document.body.style.userSelect = "none";
        }}
        style={{
          width: 4,
          minWidth: 4,
          background: "var(--border-strong)",
          cursor: "col-resize",
          flexShrink: 0,
        }}
      />
      <div style={{ flex: 1, overflow: "hidden", minWidth: 0 }}>{right}</div>
    </div>
  );
}
