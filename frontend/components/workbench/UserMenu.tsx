"use client";
import { useState, useEffect, useRef } from "react";

interface UserMenuProps {
  apiKey: string;
  onApiKeyChange: (k: string) => void;
}

export function UserMenu({ apiKey, onApiKeyChange }: UserMenuProps) {
  const [open, setOpen] = useState(false);
  const [dockerStatus, setDockerStatus] = useState<{ available: boolean; version: string } | null>(null);
  const [watcherActive, setWatcherActive] = useState(false);
  const [keyDraft, setKeyDraft] = useState(apiKey);
  const ref = useRef<HTMLDivElement>(null);

  const fetchDocker = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/docker/status");
      if (res.ok) setDockerStatus(await res.json());
    } catch {
      setDockerStatus({ available: false, version: "" });
    }
  };

  // Fetch once on mount, then again each time the dropdown opens
  useEffect(() => { fetchDocker(); }, []);
  useEffect(() => { if (open) fetchDocker(); }, [open]);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const dot = (on: boolean, animated = false) => (
    <span
      className={animated && on ? "watcher-dot-active" : ""}
      style={{
        display: "inline-block",
        width: 6,
        height: 6,
        background: on ? "var(--sev-safe)" : "var(--sev-danger)",
        flexShrink: 0,
      }}
    />
  );

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        onClick={() => setOpen((o) => !o)}
        style={{
          height: 28,
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "0 10px",
          background: "var(--bg-panel-alt)",
          border: "none",
          borderLeft: "1px solid var(--border)",
          cursor: "pointer",
          color: "var(--text-primary)",
        }}
      >
        <span
          style={{
            width: 16,
            height: 16,
            background: "var(--accent)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 10,
            fontWeight: 700,
            color: "#000",
            fontFamily: "var(--font-ui)",
            flexShrink: 0,
          }}
        >
          D
        </span>
        <span style={{ fontSize: 11, fontFamily: "var(--font-ui)", color: "var(--text-muted)" }}>
          Local User
        </span>
        <span style={{ fontSize: 10, color: "var(--text-disabled)" }}>{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div
          style={{
            position: "absolute",
            top: 28,
            right: 0,
            width: 220,
            background: "var(--bg-panel)",
            border: "1px solid var(--border)",
            zIndex: 200,
          }}
        >
          <div style={{ padding: "6px 10px 4px" }}>
            <div style={{ fontSize: 10, color: "var(--text-disabled)", fontFamily: "var(--font-ui)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 4 }}>
              System
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6, height: 22 }}>
                {dot(!!dockerStatus?.available)}
                <span style={{ fontSize: 11, color: "var(--text-primary)", fontFamily: "var(--font-ui)", flex: 1 }}>Docker</span>
                <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                  {dockerStatus?.available ? dockerStatus.version || "online" : "offline"}
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 6, height: 22 }}>
                {dot(true)}
                <span style={{ fontSize: 11, color: "var(--text-primary)", fontFamily: "var(--font-ui)", flex: 1 }}>API :8000</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 6, height: 22 }}>
                {dot(watcherActive, true)}
                <span style={{ fontSize: 11, color: "var(--text-primary)", fontFamily: "var(--font-ui)", flex: 1 }}>Watcher</span>
                <button
                  onClick={() => setWatcherActive((v) => !v)}
                  style={{
                    fontSize: 10,
                    padding: "1px 6px",
                    background: "var(--bg-inset)",
                    border: "1px solid var(--border)",
                    color: "var(--text-muted)",
                    cursor: "pointer",
                    fontFamily: "var(--font-ui)",
                  }}
                >
                  {watcherActive ? "Stop" : "Start"}
                </button>
              </div>
            </div>
          </div>

          <div style={{ height: 1, background: "var(--border)", margin: "4px 0" }} />

          <div style={{ padding: "4px 10px" }}>
            <div style={{ fontSize: 10, color: "var(--text-disabled)", fontFamily: "var(--font-ui)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 4 }}>
              API Key
            </div>
            <input
              value={keyDraft}
              onChange={(e) => setKeyDraft(e.target.value)}
              onBlur={() => onApiKeyChange(keyDraft)}
              style={{
                width: "100%",
                background: "var(--bg-inset)",
                border: "1px solid var(--border)",
                color: "var(--text-primary)",
                fontSize: 11,
                fontFamily: "var(--font-mono)",
                padding: "2px 6px",
                height: 22,
                outline: "none",
              }}
            />
          </div>

          <div style={{ height: 1, background: "var(--border)", margin: "4px 0" }} />

          <button
            onClick={() => setOpen(false)}
            style={{
              display: "block",
              width: "100%",
              textAlign: "left",
              padding: "4px 10px",
              fontSize: 11,
              color: "var(--text-primary)",
              background: "none",
              border: "none",
              cursor: "pointer",
              fontFamily: "var(--font-ui)",
            }}
            onMouseEnter={(e) => ((e.target as HTMLElement).style.background = "var(--bg-hover)")}
            onMouseLeave={(e) => ((e.target as HTMLElement).style.background = "none")}
          >
            Settings
          </button>
        </div>
      )}
    </div>
  );
}
