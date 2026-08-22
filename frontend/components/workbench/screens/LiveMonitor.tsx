"use client";
import { useEffect, useRef, useState } from "react";
import { RawWell } from "../RawWell";
import { SeverityTag, SeverityLevel } from "../SeverityTag";

interface LiveMonitorProps {
  apiKey: string;
}

interface LiveState {
  status: "IDLE" | "SCANNING" | "COMPLETE" | "WS_OFFLINE";
  target: string;
  stage: string;
}

interface RecentScan {
  id: string;
  target: string;
  verdict: string;
  type: string;
  timestamp: string;
  confidence: number;
}

export function LiveMonitor({ apiKey }: LiveMonitorProps) {
  const [live, setLive] = useState<LiveState>({ status: "IDLE", target: "", stage: "" });
  const [wsLines, setWsLines] = useState<string[]>(["Connecting to live orchestrator feed..."]);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const sessionStartRef = useRef<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const STATUS_COLOR: Record<string, string> = {
    IDLE: "var(--text-disabled)",
    SCANNING: "var(--sev-caution)",
    COMPLETE: "var(--sev-safe)",
    WS_OFFLINE: "var(--text-disabled)",
  };

  const pollScans = async () => {
    try {
      const since = sessionStartRef.current;
      const url = since
        ? `http://127.0.0.1:8000/api/scans?since=${encodeURIComponent(since)}`
        : "http://127.0.0.1:8000/api/scans";
      const res = await fetch(url, { headers: { "X-API-Key": apiKey } });
      if (!res.ok) return;
      const data = await res.json();
      if (data.scans) setRecentScans(data.scans.slice(0, 20));
    } catch { /* offline */ }
  };

  // Fetch session_start from API on mount so Recent Scans only shows current session
  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/session", { headers: { "X-API-Key": apiKey } })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data?.session_start) sessionStartRef.current = data.session_start;
      })
      .catch(() => {});
  }, [apiKey]);

  useEffect(() => {
    let destroyed = false;
    let wsFailCount = 0;

    function connect() {
      if (destroyed) return;
      const ws = new WebSocket("ws://localhost:3000/ws/live");
      wsRef.current = ws;

      ws.onopen = () => {
        if (destroyed) return;
        wsFailCount = 0;
        setWsConnected(true);
        setWsLines((p) => [...p, "[connected to orchestrator]"]);
        setLive((s) => ({ ...s, status: "IDLE" }));
        if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
      };

      ws.onmessage = (e) => {
        if (destroyed) return;
        try {
          const { event, payload } = JSON.parse(e.data);
          const line = `[${event}] ${JSON.stringify(payload)}`;
          setWsLines((p) => [...p, line]);

          if (event === "investigation_started") {
            const target = (payload.prompt || "").replace("CLI Analysis: ", "");
            setLive({ status: "SCANNING", target, stage: "sandbox" });
          } else if (event === "step_started") {
            setLive((s) => ({ ...s, stage: payload.stepId || s.stage }));
          } else if (event === "ai_summary_completed") {
            setLive((s) => ({ ...s, status: "COMPLETE", stage: "complete" }));
            pollScans();
          }
        } catch {
          setWsLines((p) => [...p, e.data]);
        }
      };

      ws.onclose = () => {
        if (destroyed) return;
        wsFailCount++;
        setWsConnected(false);
        setLive((s) => ({ ...s, status: "WS_OFFLINE" }));
        if (wsFailCount >= 2) {
          setWsLines((p) => [...p, "[orchestrator offline — polling scan history every 10s]"]);
          if (!pollRef.current) {
            pollScans();
            pollRef.current = setInterval(pollScans, 10000);
          }
          retryRef.current = setTimeout(connect, 30000);
        } else {
          setWsLines((p) => [...p, `[disconnected — retry ${wsFailCount}]`]);
          retryRef.current = setTimeout(connect, 3000);
        }
      };

      ws.onerror = () => ws.close();
    }

    connect();
    pollScans();

    return () => {
      destroyed = true;
      if (retryRef.current) clearTimeout(retryRef.current);
      if (pollRef.current) clearInterval(pollRef.current);
      wsRef.current?.close();
    };
  }, [apiKey]);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      {/* Status bar */}
      <div
        style={{
          height: 36,
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-panel-alt)",
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "0 12px",
        }}
      >
        <span
          style={{
            fontSize: 11,
            fontFamily: "var(--font-ui)",
            fontWeight: 700,
            color: STATUS_COLOR[live.status],
            letterSpacing: "0.08em",
          }}
        >
          {live.status === "WS_OFFLINE" ? "OFFLINE" : live.status}
        </span>
        {live.target && (
          <span style={{ fontSize: 12, fontFamily: "var(--font-mono)", color: "var(--text-primary)" }}>
            {live.target}
          </span>
        )}
        {live.stage && live.status !== "WS_OFFLINE" && (
          <span style={{ fontSize: 11, fontFamily: "var(--font-ui)", color: "var(--text-disabled)" }}>
            stage: {live.stage}
          </span>
        )}
        {live.status === "SCANNING" && (
          <span style={{ fontSize: 11, color: "var(--sev-caution)", fontFamily: "var(--font-mono)" }}>...</span>
        )}
        <span style={{ marginLeft: "auto", fontSize: 10, color: wsConnected ? "var(--sev-safe)" : "var(--text-disabled)", fontFamily: "var(--font-ui)" }}>
          {wsConnected ? "● WS" : "○ WS"}
        </span>
      </div>

      {/* Split: event log left, recent scans right */}
      <div style={{ flex: 1, overflow: "hidden", display: "flex" }}>
        <div style={{ flex: 1, overflow: "hidden" }}>
          <RawWell lines={wsLines} autoScroll height="100%" />
        </div>

        {/* Recent scans panel — shown when WS offline or scans available */}
        {recentScans.length > 0 && (
          <div
            style={{
              width: 280,
              minWidth: 280,
              borderLeft: "1px solid var(--border)",
              background: "var(--bg-panel)",
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                height: 28,
                borderBottom: "1px solid var(--border)",
                background: "var(--bg-panel-alt)",
                display: "flex",
                alignItems: "center",
                padding: "0 8px",
              }}
            >
              <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-ui)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                Recent Scans
              </span>
            </div>
            <div style={{ flex: 1, overflow: "auto" }}>
              {recentScans.map((s) => {
                const verdictColor = s.verdict === "danger" ? "var(--sev-danger-text)" : s.verdict === "caution" ? "var(--sev-caution)" : s.verdict === "safe" ? "var(--sev-safe)" : "var(--text-disabled)";
                return (
                  <div
                    key={s.id}
                    style={{
                      padding: "5px 8px",
                      borderBottom: "1px solid var(--border)",
                      display: "flex",
                      flexDirection: "column",
                      gap: 2,
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ fontSize: 10, color: verdictColor, fontFamily: "var(--font-ui)", fontWeight: 700, textTransform: "uppercase" }}>
                        {s.verdict}
                      </span>
                      <span style={{ fontSize: 11, color: "var(--text-primary)", fontFamily: "var(--font-mono)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {s.target}
                      </span>
                    </div>
                    <div style={{ fontSize: 10, color: "var(--text-disabled)", fontFamily: "var(--font-ui)" }}>
                      {s.type} · {s.timestamp}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
