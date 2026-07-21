"use client";

import React, { useState, useEffect, useRef } from "react";
import { SearchBar } from "../components/workbench/SearchBar";
import { UserMenu } from "../components/workbench/UserMenu";
import { CommandConsole } from "../components/workbench/CommandConsole";
import { Dashboard, ScanRow } from "../components/workbench/screens/Dashboard";
import { LiveMonitor } from "../components/workbench/screens/LiveMonitor";
import { ScanHistory } from "../components/workbench/screens/ScanHistory";
import { Evidence, SyscallEvent } from "../components/workbench/screens/Evidence";
import { Signatures } from "../components/workbench/screens/Signatures";
import { Settings } from "../components/workbench/screens/Settings";
import { FirstRunSetup } from "../components/workbench/FirstRunSetup";

type Screen = "dashboard" | "live-monitor" | "scan-history" | "evidence" | "signatures" | "settings";

const NAV: { id: Screen; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "live-monitor", label: "Live" },
  { id: "scan-history", label: "History" },
  { id: "evidence", label: "Evidence" },
  { id: "signatures", label: "Signatures" },
  { id: "settings", label: "Settings" },
];

const NAV_ICONS: Record<Screen, React.ReactNode> = {
  "dashboard": (
    <svg width="15" height="15" viewBox="0 0 15 15" fill="currentColor">
      <rect x="1" y="1" width="5.5" height="5.5"/><rect x="8.5" y="1" width="5.5" height="5.5"/>
      <rect x="1" y="8.5" width="5.5" height="5.5"/><rect x="8.5" y="8.5" width="5.5" height="5.5"/>
    </svg>
  ),
  "live-monitor": (
    <svg width="15" height="15" viewBox="0 0 15 15" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round">
      <polyline points="1,7.5 3.5,7.5 5.5,2 7.5,13 9.5,5 11.5,7.5 14,7.5"/>
    </svg>
  ),
  "scan-history": (
    <svg width="15" height="15" viewBox="0 0 15 15" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="7.5" cy="7.5" r="5.5"/>
      <polyline points="7.5,4.5 7.5,7.5 9.5,9.5"/>
    </svg>
  ),
  "evidence": (
    <svg width="15" height="15" viewBox="0 0 15 15" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round">
      <path d="M7.5 1.5 L13 4.5 L13 9 Q13 13.5 7.5 14.5 Q2 13.5 2 9 L2 4.5 Z"/>
    </svg>
  ),
  "signatures": (
    <svg width="15" height="15" viewBox="0 0 15 15" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round">
      <polyline points="4.5,4.5 1.5,7.5 4.5,10.5"/>
      <polyline points="10.5,4.5 13.5,7.5 10.5,10.5"/>
      <line x1="9" y1="2" x2="6" y2="13"/>
    </svg>
  ),
  "settings": (
    <svg width="15" height="15" viewBox="0 0 15 15" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="7.5" cy="7.5" r="2.5"/>
      <path d="M7.5 1v1.5M7.5 12.5V14M1 7.5h1.5M12.5 7.5H14M3.2 3.2l1.1 1.1M10.7 10.7l1.1 1.1M3.2 11.8l1.1-1.1M10.7 4.3l1.1-1.1"/>
    </svg>
  ),
};

interface ScanData {
  package_name: string;
  status: "idle" | "scanning" | "clean" | "malicious";
  confidence: number;
  stage: string;
  total_severity: number;
  events: SyscallEvent[];
  temporal_patterns: any[];
  ollama_triage: string;
  network_connections: any[];
  scan_history: ScanRow[];
}

interface AppStats {
  scanned: number;
  threats: number;
  uptime_seconds: number;
  model_type: string;
  ollama_online: boolean;
  api_online: boolean;
  orchestrator_online: boolean;
}

function verdictToScanRow(s: any): ScanRow {
  const v = (s.verdict || "pending").toLowerCase();
  return {
    id: s.id,
    target: s.target || s.package_name || "unknown",
    verdict: (["danger", "caution", "safe", "pending"].includes(v) ? v : "pending") as ScanRow["verdict"],
    confidence: Math.round((s.confidence || 0) * (s.confidence <= 1 ? 100 : 1)),
    type: s.type || "pip",
    timestamp: s.createdAt || s.timestamp || "",
  };
}

export default function WorkbenchShell() {
  const [screen, setScreen] = useState<Screen>("dashboard");
  const [searchQuery, setSearchQuery] = useState("");
  const [consoleOpen, setConsoleOpen] = useState(false);
  const [apiKey, setApiKey] = useState("dev-key");
  const [setupState, setSetupState] = useState<"loading" | "needed" | "done">("loading");
  const sessionStartRef = useRef<string | null>(null);

  const [stats, setStats] = useState<AppStats>({
    scanned: 0,
    threats: 0,
    uptime_seconds: 0,
    model_type: "RF",
    ollama_online: false,
    api_online: false,
    orchestrator_online: false,
  });

  const [scanData, setScanData] = useState<ScanData>({
    package_name: "NONE",
    status: "idle",
    confidence: 0,
    stage: "sandbox",
    total_severity: 0,
    events: [],
    temporal_patterns: [],
    ollama_triage: "",
    network_connections: [],
    scan_history: [],
  });

  const wsRef = useRef<WebSocket | null>(null);

  // Load API key from localStorage
  useEffect(() => {
    if (typeof window !== "undefined") {
      const k = localStorage.getItem("tracetree_api_key");
      if (k) setApiKey(k);
      const forceSetup = new URLSearchParams(window.location.search).get("setup") === "1";
      setSetupState(forceSetup || !localStorage.getItem("tracetree_setup_complete") ? "needed" : "done");
    }
  }, []);

  // Fetch session_start on mount so Dashboard recent scans start fresh each open
  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/session", { headers: { "X-API-Key": apiKey } })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => { if (data?.session_start) sessionStartRef.current = data.session_start; })
      .catch(() => {});
  }, [apiKey]);

  const handleApiKeyChange = (k: string) => {
    setApiKey(k);
    if (typeof window !== "undefined") localStorage.setItem("tracetree_api_key", k);
  };

  if (setupState === "loading") return null;
  if (setupState === "needed") {
    return <FirstRunSetup apiKey={apiKey} onComplete={() => setSetupState("done")} />;
  }

  // WebSocket — mirrors old page.tsx logic
  useEffect(() => {
    let socketTimeout: ReturnType<typeof setTimeout>;

    const connect = () => {
      const ws = new WebSocket("ws://localhost:3000/ws/live");
      wsRef.current = ws;

      ws.onopen = () => {
        setStats((p) => ({ ...p, orchestrator_online: true, ollama_online: true }));
      };

      ws.onmessage = (event) => {
        try {
          const { event: wsEvent, payload } = JSON.parse(event.data);

          if (wsEvent === "investigation_started") {
            const pkg = (payload.prompt || "unknown").replace("CLI Analysis: ", "");
            setScanData((p) => ({
              ...p,
              package_name: pkg,
              status: "scanning",
              stage: "sandbox",
              confidence: 0,
              total_severity: 0,
              events: [],
              temporal_patterns: [],
              network_connections: [],
              ollama_triage: "AI Engine analyzing...",
            }));
          } else if (wsEvent === "step_started") {
            if (payload.stepId === "sandbox") setScanData((p) => ({ ...p, stage: "sandbox", confidence: 20 }));
            else if (payload.stepId === "analysis") setScanData((p) => ({ ...p, stage: "randomforest", confidence: 60 }));
          } else if (wsEvent === "step_completed" && payload.stepId === "analysis" && payload.findings) {
            let findings = payload.findings;
            if (typeof findings === "string") { try { findings = JSON.parse(findings); } catch { findings = {}; } }

            const mappedEvents: SyscallEvent[] = (findings.events || []).map((e: any, idx: number) => ({
              id: idx + 1,
              syscall: e.syscall || "openat",
              pid: e.pid || 0,
              target: e.target || e.target_path || "unspecified",
              severity: e.severity || "LOW",
              flag: e.flag || false,
            }));

            const mappedPatterns = (findings.behavioral_signatures || []).map((s: any) => ({
              pattern: s.name || "suspicious_signature",
              severity: s.severity === "HIGH" ? 9 : s.severity === "MEDIUM" ? 6 : 3,
              window: s.evidence || "within execution window",
            }));

            const mappedNetwork = (findings.network_destinations || []).map((n: any) => ({
              destination: n.ip || n.host || "unknown",
              port: n.port || 443,
              classification: n.classification || "OUTBOUND",
              verdict: n.is_malicious ? "MALICIOUS" : "CLEAN",
            }));

            const conf = Math.round((findings.confidence_score || 0) * (findings.confidence_score <= 1 ? 100 : 1));

            setScanData((p) => ({
              ...p,
              status: findings.is_malicious ? "malicious" : "clean",
              confidence: conf,
              stage: "ollama",
              total_severity: findings.total_severity || 0,
              events: mappedEvents,
              temporal_patterns: mappedPatterns,
              network_connections: mappedNetwork,
            }));
          } else if (wsEvent === "ai_summary_completed") {
            setScanData((p) => ({ ...p, stage: "complete", ollama_triage: payload.summary || "" }));
            refreshHistory();
          }
        } catch { /* ignore bad ws frames */ }
      };

      ws.onclose = () => {
        setStats((p) => ({ ...p, orchestrator_online: false, ollama_online: false }));
        socketTimeout = setTimeout(connect, 3000);
      };

      ws.onerror = () => ws.close();
    };

    connect();
    return () => {
      clearTimeout(socketTimeout);
      wsRef.current?.close();
    };
  }, []);

  const refreshHistory = async () => {
    try {
      const since = sessionStartRef.current;
      const url = since
        ? `http://127.0.0.1:8000/api/scans?since=${encodeURIComponent(since)}`
        : "http://127.0.0.1:8000/api/scans";
      const res = await fetch(url, { headers: { "X-API-Key": apiKey } });
      if (res.ok) {
        const data = await res.json();
        if (data.scans) {
          const rows = data.scans.map(verdictToScanRow);
          setScanData((p) => ({
            ...p,
            scan_history: rows,
          }));
          setStats((p) => ({
            ...p,
            scanned: rows.length,
            threats: rows.filter((r: ScanRow) => r.verdict === "danger").length,
          }));
        }
      }
    } catch { /* offline */ }
  };

  // Poll API health
  useEffect(() => {
    const poll = async () => {
      try {
        const r = await fetch("http://127.0.0.1:8000/");
        setStats((p) => ({ ...p, api_online: r.ok }));
      } catch {
        setStats((p) => ({ ...p, api_online: false }));
      }
    };
    poll();
    refreshHistory();
    const t = setInterval(poll, 30000);
    return () => clearInterval(t);
  }, [apiKey]);

  // Uptime ticker
  useEffect(() => {
    const t = setInterval(() => setStats((p) => ({ ...p, uptime_seconds: p.uptime_seconds + 1 })), 1000);
    return () => clearInterval(t);
  }, []);

  const recentScans: ScanRow[] = scanData.scan_history.slice(0, 20).map((r) => ({
    ...r,
    verdict: (["danger", "caution", "safe", "pending"].includes(r.verdict) ? r.verdict : "pending") as ScanRow["verdict"],
  }));

  const renderScreen = () => {
    switch (screen) {
      case "dashboard":
        return <Dashboard stats={stats} recentScans={recentScans} onNavigate={(s) => setScreen(s as Screen)} />;
      case "live-monitor":
        return <LiveMonitor apiKey={apiKey} />;
      case "scan-history":
        return <ScanHistory apiKey={apiKey} />;
      case "evidence":
        return <Evidence events={scanData.events} apiKey={apiKey} />;
      case "signatures":
        return <Signatures apiKey={apiKey} />;
      case "settings":
        return <Settings apiKey={apiKey} onApiKeyChange={handleApiKeyChange} />;
    }
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        background: "var(--bg-app)",
        color: "var(--text-primary)",
        fontFamily: "var(--font-ui)",
        overflow: "hidden",
      }}
    >
      {/* TOP BAR */}
      <div
        style={{
          height: 32,
          minHeight: 32,
          background: "var(--bg-panel)",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          alignItems: "center",
          gap: 0,
        }}
      >
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 0, padding: "0 16px", borderRight: "1px solid var(--border)", height: "100%" }}>
          <span style={{ fontSize: 14, fontWeight: 800, color: "var(--text-primary)", letterSpacing: "-0.03em", fontFamily: "var(--font-mono)" }}>
            Trace<span style={{ color: "var(--accent)" }}>Tree</span>
          </span>
        </div>

        {/* Nav tabs */}
        <div style={{ display: "flex", alignItems: "center", height: "100%", flex: 1, paddingLeft: 4 }}>
          {NAV.map((item) => {
            const active = screen === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setScreen(item.id)}
                style={{
                  height: "100%",
                  padding: "0 12px",
                  background: "transparent",
                  border: "none",
                  borderTop: active ? "2px solid var(--accent)" : "2px solid transparent",
                  borderBottom: "none",
                  color: active ? "var(--text-primary)" : "var(--text-disabled)",
                  fontSize: 11,
                  fontFamily: "var(--font-ui)",
                  cursor: "pointer",
                  whiteSpace: "nowrap",
                }}
              >
                {item.label}
              </button>
            );
          })}
        </div>

        {/* Search */}
        <div style={{ width: 200, borderLeft: "1px solid var(--border)", height: "100%", display: "flex", alignItems: "center" }}>
          <SearchBar value={searchQuery} onChange={setSearchQuery} />
        </div>

        {/* User menu */}
        <UserMenu apiKey={apiKey} onApiKeyChange={handleApiKeyChange} />
      </div>

      {/* BODY */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* SIDEBAR */}
        <div
          style={{
            width: 48,
            minWidth: 48,
            background: "var(--bg-panel)",
            borderRight: "1px solid var(--border)",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            paddingTop: 4,
          }}
        >
          {NAV.map((item) => {
            const active = screen === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setScreen(item.id)}
                title={item.label}
                style={{
                  width: 48,
                  height: 44,
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 3,
                  background: active ? "var(--bg-selected)" : "transparent",
                  border: "none",
                  borderLeft: active ? "2px solid var(--accent)" : "2px solid transparent",
                  color: active ? "var(--text-primary)" : "var(--text-disabled)",
                  cursor: "pointer",
                }}
                onMouseEnter={(e) => { if (!active) (e.currentTarget as HTMLElement).style.background = "var(--bg-hover)"; }}
                onMouseLeave={(e) => { if (!active) (e.currentTarget as HTMLElement).style.background = "transparent"; }}
              >
                {NAV_ICONS[item.id]}
                <span style={{ fontSize: 9, fontFamily: "var(--font-ui)", letterSpacing: "0.04em" }}>{item.label}</span>
              </button>
            );
          })}
        </div>

        {/* MAIN CONTENT */}
        <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <div style={{ flex: 1, overflow: "hidden" }}>{renderScreen()}</div>

          {/* COMMAND CONSOLE DRAWER */}
          <div style={{ borderTop: "1px solid var(--border)", flexShrink: 0 }}>
            <button
              onClick={() => setConsoleOpen((o) => !o)}
              style={{
                width: "100%",
                height: 24,
                background: "var(--bg-panel-alt)",
                border: "none",
                borderBottom: consoleOpen ? "1px solid var(--border)" : "none",
                color: "var(--text-muted)",
                fontSize: 10,
                fontFamily: "var(--font-ui)",
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                cursor: "pointer",
                textAlign: "left",
                padding: "0 12px",
              }}
            >
              Command Console {consoleOpen ? "▲" : "▼"}
            </button>
            {consoleOpen && (
              <div style={{ height: 360, overflow: "hidden" }}>
                <CommandConsole apiKey={apiKey} onScanComplete={refreshHistory} />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
