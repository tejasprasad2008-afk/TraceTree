"use client";

import React, { useState, useEffect, useRef } from "react";
import dynamic from "next/dynamic";
import Win95Card from "../components/Win95Card";
import BevelButton from "../components/BevelButton";
import ScanStatusPanel from "../components/ScanStatusPanel";
import HitCounterStats from "../components/HitCounterStats";
import EvidenceTable from "../components/EvidenceTable";
import TemporalPatterns from "../components/TemporalPatterns";
import NetworkActivity from "../components/NetworkActivity";
import OllamaTriage from "../components/OllamaTriage";
import StatusBar from "../components/StatusBar";
import MSDosPrompt from "../components/MSDosPrompt";

// Dynamically import react-fast-marquee to avoid SSR mismatches
const Marquee = dynamic(() => import("react-fast-marquee"), { ssr: false });

interface SyscallEvent {
  id: number;
  syscall: string;
  pid: number;
  target: string;
  severity: "LOW" | "MED" | "HIGH";
  flag: boolean;
}

interface TemporalPattern {
  pattern: string;
  severity: number;
  window: string;
}

interface NetworkConn {
  destination: string;
  port: number;
  classification: string;
  verdict: string;
}

interface ScanRecord {
  id: string;
  package_name: string;
  verdict: "clean" | "malicious";
  confidence: number;
  findings?: string;
}

interface ScanStatus {
  package_name: string;
  status: "idle" | "scanning" | "clean" | "malicious";
  confidence: number;
  stage: "sandbox" | "parser" | "randomforest" | "ollama" | "complete";
  total_severity: number;
  events: SyscallEvent[];
  temporal_patterns: TemporalPattern[];
  ollama_triage: string;
  network_connections: NetworkConn[];
  scan_history: ScanRecord[];
  stats: {
    scanned: number;
    threats: number;
    uptime_seconds: number;
    model_type: string;
    ollama_online: boolean;
    api_online: boolean;
    orchestrator_online: boolean;
  };
}

const defaultMockHistory: ScanRecord[] = [
  { id: "h1", package_name: "urllib33", verdict: "malicious", confidence: 92 },
  { id: "h2", package_name: "requests", verdict: "clean", confidence: 12 },
  { id: "h3", package_name: "numpy", verdict: "clean", confidence: 8 },
  { id: "h4", package_name: "boto3-exfil-test", verdict: "malicious", confidence: 99 },
  { id: "h5", package_name: "django-security-shim", verdict: "clean", confidence: 15 }
];

export default function Dashboard() {
  const [data, setData] = useState<ScanStatus>({
    package_name: "NONE",
    status: "idle",
    confidence: 0,
    stage: "sandbox",
    total_severity: 0.0,
    events: [],
    temporal_patterns: [],
    ollama_triage: "Awaiting local console commands...",
    network_connections: [],
    scan_history: defaultMockHistory,
    stats: {
      scanned: 42,
      threats: 7,
      uptime_seconds: 120,
      model_type: "RANDOMFOREST",
      ollama_online: false,
      api_online: false,
      orchestrator_online: false
    }
  });

  // MS-DOS Command States
  const [command, setCommand] = useState("python3 cli.py analyze urllib33");
  const [enableAi, setEnableAi] = useState(true);
  const [isRunningCommand, setIsRunningCommand] = useState(false);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([
    "Microsoft(R) Windows 95",
    "   (C)Copyright Microsoft Corp 1981-1995.",
    "",
    "Welcome to the TraceTree console gateway.",
    "Select a preset button above or type your command, then press Enter.",
    ""
  ]);

  const wsRef = useRef<WebSocket | null>(null);

  // 1. WebSocket Live Telemetry Connection
  useEffect(() => {
    let socketTimeout: NodeJS.Timeout;

    const connectWebSocket = () => {
      console.log("Connecting to Orchestrator WebSocket...");
      const ws = new WebSocket("ws://localhost:3000/ws/live");
      wsRef.current = ws;

      ws.onopen = () => {
        console.log("Orchestrator WebSocket connected successfully!");
        setData(prev => ({
          ...prev,
          stats: { ...prev.stats, orchestrator_online: true, ollama_online: true }
        }));
      };

      ws.onmessage = (event) => {
        try {
          const raw = JSON.parse(event.data);
          const { event: wsEvent, payload } = raw;
          console.log("WS Telemetry Event:", wsEvent, payload);

          if (wsEvent === "investigation_started") {
            const pkgName = (payload.prompt || "unknown").replace("CLI Analysis: ", "");
            setData(prev => ({
              ...prev,
              package_name: pkgName,
              status: "scanning",
              stage: "sandbox",
              confidence: 0,
              total_severity: 0.0,
              events: [],
              temporal_patterns: [],
              network_connections: [],
              ollama_triage: "AI Engine is analyzing the package behavioral trace..."
            }));
          }

          else if (wsEvent === "step_started") {
            if (payload.stepId === "sandbox") {
              setData(prev => ({ ...prev, stage: "sandbox", confidence: 20 }));
            } else if (payload.stepId === "analysis") {
              setData(prev => ({ ...prev, stage: "randomforest", confidence: 60 }));
            }
          }

          else if (wsEvent === "step_completed") {
            if (payload.stepId === "sandbox" && payload.status === "completed") {
              setData(prev => ({ ...prev, stage: "parser", confidence: 40 }));
            } else if (payload.stepId === "analysis" && payload.findings) {
              let findings = payload.findings;
              if (typeof findings === "string") {
                try {
                  findings = JSON.parse(findings);
                } catch (e) {
                  findings = {};
                }
              }

              // Map suspicious events
              const mappedEvents = (findings.events || []).map((e: any, idx: number) => ({
                id: idx + 1,
                syscall: e.syscall || "openat",
                pid: e.pid || 0,
                target: e.target || e.target_path || "unspecified",
                severity: e.severity || "LOW",
                flag: e.flag || false
              }));

              // Map signatures
              const mappedPatterns = (findings.behavioral_signatures || []).map((s: any) => ({
                pattern: s.name || "suspicious_signature",
                severity: s.severity === "HIGH" ? 9 : s.severity === "MEDIUM" ? 6 : 3,
                window: s.evidence || "within execution window"
              }));

              // Map network
              const mappedNetwork = (findings.network_destinations || []).map((n: any) => ({
                destination: n.ip || n.host || "unknown",
                port: n.port || 443,
                classification: n.classification || "OUTBOUND",
                verdict: n.is_malicious ? "MALICIOUS" : "CLEAN"
              }));

              setData(prev => ({
                ...prev,
                status: findings.is_malicious ? "malicious" : "clean",
                confidence: Math.round((findings.confidence_score || 0) * (findings.confidence_score <= 1 ? 100 : 1)),
                stage: "ollama",
                total_severity: findings.total_severity || 0.0,
                events: mappedEvents,
                temporal_patterns: mappedPatterns,
                network_connections: mappedNetwork
              }));
            }
          }

          else if (wsEvent === "ai_summary_started") {
            setData(prev => ({
              ...prev,
              ollama_triage: "Ollama is drafting final verification summary..."
            }));
          }

          else if (wsEvent === "ai_summary_completed") {
            setData(prev => ({
              ...prev,
              stage: "complete",
              ollama_triage: payload.summary || "AI Triage analysis complete."
            }));
            // Refresh history
            refreshScanHistory();
          }

        } catch (e) {
          console.error("Error parsing WS event", e);
        }
      };

      ws.onclose = () => {
        console.warn("Orchestrator WebSocket disconnected. Retrying in 3s...");
        setData(prev => ({
          ...prev,
          stats: { ...prev.stats, orchestrator_online: false, ollama_online: false }
        }));
        socketTimeout = setTimeout(connectWebSocket, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connectWebSocket();
    return () => {
      clearTimeout(socketTimeout);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  // 2. Poll API gateway and refresh history
  const refreshScanHistory = async () => {
    try {
      const res = await fetch("http://localhost:3000/api/scans");
      if (res.ok) {
        const fetched = await res.json();
        if (fetched.scans) {
          const mappedHistory = fetched.scans.map((s: any) => ({
            id: s.id,
            package_name: s.target,
            verdict: s.verdict.toLowerCase() as "clean" | "malicious",
            confidence: Math.round(s.confidence * (s.confidence <= 1 ? 100 : 1)),
            findings: s.findings
          }));
          setData(prev => ({
            ...prev,
            scan_history: mappedHistory.length > 0 ? mappedHistory : defaultMockHistory,
            stats: {
              ...prev.stats,
              scanned: mappedHistory.length > 0 ? mappedHistory.length : prev.stats.scanned,
              threats: mappedHistory.length > 0 ? mappedHistory.filter((h: any) => h.verdict === "malicious").length : prev.stats.threats
            }
          }));
        }
      }
    } catch (err) {
      console.warn("Could not fetch scan history from orchestrator:", err);
    }
  };

  // Poll API health status
  useEffect(() => {
    const checkApiHealth = async () => {
      try {
        const res = await fetch("http://localhost:8000/");
        if (res.ok) {
          setData(prev => ({
            ...prev,
            stats: { ...prev.stats, api_online: true }
          }));
        } else {
          setData(prev => ({
            ...prev,
            stats: { ...prev.stats, api_online: false }
          }));
        }
      } catch (err) {
        setData(prev => ({
          ...prev,
          stats: { ...prev.stats, api_online: false }
        }));
      }
    };

    checkApiHealth();
    refreshScanHistory();
    const timer = setInterval(() => {
      checkApiHealth();
    }, 4000);

    return () => clearInterval(timer);
  }, []);

  // 3. Uptime ticker
  useEffect(() => {
    const timer = setInterval(() => {
      setData(prev => ({
        ...prev,
        stats: { ...prev.stats, uptime_seconds: prev.stats.uptime_seconds + 1 }
      }));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // 4. Executing CLI commands through API Gateway
  const handleExecuteCommand = async () => {
    if (isRunningCommand || !command.trim()) return;

    setIsRunningCommand(true);
    let finalCommand = command.trim();

    // Prepare flags: append --gui for telemetry & --ai if checkbox enabled
    if (finalCommand.includes("analyze") || finalCommand.includes("triage")) {
      if (!finalCommand.includes("--gui") && !finalCommand.includes("-g")) {
        finalCommand += " --gui";
      }
      if (enableAi && !finalCommand.includes("--ai")) {
        finalCommand += " --ai";
      }
    }

    setTerminalOutput(prev => [
      ...prev,
      `> ${finalCommand}`,
      "Launching local subprocess... Please wait..."
    ]);

    try {
      const response = await fetch("http://localhost:8000/api/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: finalCommand })
      });

      if (!response.ok) {
        const errBody = await response.json();
        setTerminalOutput(prev => [
          ...prev,
          `❌ Command Execution Error: ${errBody.detail || "Unknown error occurred"}`
        ]);
        setIsRunningCommand(false);
        return;
      }

      // Stream output reader
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      if (!reader) {
        setTerminalOutput(prev => [...prev, "❌ Unable to read output stream."]);
        setIsRunningCommand(false);
        return;
      }

      let buffer = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        
        // Parse SSE logs (e.g. data: line)
        const lines = buffer.split("\n\n");
        buffer = lines.pop() || ""; // preserve partial line

        for (const rawLine of lines) {
          if (rawLine.startsWith("data: ")) {
            const cleanLine = rawLine.substring(6).trimEnd();
            if (cleanLine) {
              setTerminalOutput(prev => [...prev, cleanLine]);
            }
          }
        }
      }

      setIsRunningCommand(false);
    } catch (err: any) {
      setTerminalOutput(prev => [
        ...prev,
        `❌ Connection Error: Local TraceTree API is offline.`,
        `Error details: ${err.message}`,
        `Make sure you set export TRACETREE_API_KEYS="your-key" and ran python3 cli.py dashboard.`
      ]);
      setIsRunningCommand(false);
    }
  };

  // 5. Selecting historical scans
  const loadHistoricalScan = (record: ScanRecord) => {
    if (isRunningCommand) return;
    if (!record.findings) {
      alert("No telemetry payload available for this historical item.");
      return;
    }

    try {
      const findings = JSON.parse(record.findings);
      
      const mappedEvents = (findings.events || []).map((e: any, idx: number) => ({
        id: idx + 1,
        syscall: e.syscall || "openat",
        pid: e.pid || 0,
        target: e.target || e.target_path || "unspecified",
        severity: e.severity || "LOW",
        flag: e.flag || false
      }));

      const mappedPatterns = (findings.behavioral_signatures || []).map((s: any) => ({
        pattern: s.name || "suspicious_signature",
        severity: s.severity === "HIGH" ? 9 : s.severity === "MEDIUM" ? 6 : 3,
        window: s.evidence || "within execution window"
      }));

      const mappedNetwork = (findings.network_destinations || []).map((n: any) => ({
        destination: n.ip || n.host || "unknown",
        port: n.port || 443,
        classification: n.classification || "OUTBOUND",
        verdict: n.is_malicious ? "MALICIOUS" : "CLEAN"
      }));

      setData(prev => ({
        ...prev,
        package_name: record.package_name,
        status: record.verdict,
        confidence: record.confidence,
        stage: "complete",
        total_severity: findings.total_severity || 0.0,
        events: mappedEvents,
        temporal_patterns: mappedPatterns,
        network_connections: mappedNetwork,
        ollama_triage: findings.ai_summary || findings.ollama_triage || "AI Triage analysis complete."
      }));

    } catch (e) {
      alert("Failed to parse historical telemetry data.");
    }
  };

  const handleMenuClick = (menuItem: string) => {
    alert(`TraceTree System Message:\n"${menuItem}" is a stub menu item.`);
  };

  return (
    <div className="flex flex-col min-h-screen bg-[#C0C0C0] text-black pb-10">
      
      {/* 1. TOP MARQUEE BAR */}
      <div className="w-full bg-black py-1.5 border-b-2 border-t-2 border-[#808080] select-none">
        <Marquee gradient={false} speed={40}>
          <span className="font-mono text-sm text-[#00FF00] font-bold tracking-widest whitespace-nowrap">
            ★ TRACETREE SECURITY MONITOR v1.0 ★ — &nbsp;
            PACKAGE SCAN ACTIVE — &nbsp;
            OLLAMA TRIAGE ONLINE — &nbsp;
            RANDOMFOREST MODEL LOADED — &nbsp;
            SANDBOX ISOLATION: DOCKER — &nbsp;
            {!data.stats.api_online ? "⚠️ WARNING: OFFLINE MODE (PORT 8000 UNREACHABLE)" : "⚡ API ENGINE ONLINE (PORT 8000)"} — &nbsp;
            {!data.stats.orchestrator_online ? "⚠️ WS OFFLINE" : "⚡ ORCHESTRATOR CONNECTED (PORT 3000)"} ★ &nbsp; &nbsp; &nbsp;
          </span>
        </Marquee>
      </div>

      <div className="max-w-7xl w-full mx-auto p-2 flex flex-col gap-2">
        
        {/* 2. TITLE BAR (Windows 95 style) */}
        <div className="border-2 border-t-[#fff] border-l-[#fff] border-b-[#808080] border-r-[#808080] bg-[#C0C0C0] p-1 flex flex-col gap-1 select-none">
          <div className="flex items-center justify-between bg-gradient-to-r from-[#000080] to-[#1084D0] px-2 py-1.5 text-white font-sans text-sm font-bold">
            <div className="flex items-center gap-1.5">
              <span>🕷️</span>
              <span className="uppercase tracking-wider">TRACETREE :: CASCADE ANALYZER — SECURITY DASHBOARD</span>
            </div>
            <div className="flex items-center gap-0.5 shrink-0">
              <button className="w-5 h-5 flex items-center justify-center bg-[#C0C0C0] border-2 border-t-[#fff] border-l-[#fff] border-b-[#808080] border-r-[#808080] active:border-t-[#808080] active:border-l-[#808080] active:border-b-[#fff] active:border-r-[#fff] text-black font-mono text-[10px] select-none outline-none">
                🗕
              </button>
              <button className="w-5 h-5 flex items-center justify-center bg-[#C0C0C0] border-2 border-t-[#fff] border-l-[#fff] border-b-[#808080] border-r-[#808080] active:border-t-[#808080] active:border-l-[#808080] active:border-b-[#fff] active:border-r-[#fff] text-black font-mono text-[10px] select-none outline-none">
                🗖
              </button>
              <button className="w-5 h-5 flex items-center justify-center bg-[#C0C0C0] border-2 border-t-[#fff] border-l-[#fff] border-b-[#808080] border-r-[#808080] active:border-t-[#808080] active:border-l-[#808080] active:border-b-[#fff] active:border-r-[#fff] text-black font-mono text-[11px] font-bold select-none outline-none pl-[1px]">
                🗙
              </button>
            </div>
          </div>
          
          {/* Menu Options */}
          <div className="flex flex-wrap gap-1 p-1 bg-[#C0C0C0] border border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff]">
            {["File", "Scan", "Model", "Reports", "Help"].map((menuItem) => (
              <BevelButton key={menuItem} onClick={() => handleMenuClick(menuItem)}>
                [{menuItem}]
              </BevelButton>
            ))}
          </div>
        </div>

        {/* 3. Construction stripe alert banner (only visible when MALICIOUS verdict) */}
        {data.status === "malicious" && (
          <div className="border-4 border-[#FF0000] p-1 pulse-glow select-none">
            <div className="bg-construction py-3 px-4 flex items-center justify-center text-center border border-black">
              <span className="bg-black text-[#FFFF00] font-heading text-lg font-black uppercase tracking-widest px-4 py-1.5 border-2 border-[#FFFF00] shadow-[3px_3px_0px_#000000]">
                ⚠️ WARNING: THREAT DETECTED BY AI AGENT JURY ⚠️
              </span>
            </div>
          </div>
        )}

        {/* Main Hero Header section with Rainbow CSS Animation */}
        <div className="bg-white border-2 border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] p-4 text-center select-none">
          <h1 className="font-heading text-3xl md:text-5xl font-black uppercase tracking-tight rainbow select-text">
            🕸️ TRACETREE AGENT SHIELD 🕸️
          </h1>
          <p className="font-mono text-xs text-zinc-600 mt-1 select-text">
            AUTONOMOUS BEHAVIORAL CYSTRACE & SANDBOX TRAP MONITOR
          </p>
        </div>

        {/* Interactive MS-DOS Prompt Console */}
        <Win95Card title="MS-DOS Prompt (Local Command execution Portal)">
          <MSDosPrompt
            command={command}
            setCommand={setCommand}
            isRunning={isRunningCommand}
            terminalOutput={terminalOutput}
            enableAi={enableAi}
            setEnableAi={setEnableAi}
            onExecute={handleExecuteCommand}
            onClear={() => setTerminalOutput([])}
          />
        </Win95Card>

        {/* 4. Main two-column area */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-2">
          
          {/* Main content columns (left, ~75% / 3 cols) */}
          <div className="lg:col-span-3 flex flex-col gap-2">
            
            {/* Row: Status & Stats */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              
              {/* Card 3: SCAN STATUS WINDOW */}
              <Win95Card title="Current Scan Status" className="h-full">
                <ScanStatusPanel
                  packageName={data.package_name}
                  status={data.status}
                  confidence={data.confidence}
                  stage={data.stage}
                  totalSeverity={data.total_severity}
                />
              </Win95Card>

              {/* Card 4: HIT COUNTER STATS PANEL */}
              <Win95Card title="System Statistics" className="h-full">
                <HitCounterStats
                  scanned={data.stats.scanned}
                  threats={data.stats.threats}
                  modelType={data.stats.model_type}
                  features={10}
                  ollamaOnline={data.stats.ollama_online}
                  uptimeSeconds={data.stats.uptime_seconds}
                />
              </Win95Card>

            </div>

            {/* Card 5: THREAT EVIDENCE TABLE */}
            <Win95Card title="Syscall Evidence (strace dump)">
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span>SUSPICIOUS SYSCALLS:</span>
                  {data.events.some(e => e.flag) && (
                    <span className="bg-[#FF0000] text-white px-1.5 py-0.5 border border-black font-heading font-black animate-pulse">
                      THREAT FLAG DETECTED
                    </span>
                  )}
                </div>
                <EvidenceTable events={data.events} />
              </div>
            </Win95Card>

            {/* Row: Patterns & Network */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              
              {/* Card 6: TEMPORAL PATTERNS PANEL */}
              <Win95Card title="Temporal Pattern Detection" className="h-full">
                <TemporalPatterns patterns={data.temporal_patterns} />
              </Win95Card>

              {/* Card 8: NETWORK CONNECTIONS */}
              <Win95Card title="Network Activity (connect() calls)" className="h-full">
                <NetworkActivity connections={data.network_connections} />
              </Win95Card>

            </div>

            {/* Card 7: OLLAMA TRIAGE OUTPUT */}
            <Win95Card title="AI Triage Report (Ollama Jury)">
              <OllamaTriage text={data.ollama_triage} isStreaming={false} />
            </Win95Card>

          </div>

          {/* Sidebar column (right, ~25% / 1 col) */}
          <div className="lg:col-span-1 flex flex-col gap-2">
            
            {/* Card 9: SCAN HISTORY SIDEBAR */}
            <Win95Card title="Scan History" bodyClassName="p-1 flex flex-col gap-1 min-h-[300px] lg:h-full">
              <div className="text-xs font-mono p-1 text-[#808080]">
                PAST TELEMETRY RUNS:
              </div>
              <div className="flex flex-col gap-1 overflow-y-auto max-h-[400px] lg:max-h-none">
                {data.scan_history.map((record, idx) => {
                  const bgClass = idx % 2 === 0 ? "bg-white" : "bg-[#E8E8E8]";
                  const verdictBadge =
                    record.verdict === "malicious" ? (
                      <span className="bg-[#FF0000] text-white text-[8px] font-heading font-bold px-1 border border-black shrink-0">
                        MALICIOUS
                      </span>
                    ) : (
                      <span className="bg-[#00FF00] text-black text-[8px] font-heading font-bold px-1 border border-black shrink-0">
                        CLEAN
                      </span>
                    );

                  return (
                    <button
                      key={record.id}
                      onClick={() => loadHistoricalScan(record)}
                      disabled={isRunningCommand}
                      className={`w-full text-left p-1.5 flex items-center justify-between border-2 border-t-[#fff] border-l-[#fff] border-b-[#808080] border-r-[#808080] active:border-t-[#808080] active:border-l-[#808080] active:border-b-[#fff] active:border-r-[#fff] ${bgClass} rounded-none select-none outline-none focus:outline-dotted focus:outline-2 focus:outline-black`}
                    >
                      <div className="flex flex-col truncate pr-2">
                        <span className="font-mono text-xs font-bold text-[#000080] truncate">
                          {record.package_name}
                        </span>
                        <span className="text-[9px] text-[#808080] font-mono">
                          CONFIDENCE: {record.confidence}%
                        </span>
                      </div>
                      {verdictBadge}
                    </button>
                  );
                })}
              </div>
            </Win95Card>

          </div>

        </div>

      </div>

      {/* 10. BOTTOM STATUS BAR */}
      <StatusBar />

    </div>
  );
}
