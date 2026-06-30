"use client";

import React, { useState, useEffect } from "react";
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

// Dynamically import react-fast-marquee to avoid SSR mismatches
const Marquee = dynamic(() => import("react-fast-marquee"), { ssr: false });

interface SyscallEvent {
  id: number;
  syscall: string;
  pid: number;
  target: string;
  severity: "LOW" | "MED" | "HIGH";
  flag: boolean;
  isNew?: boolean;
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
  };
}

// 90s-styled retro mock data
const mockCleanScan: ScanStatus = {
  package_name: "requests",
  status: "clean",
  confidence: 12,
  stage: "complete",
  total_severity: 0.8,
  events: [
    { id: 101, syscall: "openat", pid: 2110, target: "/usr/lib/python3.11/site-packages/requests/__init__.py", severity: "LOW", flag: false },
    { id: 102, syscall: "openat", pid: 2110, target: "/etc/resolv.conf", severity: "LOW", flag: false },
    { id: 103, syscall: "connect", pid: 2110, target: "151.101.1.69", severity: "LOW", flag: false },
    { id: 104, syscall: "brk", pid: 2110, target: "memory_allocation", severity: "LOW", flag: false }
  ],
  temporal_patterns: [],
  ollama_triage: "DEVSECOPS TRIAGE ANALYSIS:\nPackage 'requests' completed execution within the Docker sandbox. The strace logs indicate typical HTTP library initialization routines (reading local Python libraries and opening system name resolution configurations). One external network connection was established to a safe registry address (151.101.1.69) on port 443. No suspicious file system accesses or process mutations were flagged. Verdict is CLEAN.",
  network_connections: [
    { destination: "151.101.1.69", port: 443, classification: "PYPI CDN", verdict: "CLEAN" }
  ],
  scan_history: [],
  stats: { scanned: 42, threats: 7, uptime_seconds: 2520, model_type: "RANDOMFOREST", ollama_online: true }
};

const mockMaliciousScan: ScanStatus = {
  package_name: "urllib33",
  status: "malicious",
  confidence: 92,
  stage: "complete",
  total_severity: 23.5,
  events: [
    { id: 1, syscall: "openat", pid: 1530, target: "/etc/shadow", severity: "HIGH", flag: true, isNew: true },
    { id: 2, syscall: "connect", pid: 1530, target: "45.33.32.156", severity: "HIGH", flag: true, isNew: true },
    { id: 3, syscall: "dup2", pid: 1531, target: "file_descriptor", severity: "MED", flag: false },
    { id: 4, syscall: "execve", pid: 1531, target: "/bin/sh", severity: "HIGH", flag: true, isNew: true },
    { id: 5, syscall: "mprotect", pid: 1530, target: "memory_page", severity: "LOW", flag: false }
  ],
  temporal_patterns: [
    { pattern: "credential_scan_then_exfil", severity: 9, window: "1500-1800 ms" },
    { pattern: "connect_then_shell", severity: 10, window: "3200 ms" },
    { pattern: "rapid_file_enumeration", severity: 7, window: "400 ms" }
  ],
  ollama_triage: "CRITICAL ALERT: Target package 'urllib33' exhibits classical credential extraction and reverse shell behavior. Process 1530 performed a read on /etc/shadow containing system credential baselines, then immediately initiated a network socket callback to an unclassified external IP address (45.33.32.156) on port 4444. This was followed by process duplication and terminal spawning of /bin/sh. Verdict is 100% MALICIOUS.",
  network_connections: [
    { destination: "45.33.32.156", port: 4444, classification: "SUSPICIOUS", verdict: "MALICIOUS" },
    { destination: "151.101.1.69", port: 443, classification: "PYPI CDN", verdict: "CLEAN" }
  ],
  scan_history: [],
  stats: { scanned: 42, threats: 7, uptime_seconds: 2520, model_type: "RANDOMFOREST", ollama_online: true }
};

const mockHistory: ScanRecord[] = [
  { id: "1", package_name: "urllib33", verdict: "malicious", confidence: 92 },
  { id: "2", package_name: "requests", verdict: "clean", confidence: 12 },
  { id: "3", package_name: "numpy", verdict: "clean", confidence: 8 },
  { id: "4", package_name: "boto3-exfil-test", verdict: "malicious", confidence: 99 },
  { id: "5", package_name: "django-security-shim", verdict: "clean", confidence: 15 }
];

export default function Dashboard() {
  const [data, setData] = useState<ScanStatus>({
    package_name: "urllib33",
    status: "malicious",
    confidence: 92,
    stage: "complete",
    total_severity: 23.5,
    events: mockMaliciousScan.events,
    temporal_patterns: mockMaliciousScan.temporal_patterns,
    ollama_triage: mockMaliciousScan.ollama_triage,
    network_connections: mockMaliciousScan.network_connections,
    scan_history: mockHistory,
    stats: {
      scanned: 42,
      threats: 7,
      uptime_seconds: 2520,
      model_type: "RANDOMFOREST",
      ollama_online: true
    }
  });

  const [inputVal, setInputVal] = useState("");
  const [isSimulating, setIsSimulating] = useState(false);
  const [streamedTriage, setStreamedTriage] = useState(mockMaliciousScan.ollama_triage);
  const [isTriageStreaming, setIsTriageStreaming] = useState(false);
  const [pollingError, setPollingError] = useState(false);

  // Poll local backend
  useEffect(() => {
    let timer: NodeJS.Timeout;
    const fetchStatus = async () => {
      try {
        const res = await fetch("http://localhost:8422/api/status");
        if (res.ok) {
          const fetchedData = await res.json();
          setData(prev => ({
            ...fetchedData,
            stats: {
              ...prev.stats,
              ...fetchedData.stats
            },
            scan_history: prev.scan_history
          }));
          setPollingError(false);
        } else {
          setPollingError(true);
        }
      } catch (err) {
        setPollingError(true);
      }
    };

    // Only poll if not running a local scan simulation
    if (!isSimulating) {
      timer = setInterval(fetchStatus, 2000);
    }
    return () => clearInterval(timer);
  }, [isSimulating]);

  // Run uptime clock counter
  useEffect(() => {
    const interval = setInterval(() => {
      setData(prev => ({
        ...prev,
        stats: {
          ...prev.stats,
          uptime_seconds: prev.stats.uptime_seconds + 1
        }
      }));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Simulating local scan
  const handleSimulatedScan = (targetName: string) => {
    if (isSimulating) return;
    setIsSimulating(true);
    setIsTriageStreaming(false);
    setStreamedTriage("");

    const isTargetMalicious =
      targetName.toLowerCase().includes("malicious") ||
      targetName.toLowerCase().includes("typo") ||
      targetName.toLowerCase().includes("hack") ||
      targetName.toLowerCase().includes("shadow") ||
      targetName.toLowerCase().includes("urllib33");

    setData(prev => ({
      ...prev,
      package_name: targetName,
      status: "scanning",
      confidence: 0,
      stage: "sandbox",
      events: [],
      temporal_patterns: [],
      ollama_triage: "",
      network_connections: []
    }));

    // Sandbox phase (1s)
    setTimeout(() => {
      setData(prev => ({
        ...prev,
        confidence: 20,
        stage: "parser"
      }));

      // Parser phase (2s)
      setTimeout(() => {
        setData(prev => ({
          ...prev,
          confidence: 45,
          stage: "randomforest",
          events: isTargetMalicious ? mockMaliciousScan.events.slice(0, 3) : mockCleanScan.events.slice(0, 2)
        }));

        // RF Model phase (3s)
        setTimeout(() => {
          setData(prev => ({
            ...prev,
            confidence: isTargetMalicious ? 80 : 10,
            stage: "ollama",
            events: isTargetMalicious ? mockMaliciousScan.events : mockCleanScan.events,
            temporal_patterns: isTargetMalicious ? mockMaliciousScan.temporal_patterns : [],
            network_connections: isTargetMalicious ? mockMaliciousScan.network_connections : mockCleanScan.network_connections
          }));

          // Triage phase (4s)
          setTimeout(() => {
            const finalVerdict = isTargetMalicious ? "malicious" : "clean";
            const fullTriageText = isTargetMalicious ? mockMaliciousScan.ollama_triage : mockCleanScan.ollama_triage;
            
            setData(prev => ({
              ...prev,
              status: finalVerdict,
              confidence: isTargetMalicious ? 92 : 12,
              stage: "complete",
              total_severity: isTargetMalicious ? 23.5 : 0.8,
              ollama_triage: fullTriageText,
              stats: {
                ...prev.stats,
                scanned: prev.stats.scanned + 1,
                threats: isTargetMalicious ? prev.stats.threats + 1 : prev.stats.threats
              },
              scan_history: [
                {
                  id: String(prev.scan_history.length + 1),
                  package_name: targetName,
                  verdict: finalVerdict,
                  confidence: isTargetMalicious ? 92 : 12
                },
                ...prev.scan_history
              ]
            }));

            // Simulate streaming terminal text
            setIsTriageStreaming(true);
            let charIndex = 0;
            const streamTimer = setInterval(() => {
              if (charIndex < fullTriageText.length) {
                setStreamedTriage(fullTriageText.substring(0, charIndex + 2));
                charIndex += 2;
              } else {
                clearInterval(streamTimer);
                setIsTriageStreaming(false);
                setIsSimulating(false);
              }
            }, 15);

          }, 1000);
        }, 1000);
      }, 1000);
    }, 1000);
  };

  const loadHistoricalScan = (record: ScanRecord) => {
    if (isSimulating) return;
    if (record.verdict === "malicious") {
      setData(prev => ({
        ...prev,
        ...mockMaliciousScan,
        package_name: record.package_name,
        confidence: record.confidence,
        scan_history: prev.scan_history
      }));
      setStreamedTriage(mockMaliciousScan.ollama_triage);
    } else {
      setData(prev => ({
        ...prev,
        ...mockCleanScan,
        package_name: record.package_name,
        confidence: record.confidence,
        scan_history: prev.scan_history
      }));
      setStreamedTriage(mockCleanScan.ollama_triage);
    }
  };

  // Helper menu alert callbacks
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
            {pollingError ? "⚠️ WARNING: OFFLINE MODE (USING LOCAL SIMULATOR)" : "⚡ CONNECTED TO LOCAL ENGINE PORT 8422"} ★ &nbsp; &nbsp; &nbsp;
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

        {/* Local Intake panel */}
        <Win95Card title="Intake Portal (Start New Sandbox Analysis)" bodyClassName="p-3">
          <div className="flex flex-wrap gap-2 items-center">
            <label className="font-mono text-xs font-bold text-black shrink-0">
              TARGET PATH / PKG NAME:
            </label>
            <input
              type="text"
              placeholder="e.g. urllib33, requests, setup.py..."
              className="flex-1 min-w-[200px] border-2 border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] bg-white px-2 py-1 font-mono text-sm text-black outline-none focus:outline-dotted focus:outline-2 focus:outline-black rounded-none"
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              disabled={isSimulating}
              onKeyDown={(e) => {
                if (e.key === "Enter" && inputVal.trim()) {
                  handleSimulatedScan(inputVal.trim());
                  setInputVal("");
                }
              }}
            />
            <BevelButton
              onClick={() => {
                if (inputVal.trim()) {
                  handleSimulatedScan(inputVal.trim());
                  setInputVal("");
                }
              }}
              disabled={isSimulating || !inputVal.trim()}
              className="font-bold text-[#000080]"
            >
              [ RUN ANALYSIS ]
            </BevelButton>
          </div>
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
              <OllamaTriage text={isSimulating ? streamedTriage : data.ollama_triage} isStreaming={isTriageStreaming} />
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
                      disabled={isSimulating}
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
