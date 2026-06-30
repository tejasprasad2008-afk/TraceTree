import React from "react";

interface ScanStatusPanelProps {
  packageName: string;
  status: "idle" | "scanning" | "clean" | "malicious";
  confidence: number;
  stage: "sandbox" | "parser" | "randomforest" | "ollama" | "complete";
  totalSeverity: number;
}

export default function ScanStatusPanel({
  packageName,
  status,
  confidence,
  stage,
  totalSeverity,
}: ScanStatusPanelProps) {
  // Determine status badge classes
  let statusBadge = null;
  if (status === "scanning") {
    statusBadge = (
      <div className="inline-block px-3 py-1 font-heading text-sm font-bold bg-[#FFFF00] text-black border-2 border-dashed border-black pulse-glow-yellow">
        SCANNING...
      </div>
    );
  } else if (status === "clean") {
    statusBadge = (
      <div className="inline-block px-3 py-1 font-heading text-sm font-bold bg-[#00FF00] text-black border-2 border-black pulse-glow-green">
        CLEAN
      </div>
    );
  } else if (status === "malicious") {
    statusBadge = (
      <div className="relative inline-block px-4 py-2 font-heading text-sm font-bold text-white border-4 border-red-600 pulse-glow overflow-hidden select-none bg-construction">
        <span className="relative z-10 bg-black px-1.5 py-0.5 border border-red-600 font-extrabold text-red-600">
          THREAT DETECTED
        </span>
      </div>
    );
  } else {
    statusBadge = (
      <div className="inline-block px-3 py-1 font-heading text-sm font-bold bg-[#808080] text-white border-2 border-black">
        IDLE
      </div>
    );
  }

  // Segmented progress bar
  const totalSegments = 20;
  const filledSegments = Math.round((confidence / 100) * totalSegments);
  const segments = Array.from({ length: totalSegments });

  // Pipeline stages
  const stages = [
    { id: "sandbox", label: "DOCKER SANDBOX" },
    { id: "parser", label: "STRACE CAPTURE" },
    { id: "randomforest", label: "PARSER" }, 
    { id: "ollama", label: "RANDOMFOREST" },
    { id: "complete", label: "OLLAMA TRIAGE" },
  ];

  const getStageIndex = (s: string) => {
    if (s === "sandbox") return 0;
    if (s === "parser") return 1;
    if (s === "randomforest") return 2;
    if (s === "ollama") return 3;
    if (s === "complete") return 4;
    return -1;
  };

  const currentIdx = getStageIndex(stage);

  return (
    <div className="flex flex-col gap-4">
      {/* Target Details */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="font-mono text-xs text-[#808080]">TARGET PACKAGE:</div>
          <div className="font-heading text-2xl font-bold text-[#0000FF] uppercase tracking-wide">
            {packageName || "N/A"}
          </div>
        </div>
        <div>
          <div className="font-mono text-xs text-[#808080] mb-1">VERDICT STATUS:</div>
          {statusBadge}
        </div>
      </div>

      <div className="hr-groove my-1" />

      {/* Confidence Segmented Bar */}
      <div>
        <div className="flex justify-between items-center mb-1 text-xs font-mono">
          <span>CONFIDENCE LEVEL:</span>
          <span className="text-[#00FF00] bg-black px-1 font-bold">{confidence}%</span>
        </div>
        <div className="border-2 border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] bg-black p-1 flex gap-1 h-8 items-center">
          {segments.map((_, idx) => (
            <div
              key={idx}
              className={`h-full flex-1 border border-black ${
                idx < filledSegments ? "bg-[#00FF00]" : "bg-zinc-900"
              }`}
            />
          ))}
        </div>
      </div>

      <div className="hr-groove my-1" />

      {/* Pipeline Stage Indicators */}
      <div>
        <div className="text-xs font-mono mb-2">PIPELINE STATUS:</div>
        <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
          {stages.map((st, idx) => {
            const isCompleted = idx < currentIdx || stage === "complete";
            const isActive = idx === currentIdx && stage !== "complete" && status === "scanning";
            const bgClass = isCompleted
              ? "bg-[#00FF00] text-black border-[#009900]"
              : isActive
              ? "bg-[#FFFF00] text-black border-[#999900] pulse-glow-yellow"
              : "bg-[#808080] text-white border-zinc-700 opacity-60";

            return (
              <div
                key={st.id}
                className={`border-2 p-1.5 text-center font-heading text-[10px] font-bold truncate rounded-none select-none ${bgClass}`}
              >
                {st.label}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
