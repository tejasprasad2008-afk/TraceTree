import React from "react";
import HitCounter from "./HitCounter";

interface HitCounterStatsProps {
  scanned: number;
  threats: number;
  modelType: string;
  features: number;
  ollamaOnline: boolean;
  uptimeSeconds: number;
}

export default function HitCounterStats({
  scanned,
  threats,
  modelType,
  features,
  ollamaOnline,
  uptimeSeconds,
}: HitCounterStatsProps) {
  // Format uptime to hh:mm:ss
  const formatUptime = (totalSeconds: number) => {
    const hrs = Math.floor(totalSeconds / 3600);
    const mins = Math.floor((totalSeconds % 3600) / 60);
    const secs = totalSeconds % 60;
    return [
      String(hrs).padStart(2, "0"),
      String(mins).padStart(2, "0"),
      String(secs).padStart(2, "0"),
    ].join(":");
  };

  return (
    <div className="flex flex-col gap-3 font-mono text-xs text-black">
      <div className="flex items-center justify-between border-b border-[#808080] pb-2">
        <span>PACKAGES SCANNED :</span>
        <HitCounter value={scanned} digits={6} />
      </div>

      <div className="flex items-center justify-between border-b border-[#808080] pb-2">
        <span>THREATS DETECTED :</span>
        <div className="inline-flex border-2 border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] bg-black px-2 py-1 select-none">
          <span className="font-mono text-lg font-bold text-[#FF0000] tracking-widest uppercase">
            {String(threats).padStart(6, "0")}
          </span>
        </div>
      </div>

      <div className="flex justify-between border-b border-[#808080] pb-1.5 items-center">
        <span>MODEL TYPE :</span>
        <span className="bg-black text-[#00FF00] px-1.5 py-0.5 border border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] font-bold">
          {modelType || "RANDOMFOREST"}
        </span>
      </div>

      <div className="flex justify-between border-b border-[#808080] pb-1.5 items-center">
        <span>FEATURES :</span>
        <span className="bg-black text-[#00FF00] px-1.5 py-0.5 border border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] font-bold">
          {features || 10}
        </span>
      </div>

      <div className="flex justify-between border-b border-[#808080] pb-1.5 items-center">
        <span>OLLAMA STATUS :</span>
        <span
          className={`px-1.5 py-0.5 border border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] font-bold ${
            ollamaOnline ? "bg-black text-[#00FF00]" : "bg-black text-[#FF0000] animate-pulse"
          }`}
        >
          {ollamaOnline ? "ONLINE" : "OFFLINE"}
        </span>
      </div>

      <div className="flex justify-between items-center">
        <span>UPTIME :</span>
        <span className="bg-black text-[#00FF00] px-1.5 py-0.5 border border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] font-bold">
          {formatUptime(uptimeSeconds)}
        </span>
      </div>
    </div>
  );
}
