import React from "react";

interface SyscallEvent {
  id: number;
  syscall: string;
  pid: number;
  target: string;
  severity: "LOW" | "MED" | "HIGH";
  flag: boolean;
  isNew?: boolean;
}

interface EvidenceTableProps {
  events: SyscallEvent[];
}

export default function EvidenceTable({ events }: EvidenceTableProps) {
  return (
    <div className="overflow-x-auto w-full border-2 border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] bg-[#C0C0C0] p-0.5">
      <table className="w-full text-left border-collapse font-sans text-xs">
        <thead>
          <tr className="bg-[#808080] text-white border-b-2 border-black font-mono">
            <th className="p-1.5 border-r border-[#C0C0C0] font-bold">#</th>
            <th className="p-1.5 border-r border-[#C0C0C0] font-bold">SYSCALL</th>
            <th className="p-1.5 border-r border-[#C0C0C0] font-bold">PID</th>
            <th className="p-1.5 border-r border-[#C0C0C0] font-bold">TARGET</th>
            <th className="p-1.5 border-r border-[#C0C0C0] font-bold">SEVERITY</th>
            <th className="p-1.5 font-bold">FLAG</th>
          </tr>
        </thead>
        <tbody>
          {events.length === 0 ? (
            <tr>
              <td colSpan={6} className="p-4 text-center text-[#808080] bg-white font-mono">
                NO EVIDENCE CAPTURED YET
              </td>
            </tr>
          ) : (
            events.map((ev, idx) => {
              const bgClass = idx % 2 === 0 ? "bg-white" : "bg-[#E8E8E8]";
              
              let sevColor = "text-[#0000FF]";
              if (ev.severity === "MED") sevColor = "text-[#808000] font-bold";
              if (ev.severity === "HIGH") sevColor = "text-[#FF0000] font-heading font-bold";

              return (
                <tr
                  key={ev.id || idx}
                  className={`${bgClass} border-b border-[#808080] hover:bg-yellow-100 transition-colors`}
                >
                  <td className="p-1.5 border-r border-[#808080] font-mono">{idx + 1}</td>
                  <td className="p-1.5 border-r border-[#808080] font-mono text-[#000080] font-bold">
                    {ev.syscall}
                  </td>
                  <td className="p-1.5 border-r border-[#808080] font-mono">{ev.pid}</td>
                  <td className="p-1.5 border-r border-[#808080] font-mono truncate max-w-[200px]" title={ev.target}>
                    {ev.target}
                  </td>
                  <td className={`p-1.5 border-r border-[#808080] font-mono ${sevColor}`}>
                    {ev.severity}
                  </td>
                  <td className="p-1.5 flex items-center gap-1.5 font-mono">
                    <span>{ev.flag ? "🔴 ALERT" : "🟢 OK"}</span>
                    {ev.isNew && (
                      <span className="bg-[#FF0000] text-white text-[8px] font-heading font-extrabold px-1 py-0.5 border border-black animate-pulse shrink-0 select-none">
                        NEW!
                      </span>
                    )}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
