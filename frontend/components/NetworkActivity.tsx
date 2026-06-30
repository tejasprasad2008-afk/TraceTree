import React from "react";

interface NetworkConn {
  destination: string;
  port: number;
  classification: string;
  verdict: string;
}

interface NetworkActivityProps {
  connections: NetworkConn[];
}

export default function NetworkActivity({ connections }: NetworkActivityProps) {
  return (
    <div className="overflow-x-auto w-full border-2 border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] bg-[#C0C0C0] p-0.5">
      <table className="w-full text-left border-collapse font-sans text-xs">
        <thead>
          <tr className="bg-[#808080] text-white border-b-2 border-black font-mono">
            <th className="p-1.5 border-r border-[#C0C0C0] font-bold">DESTINATION IP</th>
            <th className="p-1.5 border-r border-[#C0C0C0] font-bold">PORT</th>
            <th className="p-1.5 border-r border-[#C0C0C0] font-bold">CLASSIFICATION</th>
            <th className="p-1.5 font-bold">VERDICT</th>
          </tr>
        </thead>
        <tbody>
          {connections.length === 0 ? (
            <tr>
              <td colSpan={4} className="p-4 text-center text-[#808080] bg-white font-mono">
                NO NETWORK ACTIVITY DETECTED
              </td>
            </tr>
          ) : (
            connections.map((conn, idx) => {
              const bgClass = idx % 2 === 0 ? "bg-white" : "bg-[#E8E8E8]";
              
              let classColor = "text-black";
              if (conn.classification.toUpperCase() === "PYPI CDN" || conn.classification.toUpperCase() === "SAFE_REGISTRY" || conn.classification.toUpperCase() === "SAFE") {
                classColor = "text-[#008000] font-bold";
              } else if (conn.classification.toUpperCase() === "SUSPICIOUS") {
                classColor = "text-[#FF0000] font-heading font-bold animate-pulse";
              } else if (conn.classification.toUpperCase() === "UNKNOWN") {
                classColor = "text-[#FF0000] font-heading font-bold";
              }

              let verdColor = conn.verdict.toUpperCase() === "CLEAN" || conn.verdict.toUpperCase() === "SAFE"
                ? "text-[#008000] font-bold"
                : "text-[#FF0000] font-bold";

              return (
                <tr
                  key={idx}
                  className={`${bgClass} border-b border-[#808080] hover:bg-yellow-100 transition-colors`}
                >
                  <td className="p-1.5 border-r border-[#808080] font-mono">{conn.destination}</td>
                  <td className="p-1.5 border-r border-[#808080] font-mono">{conn.port}</td>
                  <td className={`p-1.5 border-r border-[#808080] font-mono ${classColor}`}>
                    {conn.classification}
                  </td>
                  <td className={`p-1.5 font-mono ${verdColor}`}>{conn.verdict}</td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
