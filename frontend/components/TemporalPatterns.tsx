import React from "react";

interface TemporalPattern {
  pattern: string;
  severity: number;
  window: string;
}

interface TemporalPatternsProps {
  patterns: TemporalPattern[];
}

export default function TemporalPatterns({ patterns }: TemporalPatternsProps) {
  return (
    <div className="flex flex-col gap-2 font-mono text-xs">
      {patterns.length === 0 ? (
        <div className="p-3 text-center text-[#808080] bg-white border border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff]">
          NO PATTERNS DETECTED
        </div>
      ) : (
        <div className="flex flex-col gap-1">
          {patterns.map((pat, idx) => {
            let icon = "🟢";
            let textColor = "text-[#0000FF]";
            if (pat.severity >= 8) {
              icon = "🔴";
              textColor = "text-[#FF0000] font-heading font-bold";
            } else if (pat.severity >= 5) {
              icon = "🟡";
              textColor = "text-[#808000] font-bold";
            }

            return (
              <div
                key={idx}
                className="flex items-center justify-between p-2 bg-white border border-[#808080] rounded-none hover:bg-yellow-50"
              >
                <div className="flex items-center gap-2">
                  <span className="text-sm leading-none">{icon}</span>
                  <span className={`${textColor} uppercase tracking-wider`}>
                    {pat.pattern}
                  </span>
                </div>
                <div className="bg-zinc-100 px-1.5 py-0.5 border border-[#808080] text-[10px]">
                  WINDOW: <span className="font-bold">{pat.window}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
