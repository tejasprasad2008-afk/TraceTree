"use client";

import { TraceEvent } from '@/hooks/useTraceEvents';

export default function IncidentFeed({ events }: { events: TraceEvent[] }) {
  return (
    <div className="bg-coal/65 backdrop-blur-md border border-gold/20 overflow-hidden flex flex-col h-full shadow-2xl relative">
      <div className="absolute top-2 right-4 text-[8px] font-mono opacity-40 text-canvas">PLATE Nº 03</div>
      
      {/* Ledger Header */}
      <div className="border-b border-canvas/10 px-6 py-4 flex justify-between items-center">
        <div>
          <h3 className="text-lg font-serif italic text-canvas flex items-center">
            <span className="w-1.5 h-1.5 bg-terracotta rotate-45 mr-3"></span>
            Live Incident Ledger
          </h3>
          <span className="text-[8px] font-mono text-canvas/50 uppercase tracking-[0.2em]">Operational Stream</span>
        </div>
        <div className="flex space-x-1.5 items-center">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-terracotta opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-terracotta"></span>
          </span>
          <span className="font-mono text-[9px] text-terracotta font-bold tracking-wider">ACTIVE</span>
        </div>
      </div>

      {/* Ledger Entries */}
      <div className="flex-1 overflow-y-auto p-6 font-mono text-xs space-y-4 custom-scrollbar-dark">
        {events.length === 0 && (
          <div className="text-canvas/40 font-serif italic text-center py-20">
            Waiting for operational security events to anchor...
          </div>
        )}
        {events.map((ev, i) => (
          <div 
            key={i} 
            className="border-b border-canvas/5 pb-3 hover:bg-white/5 transition-colors duration-300"
          >
            <div className="flex justify-between text-[9px] text-canvas/40 mb-1.5">
              <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
              <span className="text-terracotta font-bold uppercase tracking-widest">{ev.event}</span>
            </div>
            <div className="text-canvas/80 break-all leading-relaxed whitespace-pre-wrap font-mono">
              {typeof ev.payload === 'string' 
                ? ev.payload 
                : JSON.stringify(ev.payload, null, 2)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

