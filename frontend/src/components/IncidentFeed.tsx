"use client";

import { TraceEvent } from '@/hooks/useTraceEvents';

export default function IncidentFeed({ events }: { events: TraceEvent[] }) {
  return (
    <div className="bg-black border border-gray-800 rounded-lg overflow-hidden flex flex-col h-[500px]">
      <div className="bg-gray-900 px-4 py-2 border-b border-gray-800 flex justify-between items-center">
        <span className="text-xs font-mono text-gray-400 uppercase tracking-widest">Live Incident Feed</span>
        <div className="flex space-x-1">
          <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
          <div className="w-2 h-2 rounded-full bg-gray-700"></div>
          <div className="w-2 h-2 rounded-full bg-gray-700"></div>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-4 font-mono text-sm space-y-2">
        {events.length === 0 && (
          <div className="text-gray-600 italic">Waiting for telemetry events...</div>
        )}
        {events.map((ev, i) => (
          <div key={i} className="border-l-2 border-gray-700 pl-3 py-1 hover:bg-gray-900 transition-colors">
            <div className="flex justify-between text-[10px] text-gray-500 mb-1">
              <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
              <span className="text-cyan-500 uppercase">{ev.event}</span>
            </div>
            <div className="text-gray-300 break-all">
              {typeof ev.payload === 'string' 
                ? ev.payload 
                : JSON.stringify(ev.payload)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
