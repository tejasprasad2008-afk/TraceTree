"use client";

export default function TelemetryVisualizer({ data }: { data: any }) {
  if (!data) return (
    <div className="bg-coal/65 backdrop-blur-md border border-gold/20 p-8 flex flex-col items-center justify-center text-canvas/40 min-h-[400px] h-full shadow-2xl relative overflow-hidden">
      {/* Background blueprint decorative elements */}
      <div className="absolute inset-0 opacity-[0.05] pointer-events-none flex items-center justify-center">
        <svg width="300" height="300" viewBox="0 0 100 100" fill="none" stroke="currentColor" strokeWidth="0.5">
          <circle cx="50" cy="50" r="40" strokeDasharray="2 2" />
          <circle cx="50" cy="50" r="30" />
          <line x1="10" y1="50" x2="90" y2="50" />
          <line x1="50" y1="10" x2="50" y2="90" />
        </svg>
      </div>
      <div className="absolute top-2 left-4 text-[8px] font-mono opacity-40 text-canvas">PLATE Nº 02</div>
      
      <svg className="w-12 h-12 mb-4 opacity-30 text-terracotta" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
      <p className="text-sm font-serif italic uppercase tracking-wider text-canvas/70">No telemetry data selected</p>
      <span className="text-[9px] font-mono opacity-40 uppercase tracking-widest mt-1">Telemetry node pending</span>
    </div>
  );

  return (
    <div className="bg-coal/65 backdrop-blur-md border border-gold/20 overflow-hidden flex flex-col h-full shadow-2xl relative">
      <div className="absolute top-2 right-4 text-[8px] font-mono opacity-40 text-canvas">PLATE Nº 02</div>
      
      <div className="border-b border-canvas/10 px-6 py-4 flex justify-between items-center">
        <div>
          <h3 className="text-lg font-serif italic text-canvas flex items-center">
            <span className="w-1.5 h-1.5 bg-terracotta rotate-45 mr-3"></span>
            Telemetry Visualizer
          </h3>
          <span className="text-[8px] font-mono text-canvas/50 uppercase tracking-[0.2em]">Runtime Graph Node</span>
        </div>
        <span className="text-[10px] text-terracotta font-mono font-bold">PID: {data.pid || 'N/A'}</span>
      </div>
      
      <div className="flex-1 p-6 overflow-y-auto font-mono text-xs space-y-6 custom-scrollbar-dark">
        <div className="space-y-6">
          <section>
            <h4 className="text-canvas/50 text-[9px] uppercase tracking-wider mb-3 border-b border-canvas/10 pb-1 flex justify-between">
              <span>Syscall Chain</span>
              <span className="font-serif italic lowercase font-bold text-terracotta">trace stream</span>
            </h4>
            <div className="space-y-1.5 max-h-[180px] overflow-y-auto custom-scrollbar-dark">
              {data.events?.map((ev: any, i: number) => (
                <div key={i} className="flex space-x-4 text-[11px] py-1 border-b border-canvas/5 hover:bg-white/5 transition-colors">
                  <span className="text-canvas/40 w-16">{ev.timestamp}</span>
                  <span className="text-terracotta font-bold w-20 uppercase tracking-wider">{ev.type}</span>
                  <span className="text-canvas/80 truncate flex-1">{ev.target}</span>
                </div>
              ))}
              {(!data.events || data.events.length === 0) && (
                <div className="text-canvas/45 italic py-2 text-center font-serif">No system calls observed.</div>
              )}
            </div>
          </section>

          <section>
            <h4 className="text-canvas/50 text-[9px] uppercase tracking-wider mb-3 border-b border-canvas/10 pb-1 flex justify-between">
              <span>Network Flows</span>
              <span className="font-serif italic lowercase font-bold text-terracotta">sockets</span>
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {data.network_destinations?.map((net: any, i: number) => (
                <div key={i} className="border border-gold/20 bg-white/5 p-3 shadow-sm relative">
                  <div className="text-terracotta font-bold text-xs">{net.ip}:{net.port}</div>
                  <div className="text-[9px] text-canvas/50 uppercase tracking-widest mt-1">{net.category}</div>
                </div>
              ))}
              {(!data.network_destinations || data.network_destinations.length === 0) && (
                <div className="text-canvas/45 italic py-2 col-span-2 text-center font-serif">No active network destinations recorded.</div>
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

