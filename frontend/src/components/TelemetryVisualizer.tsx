"use client";

export default function TelemetryVisualizer({ data }: { data: any }) {
  if (!data) return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 flex flex-col items-center justify-center text-gray-500 min-h-[400px]">
      <svg className="w-12 h-12 mb-4 opacity-20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
      <p className="text-sm font-mono uppercase tracking-tighter">No telemetry data selected</p>
    </div>
  );

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden flex flex-col h-full min-h-[400px]">
      <div className="bg-gray-800 px-4 py-2 flex justify-between items-center">
        <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest">Telemetry Visualizer</span>
        <span className="text-[10px] text-gray-500 font-mono">PID: {data.pid || 'N/A'}</span>
      </div>
      <div className="flex-1 p-6 overflow-y-auto font-mono text-sm">
        <div className="space-y-6">
          <section>
            <h4 className="text-gray-400 text-[10px] uppercase mb-2 border-b border-gray-800 pb-1">Syscall Chain</h4>
            <div className="space-y-1">
              {data.events?.map((ev: any, i: number) => (
                <div key={i} className="flex space-x-3 text-xs">
                  <span className="text-gray-600 w-16">{ev.timestamp}</span>
                  <span className="text-purple-400 font-bold w-20">{ev.type}</span>
                  <span className="text-gray-300">{ev.target}</span>
                </div>
              ))}
            </div>
          </section>

          <section>
            <h4 className="text-gray-400 text-[10px] uppercase mb-2 border-b border-gray-800 pb-1">Network Flows</h4>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {data.network_destinations?.map((net: any, i: number) => (
                <div key={i} className="bg-black/40 p-2 rounded border border-gray-800">
                  <div className="text-cyan-500">{net.ip}:{net.port}</div>
                  <div className="text-[10px] text-gray-500">{net.category}</div>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
