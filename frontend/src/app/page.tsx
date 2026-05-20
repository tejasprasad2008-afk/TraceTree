"use client";

import { useState, useEffect } from 'react';
import { useTraceEvents } from '@/hooks/useTraceEvents';
import IncidentFeed from '@/components/IncidentFeed';
import HITLConsole from '@/components/HITLConsole';
import TelemetryVisualizer from '@/components/TelemetryVisualizer';

export default function Dashboard() {
  const { events, isConnected } = useTraceEvents();
  const [activeHitl, setActiveHitl] = useState<any>(null);
  const [selectedTelemetry, setSelectedTelemetry] = useState<any>(null);

  // Monitor events for HITL requirements
  useEffect(() => {
    const latestEvent = events[0];
    if (latestEvent?.event === 'hitl_required') {
      setActiveHitl(latestEvent.payload);
    }
    
    // Auto-select telemetry if a step is completed with findings
    if (latestEvent?.event === 'step_completed' && latestEvent.payload?.findings) {
      // In a real app, we'd fetch the full findings from the API
      // For now, we'll simulate picking up data if available in payload
      if (latestEvent.payload.findings.includes('total_severity')) {
        try {
          const parsed = JSON.parse(latestEvent.payload.findings);
          setSelectedTelemetry(parsed);
        } catch (e) {
          // Not JSON findings
        }
      }
    }
  }, [events]);

  return (
    <main className="min-h-screen bg-black text-white p-6 font-sans">
      {/* Header */}
      <header className="flex justify-between items-center mb-8 border-b border-gray-800 pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tighter text-white flex items-center">
            TRACETREE <span className="text-cyan-500 ml-2">UNIFIED COMMAND</span>
          </h1>
          <p className="text-gray-500 text-xs mt-1 uppercase tracking-widest">
            Autonomous Investigation & Response Engine
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <div className={`flex items-center space-x-2 px-3 py-1 rounded-full border ${isConnected ? 'border-green-900/50 bg-green-950/20 text-green-500' : 'border-red-900/50 bg-red-950/20 text-red-500'} text-[10px] font-mono`}>
            <div className={`w-1.5 h-1.5 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
            <span>ORCHESTRATOR: {isConnected ? 'CONNECTED' : 'DISCONNECTED'}</span>
          </div>
          <div className="text-[10px] text-gray-500 font-mono">
            V1.0.4-PROTOTYPE
          </div>
        </div>
      </header>

      {/* Main Grid */}
      <div className="grid grid-cols-12 gap-6">
        {/* Left Column: Live Feed */}
        <div className="col-span-12 lg:col-span-4">
          <IncidentFeed events={events} />
        </div>

        {/* Right Column: Visualizer & Details */}
        <div className="col-span-12 lg:col-span-8 flex flex-col space-y-6">
          <TelemetryVisualizer data={selectedTelemetry} />
          
          <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-6 flex-1">
            <h3 className="text-xs font-mono text-gray-400 uppercase tracking-widest mb-4">Investigation Strategy</h3>
            <div className="space-y-4">
              {events.filter(e => e.event === 'investigation_started').slice(0, 1).map((e, i) => (
                <div key={i} className="bg-black/40 p-4 rounded border border-cyan-900/20 border-l-cyan-500 border-l-4">
                  <p className="text-sm text-gray-300 italic">"{e.payload.prompt}"</p>
                  <div className="mt-2 text-[10px] text-gray-500 font-mono">USER_ID: {e.payload.userId}</div>
                </div>
              ))}
              {events.length === 0 && (
                <div className="text-gray-600 text-sm italic">No active investigations. Start one via CLI or API.</div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* HITL Modal */}
      <HITLConsole 
        hitlRequest={activeHitl} 
        onResolve={() => setActiveHitl(null)} 
      />

      {/* Footer Branding */}
      <footer className="mt-12 pt-6 border-t border-gray-900 flex justify-between items-center text-[10px] text-gray-600 font-mono">
        <div>© 2026 TRACETREE LABS | INTERNAL USE ONLY</div>
        <div className="flex space-x-6">
          <span>SYSTEM_HEALTH: NOMINAL</span>
          <span>COGNITIVE_LOAD: 12%</span>
          <span>UPTIME: 42:12:09</span>
        </div>
      </footer>
    </main>
  );
}
