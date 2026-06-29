"use client";

import { useState, useEffect } from 'react';
import { useTraceEvents } from '@/hooks/useTraceEvents';
import IncidentFeed from '@/components/IncidentFeed';
import HITLConsole from '@/components/HITLConsole';
import TelemetryVisualizer from '@/components/TelemetryVisualizer';
import AuthGate from '@/components/AuthGate';
import ScanHistory from '@/components/ScanHistory';
import { useAuth } from '@/hooks/useAuth';

// Neoclassical divider component
const NeoclassicalDivider = ({ className = "" }: { className?: string }) => (
  <div className={`neoclassical-divider ${className}`}>
    <div className="divider-line"></div>
    <div className="divider-ornament">
      <div className="divider-dot"></div>
    </div>
    <div className="divider-line"></div>
  </div>
);

// Section structure
interface SectionProps {
  videoSrc: string;
  children: React.ReactNode;
  dim?: number;
  id?: string;
}

const Section = ({ videoSrc, children, dim = 0.5, id }: SectionProps) => (
  <section id={id} className="snap-section section-height flex flex-col items-center justify-center">
    <div className="absolute inset-0 z-0">
      <video
        autoPlay
        loop
        muted
        playsInline
        className="w-full h-full object-cover grayscale-[0.1] contrast-[1.1] brightness-[0.9]"
      >
        <source src={videoSrc} type="video/mp4" />
      </video>
      <div className="video-dimmer" style={{ opacity: dim }}></div>
      <div className="section-mask mask-top"></div>
      <div className="section-mask mask-bottom"></div>
    </div>
    <div className="relative z-20 w-full max-w-[1600px] h-full flex flex-col p-6 md:p-12">
      {children}
    </div>
  </section>
);

// Hero Section (T R A C E T R E E spaced out title)
const Hero = () => (
  <Section videoSrc="/mpguf5qh-Surreal-Art-Collage.mp4" dim={0.4}>
    <div className="flex-1 flex flex-col items-center justify-center text-center">
      <div className="w-full max-w-[1400px] fade-in">
        <h1 className="hero-title text-canvas select-none tracking-tighter text-shadow-premium">
          {Array.from("TRACETREE").map((l, i) => (
            <span key={i} style={{ animationDelay: `${i * 0.1}s` }}>{l}</span>
          ))}
        </h1>
      </div>
      <div className="mt-12 md:mt-20 flex flex-col items-center gap-4 md:gap-6 fade-in" style={{ animationDelay: '1s' }}>
        <p className="text-gold font-serif italic text-2xl md:text-5xl tracking-[0.5em] uppercase text-shadow-premium leading-none">
          Autonomous
        </p>
        <p className="text-gold font-serif italic text-2xl md:text-5xl tracking-[0.5em] uppercase text-shadow-premium leading-none">
          Behavioral
        </p>
        <p className="text-gold font-serif italic text-2xl md:text-5xl tracking-[0.5em] uppercase text-shadow-premium leading-none">
          Forensics
        </p>
      </div>
    </div>
    <div className="absolute bottom-20 left-1/2 -translate-x-1/2 text-canvas/40 animate-bounce cursor-pointer flex flex-col items-center gap-2">
      <span className="font-mono text-[9px] tracking-[0.4em] uppercase opacity-60">Initialize Descent</span>
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="0.75">
        <path d="M7 13l5 5 5-5M7 6l5 5 5-5" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
    </div>
  </Section>
);

// Architecture Section (8 Legs of Intelligence)
const ArchitectureSection = () => {
  const legs = [
    { id: "PLATE I", title: "Sandbox", desc: "Hardened Docker containment for suspicious execution payloads." },
    { id: "PLATE II", title: "Syscalls", desc: "Vibration-based behavioral sensing at the kernel interface level." },
    { id: "PLATE III", title: "Graphing", desc: "NetworkX-powered behavior cascades and process tree mapping." },
    { id: "PLATE IV", title: "ML / AI", desc: "Random Forest heuristics identifying zero-day threat profiles." },
    { id: "PLATE V", title: "YARA", desc: "Real-time memory DNA matching against known exploit signatures." },
    { id: "PLATE VI", title: "MCP", desc: "Specialized orchestration shield for Model Context Protocol servers." },
    { id: "PLATE VII", title: "Guardian", desc: "Local LLM scanner auditing agent history for sensitive leaks." },
    { id: "PLATE VIII", title: "Temporal", desc: "Rhythm-based anomaly detection across system call intervals." }
  ];

  return (
    <Section videoSrc="/mpfxa2zl-Spider-on-Corinthian-Column.mp4" dim={0.7}>
      <div className="flex-1 flex flex-col justify-center gap-12 lg:gap-24 py-6 md:py-12">
        <div className="max-w-5xl border-l-2 border-terracotta pl-6 md:pl-12">
          <span className="font-mono text-xs tracking-[0.7em] text-terracotta uppercase mb-4 block opacity-80">Orchestrator Architecture</span>
          <h2 className="text-6xl md:text-9xl text-canvas italic leading-tight text-shadow-premium">The 8 Legs of<br />Intelligence</h2>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-x-8 md:gap-x-16 gap-y-12 md:gap-y-20">
          {legs.map((leg, i) => (
            <div key={i} className="flex flex-col gap-3 md:gap-4 group cursor-default">
              <span className="font-mono text-[9px] md:text-[10px] text-terracotta font-bold tracking-[0.3em]">{leg.id}</span>
              <h3 className="text-2xl md:text-4xl text-canvas font-serif italic tracking-wide text-shadow-premium group-hover:text-gold transition-colors duration-500">{leg.title}</h3>
              <p className="text-white/80 text-xs md:text-sm font-sans leading-relaxed tracking-wide opacity-80 max-w-[280px]">{leg.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </Section>
  );
};

// Nervous System Section (with overview / live operation toggle)
const NervousSystemSection = ({
  events,
  selectedTelemetry,
  aiSummaryStatus,
  aiSummaryText
}: {
  events: any[];
  selectedTelemetry: any;
  aiSummaryStatus: 'loading' | 'completed' | null;
  aiSummaryText: string;
}) => {
  const [viewMode, setViewMode] = useState<'overview' | 'live'>('overview');

  useEffect(() => {
    if (events.length > 0) {
      setViewMode('live');
    }
  }, [events.length]);

  const features = [
    { title: "Regex Parser", desc: "Orchestrates multi-line traces into semantic behavior blocks." },
    { title: "Syscall Intercept", desc: "High-fidelity monitoring of process, file, and network operations." },
    { title: "Severity Weights", desc: "Weighted risk classification (0.0-9.0) for every observed action." },
    { title: "Dynamic Flow", desc: "Live visualization of malicious cascades and data exfiltration paths." }
  ];

  return (
    <Section videoSrc="/mpgufe27-Embossed-Branding-Seal---Looping-Video.mp4" dim={0.6}>
      <div className="flex-1 flex flex-col justify-between py-8 md:py-16">
        <div className="text-center w-full">
          <span className="font-mono text-[10px] md:text-xs tracking-[0.8em] text-terracotta uppercase mb-3 block">Analysis Pipeline</span>
          <h2 className="text-6xl md:text-[9rem] lg:text-[11rem] text-canvas font-serif italic tracking-tighter leading-[0.85] text-shadow-premium">
            THE NERVOUS<br />SYSTEM
          </h2>
          
          {/* AI Summary Banner inside Section 3 */}
          {aiSummaryStatus && (
            <div className="mt-4 border-y border-gold/30 py-4 bg-coal/65 backdrop-blur-md max-w-4xl mx-auto relative px-6 shadow-2xl">
              <span className="absolute top-1 left-4 text-[7px] font-mono text-terracotta tracking-widest uppercase font-bold">COGNITIVE AI SUMMARY</span>
              {aiSummaryStatus === 'loading' ? (
                <div className="flex items-center justify-center space-x-2 py-1">
                  <span className="relative flex h-1.5 w-1.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-gold opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-gold"></span>
                  </span>
                  <p className="text-sm font-serif italic text-canvas/80 tracking-wide animate-pulse">
                    The AI is loading the summarized message...
                  </p>
                </div>
              ) : (
                <p className="text-sm md:text-base font-serif italic leading-relaxed text-canvas">
                  "{aiSummaryText}"
                </p>
              )}
            </div>
          )}

          {/* Mode Switcher */}
          <div className="flex justify-center gap-6 mt-4">
            <button
              onClick={() => setViewMode('overview')}
              className={`font-mono text-[9px] tracking-[0.3em] uppercase py-1 px-3 border transition-colors cursor-pointer ${
                viewMode === 'overview'
                  ? 'border-gold text-gold bg-gold/10'
                  : 'border-canvas/20 text-canvas/60 hover:text-canvas hover:border-canvas/40'
              }`}
            >
              [ Overview ]
            </button>
            <button
              onClick={() => setViewMode('live')}
              className={`font-mono text-[9px] tracking-[0.3em] uppercase py-1 px-3 border transition-colors cursor-pointer ${
                viewMode === 'live'
                  ? 'border-gold text-gold bg-gold/10'
                  : 'border-canvas/20 text-canvas/60 hover:text-canvas hover:border-canvas/40'
              }`}
            >
              [ Live Operations ]
            </button>
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 flex items-center justify-center w-full mt-6 overflow-hidden">
          {viewMode === 'overview' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 md:gap-16 w-full">
              {features.map((f, i) => (
                <div key={i} className="border-t border-gold/30 pt-6 md:pt-10 group">
                  <h4 className="text-gold font-serif italic text-2xl md:text-3xl mb-3 text-shadow-premium group-hover:translate-x-2 transition-transform duration-500">{f.title}</h4>
                  <p className="text-white/70 text-xs md:text-sm font-sans leading-relaxed tracking-wide opacity-80">{f.desc}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 w-full h-full lg:h-[50vh] max-h-[550px] overflow-y-auto lg:overflow-visible custom-scrollbar-dark">
              <div className="lg:col-span-5 h-full">
                <IncidentFeed events={events} />
              </div>
              <div className="lg:col-span-7 h-full">
                <TelemetryVisualizer data={selectedTelemetry} />
              </div>
            </div>
          )}
        </div>
      </div>
    </Section>
  );
};

// Secure the Agent Section (strategy / target prompt)
const SecureAgentSection = ({ events }: { events: any[] }) => {
  const activePromptEvent = events.find(e => e.event === 'investigation_started');

  return (
    <Section videoSrc="/mpgs5pod-TraceTree-Static-Logo.mp4" dim={0.5}>
      <div className="flex-1 flex flex-col items-center justify-center text-center relative">
        <h2 className="text-6xl md:text-[9rem] lg:text-[13rem] text-canvas font-serif italic tracking-tighter leading-[0.8] text-shadow-premium fade-in">
          SECURE THE<br />AGENT
        </h2>
        <div className="absolute bottom-12 left-1/2 -translate-x-1/2 w-full max-w-2xl fade-in" style={{ animationDelay: '0.5s' }}>
          <p className="text-gold font-serif italic text-xl md:text-3xl tracking-[0.6em] uppercase text-shadow-premium opacity-90">
            Establish Order
          </p>
        </div>

        {activePromptEvent ? (
          <div className="absolute bottom-6 right-6 z-30 bg-coal/80 backdrop-blur-md border border-gold/30 p-4 max-w-xs rounded shadow-2xl text-left fade-in">
            <div className="flex items-center gap-2 mb-1.5">
              <span className="relative flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-terracotta opacity-75"></span>
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-terracotta"></span>
              </span>
              <span className="text-gold/60 uppercase tracking-[0.2em] text-[8px] font-mono font-bold">Active Payload</span>
            </div>
            <p className="font-serif italic text-xs leading-relaxed text-canvas/95 mb-3">"{activePromptEvent.payload.prompt}"</p>
            <div className="flex justify-between text-[8px] text-canvas/40 font-mono tracking-widest border-t border-canvas/10 pt-2">
              <span>USER: {activePromptEvent.payload.userId}</span>
              <span>SESS: {activePromptEvent.payload.sessionId ? activePromptEvent.payload.sessionId.slice(0, 6) : 'N/A'}</span>
            </div>
          </div>
        ) : (
          <div className="absolute bottom-6 right-6 z-30 bg-coal/60 backdrop-blur-sm border border-canvas/15 p-4 max-w-xs rounded shadow-xl text-left fade-in">
            <p className="text-canvas/50 font-serif italic text-[11px] leading-normal tracking-wide">
              Waiting for an active runtime investigation strategy to anchor...
            </p>
          </div>
        )}
      </div>
    </Section>
  );
};

// Technical Manual Section (cream background)
const ManualSection = ({ isConnected }: { isConnected: boolean }) => (
  <section className="snap-section bg-canvas py-20 md:py-40 px-6 md:px-24 relative z-30 border-t-2 border-coal">
    <div className="max-w-7xl mx-auto">
      <div className="flex flex-col lg:flex-row gap-16 md:gap-24 items-start mb-20 md:mb-32">
        <div className="lg:w-2/5">
          <span className="font-mono text-xs tracking-[0.7em] text-terracotta uppercase mb-6 block">Technical Manual</span>
          <h2 className="text-4xl md:text-8xl italic leading-[1.1] mb-8 md:mb-12">Establish Order in the Runtime.</h2>
          <p className="text-coal/80 font-serif text-lg md:text-3xl leading-relaxed italic mb-8 md:mb-12">
            TraceTree deployment is a rigorous protocol. Follow the sequence below to initialize the orchestrator and anchor the security organism.
          </p>
          <div className="flex flex-col gap-4 font-mono text-[9px] md:text-[10px] tracking-[0.3em] uppercase opacity-50">
            <div className="flex items-center gap-4">
              <div className="w-2 h-2 bg-terracotta rotate-45"></div>
              <span>Version 1.0.4-LTS</span>
            </div>
            <div className="flex items-center gap-4">
              <div className="w-2 h-2 bg-terracotta rotate-45"></div>
              <span>Distributed Security Protocol</span>
            </div>
          </div>
        </div>
        <div className="lg:w-3/5 w-full space-y-16 md:space-y-24">
          <div>
            <h3 className="text-3xl md:text-4xl font-serif italic mb-6 md:mb-8 border-b border-coal/10 pb-4 md:pb-6 flex items-baseline gap-6">
              <span className="text-terracotta font-mono text-sm not-italic">01.</span>
              <span>Initialization</span>
            </h3>
            <div className="code-block">
              <div className="text-gold/40 mb-4 opacity-50 uppercase tracking-[0.2em] text-[10px]"># Clone & Install</div>
              <pre className="whitespace-pre-wrap">{`git clone https://github.com/tejasprasad2008-afk/TraceTree.git\ncd TraceTree\n\n# Install TraceTree in editable mode\npip install -e .`}</pre>
            </div>
          </div>
          <div>
            <h3 className="text-3xl md:text-4xl font-serif italic mb-6 md:mb-8 border-b border-coal/10 pb-4 md:pb-6 flex items-baseline gap-6">
              <span className="text-terracotta font-mono text-sm not-italic">02.</span>
              <span>Activation</span>
            </h3>
            <p className="text-coal/80 mb-6 md:mb-8 font-sans text-sm md:text-lg tracking-wide leading-relaxed max-w-2xl">
              Analyze a package, binary, or bulk file inside the isolated sandbox environment to evaluate behavior and identify malicious footprints.
            </p>
            <div className="code-block">
              <div className="text-gold/40 mb-4 opacity-50 uppercase tracking-[0.2em] text-[10px]"># Run Analysis</div>
              <pre className="whitespace-pre-wrap">{`cascade-analyze requests`}</pre>
            </div>
          </div>
        </div>
      </div>
      
      <NeoclassicalDivider className="mb-12 md:mb-20 opacity-30" />
      
      <div className="flex flex-col md:flex-row justify-between items-center gap-8 md:gap-12 opacity-50">
        <div className="flex flex-col gap-2">
          <span className="font-mono text-[9px] md:text-[10px] tracking-[0.4em] uppercase">TRACETREE | UNIFIED COMMAND</span>
          <span className="font-mono text-[9px] md:text-[10px] tracking-[0.4em] uppercase">ARCHIVE PROTOCOL Nº 2026</span>
        </div>
        <div className="flex gap-8 md:gap-16">
          <span className="font-serif italic text-lg md:text-xl">"Order from Complexity"</span>
          <div className="flex items-center gap-4 font-mono text-[9px] md:text-[10px] tracking-[0.4em] uppercase">
            <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-coal animate-pulse' : 'bg-terracotta'}`}></span>
            {isConnected ? 'SYSTEM ONLINE' : 'SYSTEM OFFLINE'}
          </div>
        </div>
      </div>
    </div>
  </section>
);

export default function Dashboard() {
  const { events, isConnected } = useTraceEvents();
  const { user, signOut } = useAuth();
  const [activeHitl, setActiveHitl] = useState<any>(null);
  const [selectedTelemetry, setSelectedTelemetry] = useState<any>(null);
  const [aiSummaryStatus, setAiSummaryStatus] = useState<'loading' | 'completed' | null>(null);
  const [aiSummaryText, setAiSummaryText] = useState<string>('');

  // Monitor events for HITL requirements and AI summary status
  useEffect(() => {
    // 1. Sync HITL Console state dynamically based on recency
    const hitlReqIdx = events.findIndex(e => e.event === 'hitl_required');
    const hitlResIdx = events.findIndex(e => e.event === 'hitl_resolved');

    if (hitlReqIdx !== -1 && (hitlResIdx === -1 || hitlReqIdx < hitlResIdx)) {
      setActiveHitl(events[hitlReqIdx].payload);
    } else {
      setActiveHitl(null);
    }

    // 2. Auto-select telemetry based on recency
    const completedStepIdx = events.findIndex(e => e.event === 'step_completed' && e.payload?.findings);
    const startedEventIdx = events.findIndex(e => e.event === 'investigation_started');

    if (startedEventIdx !== -1 && (completedStepIdx === -1 || startedEventIdx < completedStepIdx)) {
      setSelectedTelemetry(null);
    } else if (completedStepIdx !== -1) {
      const completedStep = events[completedStepIdx];
      if (completedStep.payload.findings?.includes('total_severity')) {
        try {
          const parsed = JSON.parse(completedStep.payload.findings);
          setSelectedTelemetry(parsed);
        } catch (e) {
          // Not JSON findings
        }
      }
    }

    // 3. Monitor for AI Summary events dynamically by checking recency
    const completedIdx = events.findIndex(e => e.event === 'ai_summary_completed');
    const startedIdx = events.findIndex(e => e.event === 'ai_summary_started');
    const invStartedIdx = events.findIndex(e => e.event === 'investigation_started');

    const activeEvents = [
      { type: 'completed', index: completedIdx },
      { type: 'started', index: startedIdx },
      { type: 'investigation', index: invStartedIdx },
    ].filter(item => item.index !== -1);

    if (activeEvents.length > 0) {
      // The event with the smallest index (closest to events[0]) is the most recent
      activeEvents.sort((a, b) => a.index - b.index);
      const mostRecent = activeEvents[0];

      if (mostRecent.type === 'completed') {
        const event = events[mostRecent.index];
        setAiSummaryStatus('completed');
        setAiSummaryText(event.payload?.summary || '');
      } else if (mostRecent.type === 'started') {
        setAiSummaryStatus('loading');
        setAiSummaryText('');
      } else if (mostRecent.type === 'investigation') {
        setAiSummaryStatus(null);
        setAiSummaryText('');
      }
    }
  }, [events]);

  return (
    <div className="snap-container custom-scrollbar relative">
      {/* Paper texture overlay */}
      <div className="paper-overlay"></div>

      <Hero />
      <ArchitectureSection />
      <NervousSystemSection
        events={events}
        selectedTelemetry={selectedTelemetry}
        aiSummaryStatus={aiSummaryStatus}
        aiSummaryText={aiSummaryText}
      />
      <SecureAgentSection events={events} />
      <ManualSection isConnected={isConnected} />

      {/* Scan History Section */}
      {user && (
        <section className="snap-section bg-coal/98 py-20 md:py-40 px-6 md:px-24 relative z-30 border-t border-canvas/10">
          <div className="max-w-5xl mx-auto">
            <ScanHistory userId={user.id} />
          </div>
        </section>
      )}

      {/* HITL Modal */}
      <HITLConsole 
        hitlRequest={activeHitl} 
        onResolve={() => setActiveHitl(null)} 
      />

      {/* Auth Gate — shown when not logged in */}
      {!user && <AuthGate />}

      {/* Floating user widget */}
      {user && (
        <div className="fixed top-4 right-4 z-40 flex items-center gap-3 bg-coal/80 backdrop-blur-md border border-canvas/15 px-3 py-2 shadow-xl">
          {user.user_metadata?.avatar_url && (
            <img src={user.user_metadata.avatar_url} alt="" className="w-6 h-6 rounded-full" />
          )}
          <span className="font-mono text-[9px] tracking-[0.2em] text-canvas/60 uppercase hidden md:block">
            {user.user_metadata?.full_name ?? user.email}
          </span>
          <button
            onClick={signOut}
            className="font-mono text-[8px] tracking-widest uppercase text-canvas/30 hover:text-terracotta transition-colors cursor-pointer"
          >
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

