"use client";

import { useState } from 'react';
import { useScans, ScanRecord } from '@/hooks/useScans';

function verdictColor(verdict: string) {
  if (verdict === 'MALICIOUS') return 'text-red-400';
  if (verdict === 'CLEAN') return 'text-emerald-400';
  return 'text-canvas/50';
}

function ScanRow({ scan }: { scan: ScanRecord }) {
  const [expanded, setExpanded] = useState(false);
  const date = new Date(scan.createdAt).toLocaleString();
  const conf = Math.round(scan.confidence * 100);

  let parsedFindings: any = null;
  try { parsedFindings = JSON.parse(scan.findings); } catch {}

  return (
    <div className="border-b border-canvas/10 last:border-0">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-4 py-3 px-4 hover:bg-white/5 transition-colors text-left cursor-pointer"
      >
        <span className={`font-mono text-[9px] font-bold tracking-widest w-20 shrink-0 ${verdictColor(scan.verdict)}`}>
          {scan.verdict}
        </span>
        <span className="font-mono text-xs text-canvas/80 flex-1 truncate">{scan.target}</span>
        <span className="font-mono text-[9px] text-canvas/40 shrink-0">{conf}%</span>
        <span className="font-mono text-[8px] text-canvas/30 shrink-0 hidden md:block">{date}</span>
        <span className="text-canvas/30 text-xs shrink-0">{expanded ? '▲' : '▼'}</span>
      </button>
      {expanded && parsedFindings && (
        <div className="px-4 pb-4 bg-black/20 font-mono text-[10px] text-canvas/60 space-y-1">
          {parsedFindings.flagged_behaviors?.length > 0 && (
            <div><span className="text-terracotta">Behaviors:</span> {parsedFindings.flagged_behaviors.join(', ')}</div>
          )}
          {parsedFindings.behavioral_signatures?.length > 0 && (
            <div><span className="text-terracotta">Signatures:</span> {parsedFindings.behavioral_signatures.map((s: any) => s.name || s).join(', ')}</div>
          )}
          {parsedFindings.yara_matches?.length > 0 && (
            <div><span className="text-terracotta">YARA:</span> {parsedFindings.yara_matches.join(', ')}</div>
          )}
          {parsedFindings.network_destinations?.length > 0 && (
            <div><span className="text-terracotta">Network:</span> {parsedFindings.network_destinations.join(', ')}</div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ScanHistory({ userId }: { userId: string }) {
  const { scans, loading, error, refetch } = useScans(userId);

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-4">
        <div>
          <span className="font-mono text-[9px] tracking-[0.5em] uppercase text-terracotta block mb-1">Scan Archive</span>
          <h3 className="font-serif italic text-2xl text-canvas">Past Scans</h3>
        </div>
        <button
          onClick={refetch}
          className="font-mono text-[9px] tracking-[0.3em] uppercase text-canvas/40 hover:text-canvas/80 transition-colors cursor-pointer border border-canvas/20 hover:border-canvas/40 px-3 py-1"
        >
          Refresh
        </button>
      </div>

      <div className="border border-canvas/20 bg-coal/40 backdrop-blur-sm">
        {loading && (
          <div className="py-8 text-center font-mono text-[9px] tracking-widest uppercase text-canvas/30 animate-pulse">
            Loading scan history...
          </div>
        )}
        {!loading && error && (
          <div className="py-8 text-center font-mono text-[9px] tracking-widest uppercase text-terracotta/60">
            Orchestrator offline — showing cached scans
          </div>
        )}
        {!loading && scans.length === 0 && (
          <div className="py-8 text-center font-mono text-[9px] tracking-widest uppercase text-canvas/20">
            No scans recorded yet
          </div>
        )}
        {scans.map(scan => <ScanRow key={scan.id} scan={scan} />)}
      </div>

      {scans.length > 0 && (
        <div className="mt-2 font-mono text-[8px] tracking-widest uppercase text-canvas/20 text-right">
          {scans.length} scan{scans.length !== 1 ? 's' : ''} · stored locally
        </div>
      )}
    </div>
  );
}
