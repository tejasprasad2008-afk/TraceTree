"use client";

import { useState } from 'react';

export default function HITLConsole({ 
  hitlRequest, 
  onResolve 
}: { 
  hitlRequest: any; 
  onResolve: () => void 
}) {
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!hitlRequest) return null;

  const handleAction = async (approved: boolean) => {
    setIsSubmitting(true);
    try {
      const baseUrl = process.env.NEXT_PUBLIC_ORCHESTRATOR_API_URL || 'http://localhost:3000';
      const response = await fetch(`${baseUrl}/api/approve`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          sessionId: hitlRequest.sessionId,
          approved,
          reasoning: 'Dashboard Administrator Approval',
          userId: 'admin-01',
          role: 'ADMINISTRATOR',
        }),
      });

      if (response.ok) {
        onResolve();
      } else {
        console.error('Failed to resolve HITL');
      }
    } catch (err) {
      console.error('Error during HITL resolution', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-coal/85 backdrop-blur-md flex items-center justify-center z-50 p-4">
      {/* Paper texture overlay for the screen */}
      <div className="fixed inset-0 pointer-events-none opacity-10 bg-[url('https://www.transparenttextures.com/patterns/linen-free-paper.png')]"></div>
      
      <div className="bg-canvas border-2 border-terracotta/40 w-full max-w-md shadow-2xl relative p-8 overflow-hidden">
        {/* Decorative corner lines */}
        <div className="absolute top-2 left-2 text-[8px] font-mono opacity-30">TT-DECREE</div>
        <div className="absolute top-2 right-2 text-[8px] font-mono opacity-30">Nº {hitlRequest.sessionId ? hitlRequest.sessionId.slice(0, 8) : '0000'}</div>

        {/* Neoclassical Red Wax Seal Emblem */}
        <div className="flex flex-col items-center mb-6 pt-4">
          <div className="w-16 h-16 bg-terracotta rounded-full flex items-center justify-center shadow-lg border-2 border-gold/40 relative">
            {/* Inner seal pattern */}
            <div className="absolute inset-1 rounded-full border border-dashed border-canvas/20"></div>
            <svg className="w-8 h-8 text-canvas" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h3 className="text-xl md:text-2xl font-serif italic text-terracotta tracking-wide uppercase mt-4 text-center">
            Decree Required
          </h3>
          <span className="text-[8px] font-mono text-coal/40 uppercase tracking-[0.25em]">Human-in-the-Loop Safeguard</span>
        </div>

        <div className="space-y-6 font-mono text-xs">
          <div>
            <label className="text-[9px] text-coal/40 uppercase tracking-widest block mb-1">Operational Action</label>
            <div className="text-canvas bg-coal px-4 py-3 border-l-4 border-terracotta leading-relaxed break-all">
              {hitlRequest.toolCall.name}
            </div>
          </div>
          
          <div>
            <label className="text-[9px] text-coal/40 uppercase tracking-widest block mb-1">Cognitive Reason</label>
            <p className="text-coal/80 font-serif italic text-sm leading-relaxed border-t border-coal/10 pt-2">
              "{hitlRequest.requesterReasoning}"
            </p>
          </div>
          
          {/* Elegant Neoclassical Divider */}
          <div className="neoclassical-divider opacity-30 py-2">
            <div className="divider-line"></div>
            <div className="divider-ornament">
              <div className="divider-dot"></div>
            </div>
            <div className="divider-line"></div>
          </div>

          <div className="flex space-x-4 font-serif text-sm">
            <button
              disabled={isSubmitting}
              onClick={() => handleAction(true)}
              className="flex-1 bg-terracotta hover:bg-terracotta/95 text-canvas py-2.5 transition-all duration-300 shadow-md border border-gold/25 font-bold uppercase tracking-widest disabled:opacity-50 cursor-pointer"
            >
              Approve
            </button>
            <button
              disabled={isSubmitting}
              onClick={() => handleAction(false)}
              className="flex-1 bg-transparent hover:bg-coal/5 text-coal py-2.5 transition-all duration-300 border border-coal/30 font-bold uppercase tracking-widest disabled:opacity-50 cursor-pointer"
            >
              Deny
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
