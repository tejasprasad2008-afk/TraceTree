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
      const response = await fetch('http://localhost:3000/api/approve', {
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
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-red-900/50 w-full max-w-md rounded-xl shadow-2xl shadow-red-900/20 overflow-hidden">
        <div className="bg-red-950/30 px-6 py-4 border-b border-red-900/30">
          <h3 className="text-red-500 font-bold flex items-center">
            <svg className="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            HITL AUTHORIZATION REQUIRED
          </h3>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="text-[10px] text-gray-500 uppercase font-mono">Tool Call</label>
            <div className="text-white font-mono bg-black p-2 rounded border border-gray-800 mt-1">
              {hitlRequest.toolCall.name}
            </div>
          </div>
          <div>
            <label className="text-[10px] text-gray-500 uppercase font-mono">Reasoning</label>
            <p className="text-gray-300 text-sm mt-1 leading-relaxed">
              {hitlRequest.requesterReasoning}
            </p>
          </div>
          <div className="pt-4 flex space-x-3">
            <button
              disabled={isSubmitting}
              onClick={() => handleAction(true)}
              className="flex-1 bg-red-600 hover:bg-red-500 text-white font-bold py-2 rounded transition-colors disabled:opacity-50"
            >
              APPROVE
            </button>
            <button
              disabled={isSubmitting}
              onClick={() => handleAction(false)}
              className="flex-1 bg-gray-800 hover:bg-gray-700 text-gray-300 font-bold py-2 rounded transition-colors disabled:opacity-50"
            >
              DENY
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
