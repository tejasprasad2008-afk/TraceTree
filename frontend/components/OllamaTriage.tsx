import React, { useEffect, useRef } from "react";

interface OllamaTriageProps {
  text: string;
  isStreaming: boolean;
}

export default function OllamaTriage({ text, isStreaming }: OllamaTriageProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Auto-scroll to bottom of terminal during streaming
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [text]);

  return (
    <div
      ref={containerRef}
      className="h-48 overflow-y-auto border-2 border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] bg-black p-3 font-mono text-sm text-[#00FF00] select-text"
    >
      {text ? (
        <span className="whitespace-pre-wrap leading-relaxed">
          {text}
          {isStreaming && <span className="animate-pulse">█</span>}
        </span>
      ) : (
        <span className="text-[#005500] italic">
          Awaiting Ollama False Positive Jury analysis report...
        </span>
      )}
    </div>
  );
}
