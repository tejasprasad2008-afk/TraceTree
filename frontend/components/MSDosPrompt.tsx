"use client";

import React, { useRef, useEffect } from "react";
import BevelButton from "./BevelButton";

interface MSDosPromptProps {
  command: string;
  setCommand: (cmd: string) => void;
  isRunning: boolean;
  terminalOutput: string[];
  enableAi: boolean;
  setEnableAi: (val: boolean) => void;
  onExecute: () => void;
  onClear: () => void;
}

export default function MSDosPrompt({
  command,
  setCommand,
  isRunning,
  terminalOutput,
  enableAi,
  setEnableAi,
  onExecute,
  onClear
}: MSDosPromptProps) {
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll terminal output to the bottom
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [terminalOutput]);

  const selectCommandTemplate = (template: string) => {
    if (isRunning) return;
    if (template === "analyze") {
      setCommand("python3 cli.py analyze urllib33");
    } else if (template === "triage") {
      setCommand("python3 cli.py triage test_all_payloads.json");
    } else if (template === "scan") {
      setCommand("python3 cli.py scan cli.py");
    } else if (template === "init") {
      setCommand("python3 cli.py init");
    }
  };

  return (
    <div className="flex flex-col gap-2">
      {/* 90s Command presets */}
      <div className="flex flex-wrap items-center gap-1.5 p-1.5 bg-[#C0C0C0] border border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] select-none">
        <span className="font-mono text-xs font-bold mr-1">PRESETS:</span>
        <BevelButton onClick={() => selectCommandTemplate("analyze")} disabled={isRunning}>
          [ analyze ]
        </BevelButton>
        <BevelButton onClick={() => selectCommandTemplate("triage")} disabled={isRunning}>
          [ triage ]
        </BevelButton>
        <BevelButton onClick={() => selectCommandTemplate("scan")} disabled={isRunning}>
          [ scan ]
        </BevelButton>
        <BevelButton onClick={() => selectCommandTemplate("init")} disabled={isRunning}>
          [ init ]
        </BevelButton>
        
        <div className="flex items-center gap-1.5 ml-auto pl-2 border-l border-zinc-500">
          <input
            type="checkbox"
            id="enable-ai-prompt"
            checked={enableAi}
            onChange={(e) => setEnableAi(e.target.checked)}
            disabled={isRunning}
            className="w-3.5 h-3.5 border-2 border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] bg-white outline-none cursor-pointer"
          />
          <label htmlFor="enable-ai-prompt" className="font-mono text-xs font-bold select-none cursor-pointer">
            ENABLE LOCAL AI (--ai)
          </label>
        </div>
      </div>

      {/* Terminal Input Line */}
      <div className="flex items-center gap-2 bg-black text-[#00FF00] font-mono text-sm border-2 border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] p-2">
        <span className="shrink-0 select-none">C:\TRACETREE&gt;</span>
        <input
          type="text"
          className="flex-1 bg-black text-[#00FF00] font-mono text-sm outline-none border-none p-0 select-text"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          disabled={isRunning}
          onKeyDown={(e) => {
            if (e.key === "Enter" && command.trim() && !isRunning) {
              onExecute();
            }
          }}
        />
        <BevelButton
          onClick={onExecute}
          disabled={isRunning || !command.trim()}
          className="font-bold text-black border-[#C0C0C0]"
          style={{ padding: "1px 8px" }}
        >
          {isRunning ? "RUNNING..." : "ENTER"}
        </BevelButton>
      </div>

      {/* MS-DOS terminal screen */}
      <div className="bg-black text-[#00FF00] font-mono text-xs p-3 overflow-y-auto h-[250px] border-2 border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] select-text">
        <div className="flex flex-col gap-1">
          {terminalOutput.map((line, idx) => (
            <div key={idx} className="whitespace-pre-wrap leading-tight font-mono">
              {line}
            </div>
          ))}
          {isRunning && (
            <div className="inline-block animate-pulse w-2 h-4 bg-[#00FF00] ml-0.5"></div>
          )}
          <div ref={terminalEndRef} />
        </div>
      </div>

      {/* Clear logs */}
      <div className="flex justify-end select-none">
        <BevelButton onClick={onClear} disabled={isRunning} className="text-xs">
          [ CLEAR CONSOLE ]
        </BevelButton>
      </div>
    </div>
  );
}
