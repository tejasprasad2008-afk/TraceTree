import React from "react";

interface Win95CardProps {
  title: string;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
}

export default function Win95Card({ title, children, className = "", bodyClassName = "" }: Win95CardProps) {
  return (
    <div className={`border-2 border-t-[#fff] border-l-[#fff] border-b-[#808080] border-r-[#808080] bg-[#C0C0C0] p-1 rounded-none select-none ${className}`}>
      {/* Title Bar */}
      <div className="flex items-center justify-between bg-gradient-to-r from-[#000080] to-[#1084D0] px-1.5 py-1 text-white font-sans text-sm font-bold">
        <span className="truncate uppercase">{title}</span>
        <div className="flex items-center gap-0.5 shrink-0">
          <button className="w-[18px] h-[18px] flex items-center justify-center bg-[#C0C0C0] border-2 border-t-[#fff] border-l-[#fff] border-b-[#808080] border-r-[#808080] active:border-t-[#808080] active:border-l-[#808080] active:border-b-[#fff] active:border-r-[#fff] text-black font-mono text-[9px] select-none outline-none">
            🗕
          </button>
          <button className="w-[18px] h-[18px] flex items-center justify-center bg-[#C0C0C0] border-2 border-t-[#fff] border-l-[#fff] border-b-[#808080] border-r-[#808080] active:border-t-[#808080] active:border-l-[#808080] active:border-b-[#fff] active:border-r-[#fff] text-black font-mono text-[9px] select-none outline-none">
            🗖
          </button>
          <button className="w-[18px] h-[18px] flex items-center justify-center bg-[#C0C0C0] border-2 border-t-[#fff] border-l-[#fff] border-b-[#808080] border-r-[#808080] active:border-t-[#808080] active:border-l-[#808080] active:border-b-[#fff] active:border-r-[#fff] text-black font-mono text-[10px] font-bold select-none outline-none pl-[1px]">
            🗙
          </button>
        </div>
      </div>
      {/* Content Area */}
      <div className={`mt-1 border-2 border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] bg-[#C0C0C0] p-3 rounded-none ${bodyClassName}`}>
        {children}
      </div>
    </div>
  );
}
