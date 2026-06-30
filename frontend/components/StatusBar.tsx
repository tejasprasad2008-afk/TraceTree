import React, { useState, useEffect } from "react";

export default function StatusBar() {
  const [time, setTime] = useState("");

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTime(now.toLocaleTimeString());
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <footer className="fixed bottom-0 left-0 right-0 h-7 bg-[#C0C0C0] border-t-2 border-t-[#fff] flex items-center justify-between px-1 text-xs text-black font-sans z-50 select-none py-0.5">
      {/* Left panel */}
      <div className="flex-1 flex items-center gap-2 border border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] px-2 h-full truncate mr-1.5">
        <span>TRACETREE v1.0.0</span>
        <span className="text-[#808080] font-normal">|</span>
        <span>MODEL: RANDOMFOREST</span>
        <span className="text-[#808080] font-normal font-sans">|</span>
        <span>ISOLATION: DOCKER</span>
      </div>

      {/* Center panel */}
      <div className="w-56 hidden md:flex items-center justify-between border border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] px-2 h-full mr-1.5 font-mono">
        <span>VISITORS: 000,042</span>
        <span className="text-[9px] font-sans font-bold">EST. 2025</span>
      </div>

      {/* Right panel (Clock) */}
      <div className="w-24 flex items-center justify-center border border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] px-2 h-full font-mono font-bold">
        {time}
      </div>
    </footer>
  );
}
