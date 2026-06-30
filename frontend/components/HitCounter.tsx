import React from "react";

interface HitCounterProps {
  value: number | string;
  digits?: number;
}

export default function HitCounter({ value, digits = 6 }: HitCounterProps) {
  const strVal = typeof value === "number" ? String(value).padStart(digits, "0") : value;
  
  return (
    <div className="inline-flex border-2 border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] bg-black px-2 py-1 select-none">
      <span className="font-mono text-lg font-bold text-[#00FF00] tracking-widest uppercase">
        {strVal}
      </span>
    </div>
  );
}
