import React from "react";

interface BevelButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  active?: boolean;
}

export default function BevelButton({ children, className = "", active = false, ...props }: BevelButtonProps) {
  const activeClasses = active
    ? "border-t-[#808080] border-l-[#808080] border-b-[#fff] border-r-[#fff] translate-x-[1px] translate-y-[1px]"
    : "border-t-[#fff] border-l-[#fff] border-b-[#808080] border-r-[#808080] active:border-t-[#808080] active:border-l-[#808080] active:border-b-[#fff] active:border-r-[#fff] active:translate-x-[1px] active:translate-y-[1px]";

  return (
    <button
      className={`px-3 py-1 font-sans text-sm text-black bg-[#C0C0C0] border-2 rounded-none select-none outline-none focus:outline-dotted focus:outline-2 focus:outline-black ${activeClasses} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}
