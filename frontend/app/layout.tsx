import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "TraceTree :: Cascade Analyzer - Security Dashboard",
  description: "Retro Style Security Telemetry Panel",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-90s-tile font-sans text-black min-h-screen">
        {children}
      </body>
    </html>
  );
}
