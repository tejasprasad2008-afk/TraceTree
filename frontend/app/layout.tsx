import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "TraceTree Workbench",
  description: "Runtime behavioral security scanner",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body style={{ background: "var(--bg-app)", color: "var(--text-primary)" }}>
        {children}
      </body>
    </html>
  );
}
