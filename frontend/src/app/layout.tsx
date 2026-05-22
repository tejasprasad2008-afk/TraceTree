import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "TraceTree Unified Command",
  description: "Autonomous Security Investigation & Response",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full">
      <body className="m-0 p-0 w-full min-h-full">{children}</body>
    </html>
  );
}
