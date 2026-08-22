import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        "bg-app":        "var(--bg-app)",
        "bg-panel":      "var(--bg-panel)",
        "bg-panel-alt":  "var(--bg-panel-alt)",
        "bg-inset":      "var(--bg-inset)",
        "bg-hover":      "var(--bg-hover)",
        "bg-selected":   "var(--bg-selected)",
        "border-def":    "var(--border)",
        "border-strong": "var(--border-strong)",
        "txt-primary":   "var(--text-primary)",
        "txt-muted":     "var(--text-muted)",
        "txt-disabled":  "var(--text-disabled)",
        "accent":        "var(--accent)",
        "accent-text":   "var(--accent-text)",
        "sev-danger":    "var(--sev-danger)",
        "sev-caution":   "var(--sev-caution)",
        "sev-safe":      "var(--sev-safe)",
        "sev-info":      "var(--sev-info)",
      },
      fontFamily: {
        ui:   ["var(--font-ui)"],
        mono: ["var(--font-mono)"],
      },
      fontSize: {
        "2xs":  ["10px", { lineHeight: "1.35", letterSpacing: "0.06em" }],
        "xs":   ["11px", { lineHeight: "1.35" }],
        "sm":   ["12px", { lineHeight: "1.35" }],
        "base": ["13px", { lineHeight: "1.35" }],
        "lg":   ["15px", { lineHeight: "1.35" }],
      },
    },
  },
  plugins: [],
};

export default config;
