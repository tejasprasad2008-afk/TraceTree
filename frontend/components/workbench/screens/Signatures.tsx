"use client";
import { useEffect, useState } from "react";

interface SignaturesProps {
  apiKey: string;
}

export function Signatures({ apiKey }: SignaturesProps) {
  const [rules, setRules] = useState("// Loading YARA signatures...");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const fetchRules = () => {
    fetch("http://127.0.0.1:8000/api/signatures", { headers: { "X-API-Key": apiKey } })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (d?.rules) setRules(d.rules); })
      .catch(() => {});
  };

  useEffect(() => { fetchRules(); }, [apiKey]);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/signatures", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
        body: JSON.stringify({ rules }),
      });
      if (res.ok) {
        setSuccess("Signatures saved and validated.");
      } else {
        const e = await res.json().catch(() => ({ detail: res.statusText }));
        setError(e.detail || "Save failed");
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleDiscard = () => {
    setError(null);
    setSuccess(null);
    fetchRules();
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", padding: 8, gap: 6 }}>
      <div style={{ padding: "6px 10px", background: "var(--bg-panel)", border: "1px solid var(--border)", fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-ui)", lineHeight: 1.5 }}>
        <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>Custom Detection Rules</span>
        {" — "}YARA signatures matched against every scanned file. Add rules here to flag specific malware families, supply-chain attack patterns, or internal policy violations. Changes take effect on the next scan.
      </div>
      {error && (
        <div style={{ background: "var(--bg-inset)", border: "1px solid var(--sev-danger)", padding: "6px 10px", fontSize: 11, color: "var(--sev-danger)", fontFamily: "var(--font-ui)" }}>
          Error: {error}
        </div>
      )}
      {success && (
        <div style={{ background: "var(--bg-inset)", border: "1px solid var(--sev-safe)", padding: "6px 10px", fontSize: 11, color: "var(--sev-safe)", fontFamily: "var(--font-ui)" }}>
          {success}
        </div>
      )}

      <div style={{ display: "flex", gap: 6 }}>
        <button
          onClick={handleSave}
          disabled={saving}
          style={{
            height: 24,
            padding: "0 12px",
            background: "var(--accent)",
            border: "none",
            color: "#000",
            fontSize: 11,
            fontFamily: "var(--font-ui)",
            fontWeight: 700,
            cursor: saving ? "default" : "pointer",
          }}
        >
          {saving ? "Saving..." : "Save & Validate"}
        </button>
        <button
          onClick={handleDiscard}
          style={{
            height: 24,
            padding: "0 12px",
            background: "var(--bg-panel-alt)",
            border: "1px solid var(--border)",
            color: "var(--text-muted)",
            fontSize: 11,
            fontFamily: "var(--font-ui)",
            cursor: "pointer",
          }}
        >
          Discard Changes
        </button>
      </div>

      <textarea
        value={rules}
        onChange={(e) => setRules(e.target.value)}
        spellCheck={false}
        style={{
          flex: 1,
          background: "var(--bg-inset)",
          border: "1px solid var(--border)",
          color: "var(--text-primary)",
          fontSize: 12,
          fontFamily: "var(--font-mono)",
          padding: 8,
          resize: "none",
          outline: "none",
          lineHeight: 1.5,
        }}
      />
    </div>
  );
}
