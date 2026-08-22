"use client";

import { useState } from "react";

type ProviderId = "openai" | "claude" | "openrouter" | "ollama";

const PROVIDERS: { id: ProviderId; name: string; detail: string; keyLabel?: string; baseUrl: string; modelHint: string; requiresApiKey: boolean; defaultModel?: string }[] = [
  {
    id: "openai",
    name: "OpenAI",
    detail: "Direct access to OpenAI models",
    keyLabel: "OpenAI API key",
    baseUrl: "https://api.openai.com/v1",
    modelHint: "e.g. gpt-4.1-mini",
    requiresApiKey: true,
  },
  {
    id: "claude",
    name: "Anthropic",
    detail: "Direct access to Claude models",
    keyLabel: "Anthropic API key",
    baseUrl: "https://api.anthropic.com",
    modelHint: "e.g. claude-sonnet-4-5",
    requiresApiKey: true,
  },
  {
    id: "openrouter",
    name: "OpenRouter",
    detail: "One endpoint for many model providers",
    keyLabel: "OpenRouter API key",
    baseUrl: "https://openrouter.ai/api/v1",
    modelHint: "e.g. openai/gpt-4.1-mini",
    requiresApiKey: true,
  },
  {
    id: "ollama",
    name: "Ollama",
    detail: "Run a private model locally — no API key needed",
    baseUrl: "http://localhost:11434",
    modelHint: "qwen2.5-coder:7b",
    defaultModel: "qwen2.5-coder:7b",
    requiresApiKey: false,
  },
];

interface FirstRunSetupProps {
  apiKey: string;
  onComplete: () => void;
}

export function FirstRunSetup({ apiKey, onComplete }: FirstRunSetupProps) {
  const [step, setStep] = useState(0);
  const [provider, setProvider] = useState<ProviderId>("openai");
  const [apiToken, setApiToken] = useState("");
  const [baseUrl, setBaseUrl] = useState(PROVIDERS[0].baseUrl);
  const [model, setModel] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [ollamaReady, setOllamaReady] = useState(false);

  const selected = PROVIDERS.find((item) => item.id === provider)!;
  const apiBase = process.env.NEXT_PUBLIC_TRACETREE_API_URL || "http://127.0.0.1:8000";
  const totalSteps = selected.requiresApiKey ? 4 : 3;
  const displayStep = step === 0 ? 1 : step === 2 ? (selected.requiresApiKey ? 3 : 2) : step === 3 ? totalSteps : 0;
  const finishLater = () => {
    localStorage.setItem("tracetree_setup_complete", "skipped");
    onComplete();
  };
  const save = async () => {
    if (!model.trim()) { setError("Enter the model name you want TraceTree to use."); return; }
    setSaving(true); setError("");
    try {
      const response = await fetch(`${apiBase}/api/setup/llm`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
        body: JSON.stringify({ provider, api_key: apiToken, base_url: baseUrl, model }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || "TraceTree could not save this configuration.");
      localStorage.setItem("tracetree_setup_complete", "configured");
      setOllamaReady(provider === "ollama" && data.model_warmed === true);
      setStep(4);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to save setup.");
    } finally { setSaving(false); }
  };
  const exitSetup = async () => {
    try {
      await fetch(`${apiBase}/api/setup/exit`, {
        method: "POST",
        headers: { "X-API-Key": apiKey },
      });
    } finally {
      window.location.replace("about:blank");
    }
  };
  const openDashboard = () => {
    window.history.replaceState(null, "", window.location.pathname);
    onComplete();
  };

  const title = ["Choose your AI provider", "Add an API key", "Confirm the endpoint", "Choose a model", "Setup saved"][step];
  return (
    <main style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: 24, background: "radial-gradient(circle at 12% 15%, #263d4d 0, transparent 32%), var(--bg-app)" }}>
      <section style={{ width: "min(720px, 100%)", border: "1px solid var(--border-strong)", background: "var(--bg-panel)", padding: 28 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 30 }}>
          <div>
            <div style={{ color: "var(--accent)", fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: 1.4 }}>TRACETREE WORKBENCH</div>
            <h1 style={{ margin: "6px 0 0", fontSize: 26, lineHeight: 1.1, color: "var(--text-primary)" }}>First-run setup</h1>
          </div>
          <div style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 11 }}>{step < 4 ? `STEP ${displayStep} / ${totalSteps}` : "READY"}</div>
        </div>
        {step < 4 && <div style={{ display: "flex", gap: 4, marginBottom: 28 }}>{Array.from({ length: totalSteps }, (_, item) => <span key={item} style={{ height: 3, flex: 1, background: item < displayStep ? "var(--accent)" : "var(--border)" }} />)}</div>}
        <h2 style={{ margin: "0 0 8px", fontSize: 18 }}>{title}</h2>
        {step === 0 && <><p style={{ color: "var(--text-muted)", marginTop: 0 }}>Select the service that will generate optional AI triage summaries. OpenAI is first; you can change this later in your local <code>.env</code>.</p><div style={{ display: "grid", gap: 8 }}>{PROVIDERS.map((item) => <button key={item.id} onClick={() => { setProvider(item.id); setBaseUrl(item.baseUrl); setModel(item.defaultModel || ""); setError(""); }} style={{ textAlign: "left", padding: 14, border: `1px solid ${provider === item.id ? "var(--accent)" : "var(--border)"}`, background: provider === item.id ? "#273a42" : "var(--bg-inset)", color: "var(--text-primary)", cursor: "pointer" }}><strong>{item.name}</strong><span style={{ display: "block", marginTop: 3, fontSize: 11, color: "var(--text-muted)" }}>{item.detail}</span></button>)}</div></>}
        {step === 1 && <><p style={{ color: "var(--text-muted)", marginTop: 0 }}>Your key is saved only to this machine&apos;s ignored <code>.env</code> file. It is never displayed again.</p><label style={{ display: "block", fontSize: 11, color: "var(--text-muted)", marginBottom: 6 }}>{selected.keyLabel}</label><input autoFocus type="password" value={apiToken} onChange={(event) => setApiToken(event.target.value)} placeholder="Paste your API key" style={inputStyle} /></>}
        {step === 2 && <><p style={{ color: "var(--text-muted)", marginTop: 0 }}>{provider === "ollama" ? "Ollama must be running locally. The default is prefilled; you can use another local endpoint if needed." : "The official default is prefilled. Press Continue to accept it, or paste a compatible endpoint."}</p><label style={labelStyle}>Base URL</label><input autoFocus value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} style={inputStyle} /></>}
        {step === 3 && <><p style={{ color: "var(--text-muted)", marginTop: 0 }}>{provider === "ollama" ? "TraceTree will check Ollama and download this model when it is not installed yet. The first download can take a few minutes." : "Enter the exact model identifier available to your account. TraceTree does not silently choose a different model."}</p><label style={labelStyle}>Model name</label><input autoFocus value={model} onChange={(event) => setModel(event.target.value)} placeholder={selected.modelHint} style={inputStyle} /></>}
        {step === 4 && <div style={{ padding: "14px 0" }}><div style={{ color: "var(--sev-safe)", fontSize: 18, fontWeight: 700, display: "flex", alignItems: "center", gap: 9 }}>{ollamaReady && <span aria-label="Ollama connected and model ready" title="Ollama connected and model ready" style={{ width: 20, height: 20, borderRadius: "50%", display: "inline-grid", placeItems: "center", background: "var(--sev-safe)", color: "#101817", fontSize: 13 }}>✓</span>}{ollamaReady ? "Ollama connected and model ready." : "Configuration saved locally."}</div><p style={{ color: "var(--text-muted)", maxWidth: 520 }}>Open Dashboard to continue immediately. TraceTree reloads the orchestrator with your selected provider in the background.</p></div>}
        {error && <div style={{ marginTop: 16, padding: 10, border: "1px solid var(--sev-danger)", color: "var(--sev-danger-text)", background: "#321f21" }}>{error}</div>}
        <div style={{ display: "flex", justifyContent: "space-between", gap: 10, marginTop: 30 }}>
          {step < 4 ? <button onClick={finishLater} style={secondaryStyle}>Set up later (local mock mode)</button> : <span />}
          <div style={{ display: "flex", gap: 8 }}>{step > 0 && step < 4 && <button onClick={() => { setError(""); setStep(step === 2 && !selected.requiresApiKey ? 0 : step - 1); }} style={secondaryStyle}>Back</button>}{step === 0 && <button onClick={() => { setError(""); setStep(selected.requiresApiKey ? 1 : 2); }} style={primaryStyle}>Continue</button>}{step === 1 && <button disabled={!apiToken.trim()} onClick={() => { setError(""); setStep(2); }} style={primaryStyle}>Continue</button>}{step === 2 && <button disabled={!baseUrl.trim()} onClick={() => { setError(""); setStep(3); }} style={primaryStyle}>Continue</button>}{step === 3 && <button disabled={saving} onClick={save} style={primaryStyle}>{saving ? (provider === "ollama" ? "Preparing model…" : "Saving…") : (provider === "ollama" ? "Download model & save" : "Save configuration")}</button>}{step === 4 && <><button onClick={exitSetup} style={secondaryStyle}>Save & exit setup</button><button onClick={openDashboard} style={primaryStyle}>Open dashboard</button></>}</div>
        </div>
      </section>
    </main>
  );
}

const inputStyle = { width: "100%", boxSizing: "border-box" as const, height: 40, padding: "0 11px", background: "var(--bg-inset)", border: "1px solid var(--border-strong)", color: "var(--text-primary)", fontFamily: "var(--font-mono)", outline: "none" };
const labelStyle = { display: "block", fontSize: 11, color: "var(--text-muted)", marginBottom: 6 };
const primaryStyle = { height: 34, padding: "0 14px", border: "none", background: "var(--accent)", color: "#17181a", fontWeight: 700, cursor: "pointer" };
const secondaryStyle = { height: 34, padding: "0 12px", border: "1px solid var(--border-strong)", background: "transparent", color: "var(--text-muted)", cursor: "pointer" };
