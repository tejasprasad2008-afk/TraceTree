"use client";
import { useEffect, useState } from "react";
import { Panel } from "../Panel";

interface SettingsProps {
  apiKey: string;
  onApiKeyChange: (k: string) => void;
}

interface ConnStatus {
  api: boolean;
  ollama: boolean;
  orchestrator: boolean;
}

interface ModelInfo {
  model_type: string;
  metrics: Record<string, number>;
  retrain_status: { status: string; last_run: string | null; error: string | null };
}

export function Settings({ apiKey, onApiKeyChange }: SettingsProps) {
  const [keyDraft, setKeyDraft] = useState(apiKey);
  const [conn, setConn] = useState<ConnStatus>({ api: false, ollama: false, orchestrator: false });
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);
  const [retraining, setRetraining] = useState(false);
  const [retrainMsg, setRetrainMsg] = useState<string | null>(null);

  useEffect(() => {
    const check = async () => {
      const [api, ollama, orch] = await Promise.all([
        fetch("http://127.0.0.1:8000/").then((r) => r.ok).catch(() => false),
        fetch("http://localhost:11434/api/tags").then((r) => r.ok).catch(() => false),
        fetch("http://localhost:3000/health").then((r) => r.ok).catch(() => false),
      ]);
      setConn({ api: api as boolean, ollama: ollama as boolean, orchestrator: orch as boolean });
    };
    check();

    fetch("http://127.0.0.1:8000/api/model/info", { headers: { "X-API-Key": apiKey } })
      .then((r) => r.ok ? r.json() : null)
      .then((d) => { if (d) setModelInfo(d); })
      .catch(() => {});
  }, [apiKey]);

  const handleRetrain = async () => {
    setRetraining(true);
    setRetrainMsg(null);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/model/retrain", {
        method: "POST",
        headers: { "X-API-Key": apiKey },
      });
      setRetrainMsg(res.ok ? "Retraining triggered in background." : "Failed to trigger retraining.");
    } catch {
      setRetrainMsg("Connection error.");
    } finally {
      setRetraining(false);
    }
  };

  const dot = (on: boolean) => (
    <span
      style={{
        display: "inline-block",
        width: 6,
        height: 6,
        background: on ? "var(--sev-safe)" : "var(--sev-danger)",
        marginRight: 6,
        flexShrink: 0,
      }}
    />
  );

  const services = [
    { label: "FastAPI Gateway :8000", on: conn.api },
    { label: "Ollama AI :11434", on: conn.ollama },
    { label: "Orchestrator WS :3000", on: conn.orchestrator },
  ];

  return (
    <div style={{ padding: 8, display: "flex", flexDirection: "column", gap: 8, overflow: "auto", height: "100%" }}>
      <Panel title="API Key">
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <input
            value={keyDraft}
            onChange={(e) => setKeyDraft(e.target.value)}
            style={{
              flex: 1,
              background: "var(--bg-inset)",
              border: "1px solid var(--border)",
              color: "var(--text-primary)",
              fontSize: 12,
              fontFamily: "var(--font-mono)",
              padding: "0 8px",
              height: 24,
              outline: "none",
            }}
          />
          <button
            onClick={() => {
              onApiKeyChange(keyDraft);
              localStorage.setItem("tracetree_api_key", keyDraft);
            }}
            style={{
              height: 24,
              padding: "0 12px",
              background: "var(--accent)",
              border: "none",
              color: "#000",
              fontSize: 11,
              fontFamily: "var(--font-ui)",
              fontWeight: 700,
              cursor: "pointer",
            }}
          >
            Save
          </button>
        </div>
        <div style={{ marginTop: 6, fontSize: 11, color: "var(--text-disabled)", fontFamily: "var(--font-ui)" }}>
          Authentication token for the local TraceTree API. Default <code style={{ color: "var(--text-muted)" }}>dev-key</code> works without any configuration when running locally.
        </div>
      </Panel>

      <Panel title="Backend Services">
        <div style={{ marginBottom: 8, fontSize: 11, color: "var(--text-disabled)", fontFamily: "var(--font-ui)" }}>
          FastAPI is required for all scans. Ollama enables AI triage summaries. Orchestrator handles live WebSocket events.
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {services.map((svc) => (
            <div key={svc.label} style={{ display: "flex", alignItems: "center", height: 24 }}>
              {dot(svc.on)}
              <span style={{ fontSize: 12, fontFamily: "var(--font-ui)", color: "var(--text-primary)" }}>{svc.label}</span>
              <span style={{ marginLeft: "auto", fontSize: 11, color: svc.on ? "var(--sev-safe)" : "var(--sev-danger)", fontFamily: "var(--font-ui)" }}>
                {svc.on ? "ONLINE" : "OFFLINE"}
              </span>
            </div>
          ))}
        </div>
      </Panel>

      {modelInfo && (
        <Panel title="Detection Model">
          <div style={{ marginBottom: 6, fontSize: 11, color: "var(--text-disabled)", fontFamily: "var(--font-ui)" }}>
            Random Forest classifier trained on behavioral features (process spawns, file writes, network connections, matched signatures). Trained on 5,030 labeled samples.
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <div style={{ fontSize: 12, color: "var(--text-primary)", fontFamily: "var(--font-ui)" }}>
              Type: <strong>{modelInfo.model_type}</strong>
            </div>
            <table style={{ fontSize: 11, fontFamily: "var(--font-ui)", borderCollapse: "collapse", width: "100%" }}>
              <tbody>
                {Object.entries(modelInfo.metrics || {}).map(([k, v]) => (
                  <tr key={k} style={{ height: 22 }}>
                    <td style={{ color: "var(--text-muted)", paddingRight: 12 }}>{k}</td>
                    <td style={{ color: "var(--text-primary)", fontFamily: "var(--font-mono)" }}>
                      {typeof v === "number" ? v.toFixed(4) : String(v)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {retrainMsg && (
              <div style={{ fontSize: 11, color: "var(--sev-info)", fontFamily: "var(--font-ui)" }}>{retrainMsg}</div>
            )}

            <button
              onClick={handleRetrain}
              disabled={retraining}
              style={{
                height: 24,
                padding: "0 12px",
                width: "max-content",
                background: "var(--bg-panel-alt)",
                border: "1px solid var(--border)",
                color: "var(--text-muted)",
                fontSize: 11,
                fontFamily: "var(--font-ui)",
                cursor: retraining ? "default" : "pointer",
              }}
            >
              {retraining ? "Retraining..." : "Retrain Model"}
            </button>
          </div>
        </Panel>
      )}
    </div>
  );
}
