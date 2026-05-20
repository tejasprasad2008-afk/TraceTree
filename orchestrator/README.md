# OpenClue

**OpenClue** is a standalone, local-first, open-source version of Anthropic's internal "CLUE" (Claude Looks Up Evidence) platform. It is an AI-driven Detection and Response (SOAR) engine designed to automate security triage and investigations through natural language orchestration.

## 🚀 Quick Start

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **Package Manager**: npm, pnpm, or yarn
- **LLM Access**: 
  - Anthropic Claude API Key (Recommended)
  - OpenRouter API Key
  - Local [Ollama](https://ollama.com/) Instance

### Installation
```bash
git clone https://github.com/your-org/openclue.git
cd openclue
npm install
npm run build
```

### Initial Onboarding
Run the following command to trigger the interactive setup wizard:
```bash
npx openclue init
```
This will guide you through selecting an LLM provider and configuring your credentials.

---

## 🛠 Usage Commands

### 1. Natural Language Investigation
Start an autonomous investigation loop by describing a security incident in natural language.
```bash
npx openclue investigate "A developer escalated their privileges to admin. Check for compromise."
```

### 2. Automated Triage
Stream a raw SIEM or Webhook alert JSON for a fast-pass confidence score and disposition verdict.
```bash
npx openclue triage ./alerts/sample_siem_alert.json
```

### 3. Demo Mode (Zero-Config Sandbox)
Witness the full autonomous orchestration loop instantly using simulated security tools (no API keys required for tools).
```bash
npx openclue investigate "Check IP 185.151.242.15 for malicious activity" --demo
```

### 4. Resuming a Session (HITL)
If a destructive action is detected, the engine will pause. Resume it using the session ID provided in the console.
```bash
npx openclue resume <session_id> --approve
```

---

## 🧠 Architectural Lifecycle

OpenClue executes a deterministic 4-phase lifecycle for every investigation:

1.  **Natural Language Triage:** Ingests the query or alert and establishes a hypothesis.
2.  **Autonomous Multi-Step Planner:** Generates a 5–6 step strategic investigation plan using the LLM Orchestrator.
3.  **MCP Execution Loop:** Executes tools via the **Model Context Protocol (MCP)**.
    - **Parallelism**: Independent steps run concurrently.
    - **Timeouts**: Every tool call has a strict 15s racing timeout.
    - **Resilience**: Individual tool failures do not crash the investigation.
4.  **Synthesis Engine:** Aggregates raw findings into a clean, Markdown-formatted **Final Investigation Summary** with a disposition verdict.

---

## 🛡 Security & Privacy
- **Local-First**: Sensitive session states and tool outputs are stored locally in `.openclue/`.
- **HITL Barrier**: Destructive actions (credential revocation, isolation) require manual analyst approval before execution.
- **Provider Agnostic**: Switch seamlessly between cloud APIs (Claude) and local inference (Ollama) to maintain data sovereignty.

## 📜 License
Apache-2.0
