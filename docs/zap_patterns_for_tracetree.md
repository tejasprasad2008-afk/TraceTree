# ZAP Architecture Patterns for TraceTree

Source: OWASP ZAP commit `3bec228` (shallow clone, `zaproxy/zaproxy`).
Scope: 6 subsystems only. Web-proxy concepts (ProxyEngine, HttpSender, ActiveScan,
Auth, Scripting, zap-extensions) are deliberately excluded — they map to nothing
in TraceTree's pipeline.

---

## Cross-Subsystem Wiring Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                         STARTUP PHASE                            │
│                                                                  │
│  AddOnLoader ──creates──► AddOn ──contains──► Extension(s)       │
│       │                                                          │
│       └──addExtension()──► ExtensionLoader                       │
│                                 │                                │
│                    for each ext: hook(ExtensionHook)             │
│                                 │                                │
│                    ExtensionAdaptor ──registers into──►          │
│                         ExtensionHook                            │
│                        /    |     \                              │
│               PassiveScanner  ApiImplementor  EventConsumer      │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                       RUNTIME DATA FLOW                          │
│                                                                  │
│  [item arrives]                                                  │
│       │                                                          │
│       ▼                                                          │
│  HistoryReference (id, type, cached bytes, Set<Alert>, tags)     │
│       │                    │                                     │
│       ▼                    ▼                                     │
│  TableHistory          HistoryReferenceEventPublisher            │
│  RecordHistory              │                                    │
│                             ▼                                    │
│                       SimpleEventBus                             │
│                             │  publishSyncEvent(ADD/TAG/NOTE)    │
│                             ▼                                    │
│                       EventConsumer(s)  [UI tabs, Dashboard]     │
│                                                                  │
│  PassiveScanController ──polls── HistoryReference queue          │
│       │                                                          │
│       ▼                                                          │
│  PassiveScanTaskHelper ──iterates── [PassiveScanner list]        │
│       │                                                          │
│  each scanner: scanHttpResponseReceive(msg, id, source)          │
│       │                                                          │
│       ▼                                                          │
│  PassiveScanActions.raiseAlert() ──writes──► TableAlert          │
│                                               RecordAlert        │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                         MODEL LAYER                              │
│                                                                  │
│  Model (singleton)                                               │
│    ├── Session ──owns──► SiteMap ──► SiteNode ──► HistoryRef(s)  │
│    └── Database ──► TableHistory / TableAlert                    │
│                                                                  │
│  API (singleton, Map<prefix, ApiImplementor>)                    │
│    └── each extension registers ApiImplementor via ExtensionHook │
└──────────────────────────────────────────────────────────────────┘
```

Load-bearing abstractions (5):
1. `ExtensionHook` — every capability plugs in here
2. `HistoryReference` — the universal artifact handle
3. `SimpleEventBus` — decouples producers from UI consumers
4. `TableHistory` / `TableAlert` split — raw vs. derived data
5. `ApiImplementor` — distributed API surface, no central router

---

## Subsystem 1: Extension / Add-on Loader

### ZAP pattern

**Problem:** ZAP has ~50 built-in capabilities plus a marketplace of community
add-ons. Hardcoding them all into `Control` would make the codebase unmaintainable
and prevent hot-load/unload.

**Core contract — `ExtensionAdaptor` (abstract class):**

```java
void init()                            // phase 1: no dependencies yet
void initModel(Model model)            // phase 2: get data model handle
void initView(ViewDelegate view)       // phase 3: build UI (skipped in daemon mode)
void initXML(Session session, OptionsParam options)  // phase 4: load config
void hook(ExtensionHook extensionHook) // phase 5: register everything
void start()                           // phase 6: start background work
void postInit()                        // phase 7: after all extensions started
void stop() / void destroy()           // shutdown
boolean canUnload()                    // hot-unload gate
List<Class<? extends Extension>> getDependencies() // ordering
```

**`ExtensionHook` — the registration bag (one instance per extension):**

Extensions call these on their hook during `hook()`:
- `addPassiveScannerList(list)` → scanner engine picks up
- `addApiImplementor(impl)` → REST API picks up
- `addSessionListener(l)` → notified on session change
- `addSiteMapListener(l)` → notified on tree change
- `addContextDataFactory(f)` → contributes metadata to Context objects
- `addAddonFilesChangedListener(l)` → notified when add-on files change

**`ExtensionLoader`** — holds `Map<Extension, ExtensionHook>`. On startup calls
`hook()` on every extension. On event (session change, scanner run, API call),
iterates all `extensionHooks.values()` and dispatches to each registered listener.
`addExtension()` / `removeExtension()` enable dynamic hot-load.

**`AddOnLoader`** — reads `.zap` files (zip), class-loads them with isolated
`AddOnClassLoader`, instantiates extensions via `ExtensionFactory`, hands to
`ExtensionLoader`.

### TraceTree translation

**Equivalent problem:** YARA rule packs, alternate classifier backends
(RandomForest → LLM judge → GBDT), and community heuristics are all currently
hardcoded into `monitor/signatures.py`, `monitor/parser.py`, and `api/main.py`.
Adding a new detector requires editing core files.

**Proposed pattern — `AnalyzerPlugin` contract:**

```python
class AnalyzerPlugin(ABC):
    # Phase 1: no deps
    def init(self) -> None: ...

    # Phase 2: get shared data handle
    def init_store(self, store: TraceStore) -> None: ...

    # Phase 3: register capabilities
    def hook(self, hook: AnalyzerHook) -> None: ...

    # Phase 4: start background threads if needed
    def start(self) -> None: ...
    def stop(self) -> None: ...

    @property
    def name(self) -> str: ...

    @property
    def dependencies(self) -> list[type["AnalyzerPlugin"]]: ...
    def can_unload(self) -> bool: return False
```

**`AnalyzerHook` — registration bag:**

```python
@dataclass
class AnalyzerHook:
    detector_rules: list[DetectorRule] = field(default_factory=list)
    classifier_backends: list[ClassifierBackend] = field(default_factory=list)
    api_namespaces: list[APINamespace] = field(default_factory=list)
    sample_listeners: list[SampleEventListener] = field(default_factory=list)
```

**`PluginLoader`** loads from a `plugins/` directory on startup. Concrete plugins:
- `YaraPackPlugin` — registers YARA rule sets; `hook()` adds `DetectorRule` entries
- `RandomForestPlugin` — registers the current RF classifier; `hook()` adds
  `ClassifierBackend`
- `LegsPlugin` — registers the multi-stage LLM triage chain
- Community plugin could add new Legs stages or override confidence thresholds

**Key lifecycle payoff:** Legs pipeline stages become `AnalyzerPlugin`s that declare
`dependencies = [YaraPackPlugin]`. `PluginLoader` topologically sorts and inits in
order — same mechanism ZAP uses for `getDependencies()`.

**What changes in TraceTree:**
- `monitor/signatures.py` becomes `plugins/builtin/yara_pack_plugin.py`
- `ml/model.skops` loading moves into `plugins/builtin/rf_classifier_plugin.py`
- `api/main.py` stops importing them directly; reads from `PluginLoader`
- New YARA packs drop into `plugins/community/` — zero core changes

---

## Subsystem 2: Passive Scan Engine

### ZAP pattern

**Problem:** ZAP needs many independent analysis rules to observe traffic and emit
findings without modifying or blocking anything. Rules must be independently
enable/disable-able, have per-rule confidence thresholds, and not know about each
other.

**Core interface — `PassiveScanner`:**

```java
void scanHttpResponseReceive(HttpMessage msg, int id, Source source)
void scanHttpRequestSend(HttpMessage msg, int id)
boolean appliesToHistoryType(int historyType)  // filter: only process relevant types
String getName()
void setEnabled(boolean enabled)
boolean isEnabled()
// raise findings via injected PassiveScanActions, not return value:
void setPassiveScanActions(PassiveScanActions actions)
```

Key design: **findings emitted via side-channel** (`PassiveScanActions.raiseAlert()`),
not returned. Scanner has no knowledge of where alerts go. Also: scanner is stateless
per call — it receives the full artifact (`HttpMessage`) and produces findings in one
invocation.

**`PluginPassiveScanner` (abstract)** extends this with:
- `AlertThreshold` (LOW/MEDIUM/HIGH) — controls sensitivity
- Per-scanner config persistence via `HierarchicalConfiguration`
- `getExampleAlerts()` — for documentation generation
- `List<Integer> getHistoryTypes()` — which traffic types trigger this scanner

**`PassiveScanController`** (deprecated in 2.16, replaced by task-based approach):
- Polls `TableHistory` for new `HistoryReference` IDs
- Submits each to `ThreadPoolExecutor` as `PassiveScanTask`
- `PassiveScanTaskHelper` iterates all registered `PassiveScanner`s against one item

**`ExtensionPassiveScan`** wires it: on `hook()`, calls
`hook.addPassiveScannerList(scanners)` — `ExtensionLoader` makes scanners available
to the controller at startup.

### TraceTree translation

**Equivalent problem:** TraceTree's "Legs" pipeline is a single monolithic function
chain. Adding a new analysis stage (e.g. a PE header heuristic, a strings entropy
check, a new Legs prompt) requires editing the core pipeline. There's no concept of
per-rule enable/disable or confidence thresholds.

**Proposed pattern — `SampleAnalyzer`:**

```python
class SampleAnalyzer(ABC):
    @abstractmethod
    def analyze(self, sample: SampleRecord, actions: AnalyzerActions) -> None:
        """Observe sample, emit findings via actions. Never mutate sample."""

    @abstractmethod
    def name(self) -> str: ...

    def applies_to(self, sample_type: SampleType) -> bool:
        return True  # default: all sample types

    def is_enabled(self) -> bool: return True
    def set_enabled(self, enabled: bool) -> None: ...
    confidence_threshold: float = 0.5
```

**`AnalyzerActions` — side-channel finding emission:**

```python
@dataclass
class AnalyzerActions:
    def raise_finding(self, finding: AnalysisFinding) -> None:
        """Write to verdict DB, publish event to bus."""
```

**`AnalysisFinding`:**

```python
@dataclass
class AnalysisFinding:
    analyzer_name: str
    sample_id: str
    verdict: Verdict          # MALICIOUS / BENIGN / UNCERTAIN
    confidence: float         # 0.0–1.0
    evidence: list[str]       # YARA hits, syscall patterns, feature importances
    model_version: str        # which model/prompt version produced this
    tags: list[str]
```

**`SampleAnalysisController`** — parallels `PassiveScanController`:
- Watches for new `SampleRecord`s via EventBus (or polls DB)
- Submits each to `ThreadPoolExecutor`
- `SampleAnalysisTask` iterates all enabled `SampleAnalyzer`s

**Concrete analyzers mapping to current TraceTree components:**
- `YaraAnalyzer` → wraps current `monitor/signatures.py` YARA matching
- `SyscallPatternAnalyzer` → wraps current `monitor/parser.py` trace parsing
- `LegsStage1Analyzer` → first LLM triage prompt
- `LegsStage2Analyzer` → second LLM triage prompt (depends on Stage1 finding)
- `RandomForestAnalyzer` → final classifier, reads feature vector from prior findings

**Key payoff:** each analyzer sees the same `SampleRecord` and emits to the same
`AnalyzerActions`. New community heuristic = new `SampleAnalyzer` subclass. The
Legs stages become observable and independently enable/disable-able from the
Signatures tab.

---

## Subsystem 3: Event Bus

### ZAP pattern

**Problem:** Many parts of ZAP need to react to the same events (new history item,
scan finding, session change) without the producer knowing about consumers. Polling
the DB is expensive and introduces latency on the Live/Dashboard tabs.

**`EventBus` interface:**

```java
void registerPublisher(EventPublisher publisher, String... eventTypes)
void unregisterPublisher(EventPublisher publisher)
void registerConsumer(EventConsumer consumer, String publisherName)
void registerConsumer(EventConsumer consumer, String publisherName, String... eventTypes)
void unregisterConsumer(EventConsumer consumer)
void publishSyncEvent(EventPublisher publisher, Event event)
Set<String> getPublisherNames()
```

**`SimpleEventBus` implementation:**
- `Map<String, RegisteredPublisher>` — publishers registered by name
- `CopyOnWriteArrayList<RegisteredConsumer>` — consumers per publisher/event-type
- `ReentrantLock` for registration (not dispatch) — dispatch is lock-free via COWL
- Only registered publishers can publish (guard at `publishSyncEvent`)
- Consumers can filter by specific event types, not just publisher name
- Dispatch is **synchronous** (`publishSyncEvent`) — no queue, no threading

**`EventPublisher` interface:** just `String getPublisherName()`.
**`EventConsumer` interface:** just `void eventReceived(Event event)`.

**`Event`:** carries `publisherName`, `eventType`, `Map<String, String> parameters`.

**`HistoryReferenceEventPublisher`** publishes:
- `HISTORY_REFERENCE_ADDED` — new item entered DB
- `HISTORY_REFERENCE_DELETED`
- `TAG_SET` — a tag was added
- `NOTE_SET` — a note was added

The History tab and Dashboard tab register as consumers — no polling.

**Notable design decision:** synchronous dispatch means the publisher thread also
runs consumer callbacks. ZAP accepts this because callbacks are fast (UI updates,
counter increments). Async would need a queue and risks out-of-order delivery.

### TraceTree translation

**Equivalent problem:** TraceTree's Live tab currently polls the DB (or relies on
page refresh) for new verdicts. Dashboard doesn't auto-update on new triage results.
The Legs pipeline has no way to push progress events to the frontend.

**Proposed pattern — `TraceEventBus`:**

```python
class TraceEventBus:
    def register_publisher(self, publisher: "EventPublisher", *event_types: str) -> None: ...
    def register_consumer(self, consumer: "EventConsumer", publisher_name: str,
                          *event_types: str) -> None: ...
    def publish(self, publisher: "EventPublisher", event: "TraceEvent") -> None: ...
    def unregister_consumer(self, consumer: "EventConsumer") -> None: ...
```

**`TraceEvent`:**

```python
@dataclass
class TraceEvent:
    publisher_name: str
    event_type: str
    params: dict[str, Any]
```

**Publishers in TraceTree:**

| Publisher | Event types |
|-----------|------------|
| `SampleEventPublisher` | `SAMPLE_SUBMITTED`, `SAMPLE_TRIAGE_STARTED`, `SAMPLE_VERDICT_READY`, `SAMPLE_DELETED` |
| `LegsEventPublisher` | `LEGS_STAGE_COMPLETE` (+ stage name, partial confidence) |
| `SignatureEventPublisher` | `YARA_RULE_ADDED`, `YARA_RULE_DELETED`, `YARA_RULE_UPDATED` |

**Consumers in TraceTree:**

| Consumer | Listens to | Effect |
|----------|------------|--------|
| `LiveTabConsumer` | `SampleEventPublisher`, all types | Pushes SSE to frontend Live tab |
| `DashboardConsumer` | `SAMPLE_VERDICT_READY` | Increments counters, updates chart data |
| `AlertConsumer` | `SAMPLE_VERDICT_READY` | Triggers notification if malicious |

**Integration with FastAPI:** `TraceEventBus` lives as an app-level singleton.
`LiveTabConsumer` wraps an `asyncio.Queue` that feeds an SSE endpoint. The Legs
pipeline calls `bus.publish(legs_publisher, TraceEvent("legs", "LEGS_STAGE_COMPLETE",
{"stage": 2, "confidence": 0.73}))` after each stage — the Live tab shows real-time
progress without polling.

**ZAP's sync-dispatch lesson applies:** TraceTree is single-user, so synchronous
dispatch on the analysis thread is fine. Only `LiveTabConsumer` needs async bridging
(via `asyncio.Queue`) since it crosses thread boundary to the event loop.

---

## Subsystem 4: Session / Context / Model

### ZAP pattern

**Problem:** A piece of traffic (`HttpMessage`) needs to accumulate associated
metadata over time without mutating its raw bytes: alerts fired against it,
tags added by rules, notes added by the analyst, retests, custom context data
contributed by different extensions.

**`HistoryReference`** — the universal artifact handle:
- `historyId` (int, PK in `TableHistory`)
- `sessionId` (long)
- `histType` (int — TYPE_PROXIED=1, TYPE_ZAP_USER=15, TYPE_SPIDER=2, etc.)
- `HttpMessage` (lazy-loaded from DB, cached in memory)
- `Set<Alert>` (derived, from `TableAlert` where `sourceHistoryId = this.historyId`)
- `tags` (Map<String, String>)
- `note` (String)

`HistoryReference` is a **handle, not a copy**. It holds an ID and loads content
from DB on first access. Alerts accumulate in `TableAlert` pointing back to the ID.

**`SiteMap`** — tree of `SiteNode`s (indexed by URL) where each `SiteNode` holds
`List<HistoryReference>`. The same URL can have many history entries from different
scanner runs. Extensions implement `SiteMapListener` to react to tree changes.

**`Context`** — a named scope (e.g. "in-scope URLs") that can be attached to
`HistoryReference`s. Extensions contribute `ContextDataFactory` to associate their
own data with a context. Context persists to session XML.

**`Session`** — owns the `SiteMap`, current mode, exclusion patterns, scope
definitions. `SessionChangedListener` (registered via `ExtensionHook`) notifies
extensions when a session opens/closes.

**`Model`** (singleton) — owns `Session`, `OptionsParam`, and `Database` handle.
All extensions get `Model` via `initModel()` — single point of access to shared state.

**Key insight:** `HistoryReference` separates the **identity** of an artifact
(its ID) from the **accumulation** of findings (alerts table), **annotations**
(tags, notes), and **derived views** (SiteNode placement). Re-running a scanner
against the same `historyId` just writes new `RecordAlert` rows — the original
`RecordHistory` bytes never change.

### TraceTree translation

**Equivalent problem:** TraceTree's Evidence view needs to show a sample alongside
all findings generated against it: YARA hits from run 1, Legs verdict from run 1,
RF confidence from run 1, then the same for run 2 after a model update. Currently
there's no model for a sample accumulating multiple analysis runs over time.

**Proposed pattern — `SampleReference`:**

```python
@dataclass
class SampleReference:
    sample_id: str            # PK in samples table (SHA256 or UUID)
    submitted_at: datetime
    sample_type: SampleType   # PE/ELF/SCRIPT/PCAP/etc.
    _raw: bytes | None = None # lazy-loaded

    # Derived from findings table — never mutated directly
    @property
    def findings(self) -> list[AnalysisFinding]:
        return store.get_findings(self.sample_id)

    @property
    def tags(self) -> list[str]: ...

    @property
    def notes(self) -> str: ...
```

**`SampleStore` — parallels `Model`:**

```python
class SampleStore:
    def get_sample(self, sample_id: str) -> SampleReference: ...
    def get_findings(self, sample_id: str) -> list[AnalysisFinding]: ...
    def write_finding(self, finding: AnalysisFinding) -> None: ...
    def add_tag(self, sample_id: str, tag: str) -> None: ...
    def set_note(self, sample_id: str, note: str) -> None: ...
```

**Two-table split:**
- `samples` table (raw): `sample_id`, `submitted_at`, `file_bytes`, `file_name`
- `analysis_findings` table (derived): `finding_id`, `sample_id`, `analyzer_name`,
  `verdict`, `confidence`, `evidence_json`, `model_version`, `run_at`

Re-running a sample through a new model version appends new rows to
`analysis_findings`. The Evidence view shows all rows grouped by `run_at` +
`model_version`. The original `samples` row is never touched.

**Evidence view query:**

```sql
SELECT f.*, s.file_name
FROM analysis_findings f
JOIN samples s ON s.sample_id = f.sample_id
WHERE f.sample_id = ?
ORDER BY f.run_at DESC, f.analyzer_name
```

**What changes in TraceTree:**
- `SampleReference` replaces the current flat dict/ORM object
- History view groups by `sample_id`, shows verdict timeline across runs
- "Re-analyze" button submits same `sample_id` to `SampleAnalysisController`;
  new findings appear in Evidence view alongside old ones
- Model version field in `AnalysisFinding` makes regressions visible

---

## Subsystem 5: Database Layer

### ZAP pattern

**Problem:** ZAP needs to persist raw traffic and derived findings (alerts)
independently. Raw traffic bytes and derived alert records have different lifecycles:
raw records are write-once, alerts can be deleted, updated, suppressed, or
regenerated by re-scanning.

**`TableHistory` interface:**

```java
RecordHistory read(int historyId)
RecordHistory write(long sessionId, int histType, HttpMessage msg)
List<Integer> getHistoryIds(long sessionId)
List<Integer> getHistoryIdsOfHistType(long sessionId, int... histType)
void delete(int historyId)
void deleteHistorySession(long sessionId)
```

**`RecordHistory`** fields: `historyId`, `sessionId`, `historyType`, `HttpMessage`
(raw bytes: `reqHeader`, `reqBody`, `resHeader`, `resBody`).

**`TableAlert` interface:**

```java
RecordAlert read(int alertId)
int write(int scanId, int pluginId, String alert, int risk, int confidence,
          String description, String uri, ..., int historyId, int sourceHistoryId)
List<Integer> getAlertsBySourceHistoryId(int historyId)
void deleteAlert(int alertId)
void deleteAllAlerts()
```

**`RecordAlert`** fields: `alertId`, `scanId`, `pluginId`, `risk` (0-3),
`confidence` (0-3), `description`, `uri`, `historyId` (the full message),
`sourceHistoryId` (the original record that triggered the finding), `evidence`,
`inputVector`, `cweId`, `wascId`, `alertRef`.

**Critical split:** `historyId` vs `sourceHistoryId`. A scanner may send a new
request to probe a vulnerability — that probe goes in `TableHistory` as its own
`RecordHistory`. But the alert's `sourceHistoryId` points back to the original
traffic record that revealed the vuln. Evidence chains never break.

**Database interface layer:** `TableHistory` and `TableAlert` are Java interfaces.
The default impl uses HSQLDB. In theory, a different impl could use SQLite or
PostgreSQL — extensions just call the interface, not the impl. Extensions get
notified via `databaseOpen(Database db)` on `ExtensionAdaptor` when the DB is ready.

### TraceTree translation

**Equivalent problem:** TraceTree currently conflates raw sample data with verdict
data in the same ORM model. Re-running a sample after a model update risks
overwriting the original verdict, losing the baseline for comparison.

**Proposed two-table schema:**

```sql
-- Table 1: raw sample data (write-once after initial submission)
CREATE TABLE samples (
    sample_id     TEXT PRIMARY KEY,  -- SHA256 of file bytes
    submitted_at  TIMESTAMP NOT NULL,
    file_name     TEXT,
    file_size     INTEGER,
    file_bytes    BLOB,              -- stored once, never updated
    sample_type   TEXT              -- PE/ELF/SCRIPT/PCAP/UNKNOWN
);

-- Table 2: derived findings (append-only per analysis run)
CREATE TABLE analysis_findings (
    finding_id      TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    sample_id       TEXT NOT NULL REFERENCES samples(sample_id),
    source_sample_id TEXT,          -- if this finding triggered a secondary analysis,
                                    -- original sample_id (parallels sourceHistoryId)
    analyzer_name   TEXT NOT NULL,  -- 'yara_pack', 'legs_stage1', 'rf_classifier', etc.
    verdict         TEXT NOT NULL,  -- 'MALICIOUS'/'BENIGN'/'UNCERTAIN'
    confidence      REAL NOT NULL,
    evidence_json   TEXT,           -- YARA hits, syscall patterns, feature importances
    model_version   TEXT,           -- 'rf-v2.1', 'legs-gpt4o-2025-07', etc.
    run_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tags            TEXT            -- JSON array
);

CREATE INDEX idx_findings_sample ON analysis_findings(sample_id, run_at DESC);
CREATE INDEX idx_findings_model ON analysis_findings(model_version);
```

**`SampleStore` interface (parallels ZAP's `TableHistory`):**

```python
class SampleStore(Protocol):
    def write_sample(self, sample: RawSample) -> str: ...         # returns sample_id
    def read_sample(self, sample_id: str) -> RawSample | None: ...
    def write_finding(self, finding: AnalysisFinding) -> str: ... # returns finding_id
    def get_findings(self, sample_id: str) -> list[AnalysisFinding]: ...
    def get_finding(self, finding_id: str) -> AnalysisFinding | None: ...
    def delete_finding(self, finding_id: str) -> None: ...
    def delete_sample(self, sample_id: str) -> None: ...          # cascades
```

**What changes in TraceTree:**
- `verdict DB` (current single-table approach) → `samples` + `analysis_findings`
- `api/main.py` triage endpoint: after full Legs+RF pipeline, write one
  `AnalysisFinding` per analyzer stage — don't overwrite any prior findings
- History view: group by `sample_id`, show finding timeline
- Evidence view: JOIN both tables on `sample_id`, display all findings from all runs
- "Compare model versions" feature becomes trivial: `WHERE model_version IN ('v1','v2')`

---

## Subsystem 6: REST / JSON API

### ZAP pattern

**Problem:** ZAP's REST API needs to expose endpoints contributed by 50+ extensions
without a central router file that every extension must edit.

**`ApiImplementor` abstract class:**

```java
// Each instance owns its namespace:
abstract String getPrefix()  // e.g. "pscan", "ascan", "core"

// Three endpoint types:
List<ApiAction> getApiActions()  // POST — side effects (start scan, clear alerts)
List<ApiView>   getApiViews()    // GET  — read data (get alerts, get scan status)
List<ApiOther>  getApiOthers()   // GET  — raw/binary responses (report download)

// Route handlers:
ApiResponse handleApiAction(String name, JSONObject params) throws ApiException
ApiResponse handleApiView(String name, JSONObject params) throws ApiException
IApiResponse handleApiOther(HttpMessage msg, boolean isAdmin) throws ApiException

// Optional: auto-generate option getters/setters from AbstractParam
void addApiOptions(AbstractParam param)
```

**`API` singleton routes `GET /JSON/{prefix}/view/{name}/` → `ApiImplementor`.**

**Registration:** extensions call `hook.addApiImplementor(impl)` in their `hook()`
method. `ExtensionLoader` iterates all hooks at startup and calls
`API.getInstance().addApiImplementor(impl)` for each. No central router file exists.
Each `ApiImplementor` fully owns its URL namespace.

**`ApiAction` / `ApiView` / `ApiOther`** carry: `name`, `List<ApiParameter>`
(mandatory/optional), description strings. The `API` class validates parameters
before calling the handler — implementations don't need to validate presence of
mandatory params.

**Notable pattern:** `ApiView` = read-only query (maps to HTTP GET with no side
effects). `ApiAction` = mutation (maps to POST-only). This enforces REST semantics
at the framework level, not per-implementor.

### TraceTree translation

**Equivalent problem:** TraceTree's `api/main.py` is a monolithic FastAPI router.
Adding a new analyzer plugin requires editing `main.py` to add its endpoints. As
TraceTree grows (CI integration, plugin ecosystem, remote submissions), this becomes
a bottleneck.

**Proposed pattern — `APINamespace`:**

```python
class APINamespace(ABC):
    @property
    @abstractmethod
    def prefix(self) -> str:
        """URL prefix: /api/{prefix}/..."""

    @abstractmethod
    def get_router(self) -> APIRouter:
        """Return a FastAPI APIRouter with all routes for this namespace."""

    def get_views(self) -> list[APIView]: ...    # GET endpoints (read-only)
    def get_actions(self) -> list[APIAction]: ... # POST endpoints (mutations)
```

**`APIRegistry`** — parallels ZAP's `API` singleton:

```python
class APIRegistry:
    _namespaces: dict[str, APINamespace] = {}

    def register(self, namespace: APINamespace) -> None:
        self._namespaces[namespace.prefix] = namespace

    def build_app(self, app: FastAPI) -> None:
        for ns in self._namespaces.values():
            app.include_router(ns.get_router(), prefix=f"/api/{ns.prefix}")
```

**`PluginLoader` wires it** — after calling `plugin.hook(hook)`, reads
`hook.api_namespaces` and calls `registry.register(ns)` for each.

**Concrete namespaces from existing TraceTree features:**

```
/api/samples/     — SamplesNamespace: submit, get, delete, list
/api/triage/      — TriageNamespace: start analysis, get status, get findings
/api/signatures/  — SignaturesNamespace: CRUD for YARA rules
/api/models/      — ModelsNamespace: list model versions, set active
/api/history/     — HistoryNamespace: query by sample, by verdict, by date
```

**What changes in TraceTree:**
- `api/main.py` becomes a thin orchestrator: `registry.build_app(app)` only
- Each subsystem owns its router — `SignaturesNamespace` in `plugins/builtin/yara_pack_plugin.py`
- CI integration (`/api/ci/submit`, `/api/ci/poll`) = a new `CINamespace` plugin
- No existing routes break — just reorganized into namespaces

---

## Priority Recommendation

TraceTree is single-user and local today. Not multi-tenant, not yet API-driven.
Priority by impact-vs-cost for current state:

### Priority 1: DB Layer split (Subsystem 5)

**Do this first.** Purely a data model change. No new abstractions, no framework.
Split the verdict table into `samples` (raw, write-once) and `analysis_findings`
(derived, append). Cost: ~1 day of migration + ORM update. Payoff: model retraining
becomes safe, Evidence view becomes accurate, History view becomes meaningful.
Every other subsystem builds on this.

### Priority 2: Event Bus (Subsystem 3)

**Do second.** Eliminates DB polling for Live tab. `SimpleEventBus` is ~80 lines —
copy the pattern, not the Java. Add `asyncio.Queue` bridge for FastAPI SSE. Cost:
~1 day. Payoff: Live tab works without polling, Legs pipeline progress visible in
real time, Dashboard auto-updates on verdict.

### Priority 3: Passive Scan pattern → SampleAnalyzer (Subsystem 2)

**Do third.** Refactor Legs + RF into `SampleAnalyzer` chain with `AnalyzerActions`
side-channel. Each stage becomes independently observable. Cost: ~2-3 days (touching
the core pipeline). Payoff: per-stage enable/disable, per-stage confidence threshold,
stage progress events feed into EventBus.

### Priority 4: Session/Context model → SampleReference (Subsystem 4)

**Follows naturally from Priority 1 and 3.** Once DB is split and analyzers emit
structured `AnalysisFinding`, `SampleReference` is just a query facade over those
tables. Cost: ~1 day once DB split is done.

### Priority 5: Extension/Plugin Loader (Subsystem 1)

**Hold until the above 4 are stable.** `AnalyzerPlugin` contract is most valuable
when there are community plugins to load. For now, the builtin analyzers (YARA, Legs,
RF) can just be classes that conform to `SampleAnalyzer` without a full plugin loader.
Implement `PluginLoader` when the first external plugin materializes.

### Priority 6: Distributed API Namespaces (Subsystem 6)

**Last.** Current `main.py` works. Reorganize into `APINamespace`s when adding a CI
integration endpoint or the plugin count exceeds ~5. Premature for today.

---

## What NOT to borrow from ZAP

- **`ProxyListener` / intercept pattern** — nothing to intercept in TraceTree
- **`OverrideMessageProxyListener`** — mutation of traffic; no analog
- **`SiteMap` tree structure** — URL hierarchy; TraceTree has no URL tree
- **Hot-load/unload of plugins at runtime** — `canUnload()` complexity not needed
  for a local tool; restart is acceptable
- **`AddOnLoader` + `.zap` file format** — for TraceTree, a plain Python module
  in `plugins/` discovered by importlib is sufficient
- **`Authentication` / `Session` management subsystems** — no target application
  to authenticate against
- **Multi-session management** — ZAP supports multiple saved sessions; TraceTree
  has no session concept (all samples are always visible)
