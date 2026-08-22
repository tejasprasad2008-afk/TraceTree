# TraceTree Workbench UI — Implementation Prompt for Codex

You are building the primary dashboard UI for **TraceTree**, a runtime behavioral
security scanner. This document is the complete design specification. Follow it
exactly. Where this document is silent, default to the plainest, densest,
most conservative option available — never the more decorative one.

---

## 1. Design North Star

TraceTree's UI must look like a professional security/engineering workbench in
the lineage of **Burp Suite, Caido, Wireshark, DaVinci Resolve, and IDEs** —
a tool an enterprise analyst uses 6 hours a day. It must look like it was
designed by engineers around 2015 and has been maintained, not redesigned,
since. Dense, quiet, scannable, keyboard-friendly.

**The one memorable detail:** verdicts and severity are communicated through
small, solid, rectangular colored tags and colored table-row text — exactly like
Burp's Issues panel — never through banners, cards, badges with rounded
corners, or animation.

### Hard prohibitions (violating any of these fails review)

- NO `border-radius` anywhere. Every corner is square. `border-radius: 0` globally.
- NO glassmorphism, backdrop blur, or translucent panels.
- NO gradients of any kind (backgrounds, buttons, text).
- NO drop shadows. Depth is expressed with 1px borders only.
- NO pulsating/glowing/breathing animations. No `animate-pulse`, no glow rings.
- NO purple/violet as an accent. No multi-color gradient accents.
- NO oversized typography. Max font size in the entire app: 15px (see scale).
- NO hero sections, marketing copy, empty-state illustrations, or mascots
  inside the tool. Empty states are one line of gray text.
- NO emoji anywhere in the UI. Severity is text + color.
- NO toggle switches. Use square checkboxes.
- NO cards inside cards. Panels are flat bordered regions; content sits
  directly inside them.
- NO framer-motion, no entrance/stagger animations, no page transitions.
- NO skeleton shimmer loaders. Loading = text like `loading…` or a thin
  determinate progress bar.
- NO component library default styling (no stock shadcn/MUI look). If a
  library is used, its radius, shadows, and rings must be stripped to zero.
- NO rounded avatars, pill buttons, or floating action buttons.

---

## 2. Design Tokens

Implement as CSS variables in `globals.css` AND mirror them in
`tailwind.config.ts` as theme extensions. All colors below are final — do not
"improve" them.

```css
:root {
  /* Surfaces — flat dark grays, slightly warm, DaVinci/Caido territory */
  --bg-app:        #1b1c1e;  /* window background */
  --bg-panel:      #232427;  /* panel/table background */
  --bg-panel-alt:  #28292d;  /* table header rows, toolbars */
  --bg-inset:      #161719;  /* raw log/code wells, deepest inset */
  --bg-hover:      #2e3034;  /* row/button hover */
  --bg-selected:   #14324f;  /* selected table row (muted steel blue) */

  /* Borders — 1px solid everywhere, no shadows */
  --border:        #3a3c40;
  --border-strong: #4a4d52;

  /* Text */
  --text-primary:  #d6d7d9;
  --text-muted:    #8b8e94;
  --text-disabled: #5c5f66;

  /* Single accent — Burp-style amber/orange. Used ONLY for: active tab
     underline, focused control border, primary button, live-status dot. */
  --accent:        #d78a2e;
  --accent-text:   #1b1c1e; /* text on accent backgrounds */

  /* Severity — the semantic core of the app */
  --sev-danger:    #c94f4f;
  --sev-caution:   #cfa53f;
  --sev-safe:      #58a05e;
  --sev-info:      #5187b8;

  /* On-dark severity text variants (for coloring row text, Burp-style) */
  --sev-danger-text:  #e07575;
  --sev-caution-text: #dcbc6a;
  --sev-safe-text:    #7dbb82;
}
```

### Typography

```css
--font-ui:   -apple-system, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
--font-mono: "SF Mono", "Consolas", "Roboto Mono", "Liberation Mono", monospace;
```

Scale (there are exactly five sizes — use no others):

| Token | Size | Use |
|---|---|---|
| `text-2xs` | 10px, uppercase, letter-spacing 0.06em | severity tags, table headers, sidebar section labels |
| `text-xs`  | 11px | status bar, secondary metadata, filter summaries |
| `text-sm`  | 12px | table cells, form controls, sidebar items — the workhorse size |
| `text-base`| 13px | panel titles, tab labels, body text |
| `text-lg`  | 15px, weight 600 | screen title only (one per screen, top-left) |

All paths, hashes, syscalls, hostnames, ports, log excerpts: `--font-mono`.
Everything else: `--font-ui`. Line-height 1.35 globally. Font-weight 400
default, 600 for emphasis; never 700+.

### Spacing & sizing

4px base grid. Density targets:
- Table row height: **24px**. Cell padding: 3px 8px.
- Button height: **24px**, padding 0 10px.
- Input height: **24px**.
- Sidebar row height: **26px**.
- Panel header height: **28px**.
- Toolbar height: **32px**.
- Tab height: **30px**.
- Status bar height: **22px**.
- Panel padding: 8px. Never more than 12px of padding anywhere.

---

## 3. Application Shell

Fixed layout, desktop-first (min supported width 1200px; below that, panels
get horizontal scroll — do NOT build a mobile layout).

```
┌──────────────────────────────────────────────────────────────────────┐
│ TITLE BAR (32px): "TraceTree" left · global search center ·          │
│ Docker status + watcher status right                                  │
├──────────────────────────────────────────────────────────────────────┤
│ TAB STRIP (30px): Dashboard│Live Monitor│Scan History│Evidence│       │
│ Signatures│Settings                                                   │
├────────────┬─────────────────────────────────────────────────────────┤
│ SIDEBAR    │ MAIN CONTENT                                            │
│ (220px)    │ (split panes, 1px draggable dividers)                   │
│            │                                                          │
│ MONITOR    │                                                          │
│  Overview  │                                                          │
│  Watched…  │                                                          │
│  Queue     │                                                          │
│ ANALYSIS   │                                                          │
│  Findings  │                                                          │
│  Network   │                                                          │
│  Graph     │                                                          │
│ LOGGING    │                                                          │
│  Raw logs  │                                                          │
│  Exports   │                                                          │
├────────────┴─────────────────────────────────────────────────────────┤
│ STATUS BAR (22px): v0.x · watcher: ACTIVE · docker: CONNECTED ·       │
│ queue: 2 · events: 14,203                                             │
└──────────────────────────────────────────────────────────────────────┘
```

### Title bar
- Background `--bg-panel-alt`, bottom border `--border`.
- App name: 13px, weight 600, `--text-primary`. No logo image required; a
  16px monochrome glyph is acceptable.
- Right side: two status indicators, each = 8px square (not circle) colored
  dot + 11px label. `DOCKER: CONNECTED` (safe green) / `DOCKER: NOT RUNNING`
  (danger red, and the label is a click target opening the Docker help
  dialog). `WATCHER: ACTIVE` / `PAUSED`.
- The status dot for ACTIVE may blink between full and 40% opacity at a slow
  1.5s step interval (steps(2), not eased fade) — this is the ONLY blinking
  element permitted in the app, mirroring Caido's Intercept dot.

### Tab strip (Burp-style)
- Square tabs, 30px tall, 13px labels, padding 0 14px.
- Inactive: background transparent, text `--text-muted`, 1px right border.
- Hover: `--bg-hover`.
- Active: background `--bg-panel`, text `--text-primary`, and a **2px solid
  `--accent` border on the TOP edge only**. No underline animation — state
  changes instantly.

### Sidebar (Caido-style)
- Background `--bg-app`, right border `--border`.
- Section labels: `text-2xs`, `--text-muted`, padding 10px 12px 4px.
- Items: 26px rows, 12px text, 16px monochrome icon (lucide-react with
  `strokeWidth={1.75}`, color inherits text) + label, padding-left 12px.
- Active item: full-row `--bg-selected` background, text `--text-primary`.
  No left-border accent strip, no radius.
- Collapse control at bottom: `« Collapse` text button.

### Status bar
- Background `--bg-panel-alt`, top border `--border`, 11px `--text-muted`,
  segments separated by ` · ` or 1px vertical dividers.

---

## 4. Core Components

Build these as shared components FIRST (`components/workbench/`). Every screen
composes them. Do not restyle per-screen.

### 4.1 `DataTable`
The single most important component. Reference: Burp's HTTP history / Caido's
proxy table.

- Header row: `--bg-panel-alt`, `text-2xs` uppercase `--text-muted`, sortable
  columns show `▲`/`▼` text glyph after the label. 1px bottom border
  `--border-strong`.
- Body rows: 24px, zebra striping (`--bg-panel` / `#212226` alternating).
- Hover: `--bg-hover`. Selected: `--bg-selected` full row.
- Severity-colored rows: when a row has a verdict, its TEXT color shifts to
  the matching `--sev-*-text` variant (Burp colors issue rows this way);
  background stays normal.
- Monospace columns: hash, path, syscall, host, port.
- Column resizing via drag handles on header dividers (can use
  `@tanstack/react-table` — strip all default styling).
- Keyboard: up/down arrows move selection, Enter opens detail.
- Right-click: native-feeling context menu (flat panel, 1px
  `--border-strong` outline as the only elevation cue, 24px items, no
  radius/shadow): `Open detail`, `Copy path`, `Copy SHA-256`, `Re-scan`,
  `Reveal in Finder/Explorer`.
- Empty state: single centered line, 12px `--text-muted`:
  `No scans recorded. Files appearing in watched folders will be analyzed automatically.`

### 4.2 `SeverityTag`
Rectangular, solid-fill tag: `text-2xs` uppercase, 3px 6px padding,
white/near-black text on solid severity color. Exactly these four:

| Tag | Fill | Text |
|---|---|---|
| `DANGER` | `--sev-danger` | `#fff` |
| `CAUTION` | `--sev-caution` | `#1b1c1e` |
| `SAFE` | `--sev-safe` | `#fff` |
| `PENDING` | `--bg-hover` | `--text-muted` |

### 4.3 `Panel`
Flat region: `--bg-panel` background, 1px `--border` border. Header: 28px,
`--bg-panel-alt`, 13px weight-600 title left, optional small text-button
actions right, 1px bottom border. No padding tricks, no shadow, no radius.

### 4.4 `SplitPane`
Resizable horizontal/vertical splits with a 5px hit-area divider rendering as
a 1px `--border-strong` line; cursor `col-resize`/`row-resize`. Persist sizes
to localStorage.

### 4.5 `FilterBar` (Burp signature element)
A full-width 26px strip above tables, background `--bg-panel-alt`, 11px
`--text-muted` text summarizing active filters as a sentence:
`Filter: hiding clean scans; hiding archives; showing last 7 days`
Clicking it opens a flat dropdown panel of square checkboxes. This element is
what makes it read as Burp — implement it faithfully.

### 4.6 Buttons & inputs
- Default button: `--bg-hover` fill, 1px `--border-strong` border, 12px text.
  Hover lightens fill one step. Active state: fill darkens (pressed look via
  color only, no transform/shadow).
- Primary button (max one per view): `--accent` fill, `--accent-text` text.
- Text inputs/selects: `--bg-inset` fill, 1px `--border` border; focus =
  border becomes `--accent`, no glow/ring.
- Checkboxes: 13px square, custom-drawn, `--accent` check when checked.
- Transitions: `background-color 100ms linear` ONLY. Nothing else animates.

### 4.7 `RawWell`
Scrollable monospace log viewer: `--bg-inset` background, 12px mono, 1.5
line-height, optional line numbers in `--text-disabled`. Used for strace
excerpts. Syntax accents allowed: syscall names in `--sev-info`, flagged
lines in `--sev-danger-text`. Reference: Burp's Raw request pane.

---

## 5. Screens

### 5.1 Dashboard (default tab)
Purpose: at-a-glance protection state + recent activity. NOT a marketing page.

Layout top→bottom:
1. **Status strip** (not a hero): full-width Panel, 40px content row:
   left — `Protection active — watching ~/Downloads` (13px) with the square
   status dot; right — `Pause watching` default button. If Docker is down,
   a second 28px row appears inside the same panel: danger-red text
   `Deep scanning unavailable — Docker is not running.` + `Open Docker Desktop`
   button. This is a bordered row, not a toast, not a floating banner.
2. **Stat tiles**: 4 flat Panels in a row (equal width, 8px gap):
   `SCANS TODAY`, `THREATS BLOCKED`, `WATCHED FOLDERS`, `QUEUE`. Each: 10px
   uppercase muted label top, 15px weight-600 mono number below (respect the
   type scale; keeping numbers small is intentional density). No icons, no
   sparklines, no deltas.
3. **Recent scans**: full-width `DataTable`, columns:
   `Time · File · Type · SHA-256 (first 12 chars, mono) · Static · Dynamic · Confidence`.
   Static/Dynamic columns render `SeverityTag`s. Double-click / Enter →
   Evidence tab for that scan.

### 5.2 Live Monitor
Purpose: watch a scan happen. Master-detail, Burp Repeater energy.

- Top pane (40% height): **queue table** — all in-flight + recent scans.
  Columns: `ID · File · Stage · Static · Dynamic · Elapsed`. `Stage` cell
  shows plain text `sandbox → parser → ml → done` with the current stage in
  `--accent` (text color only; no spinner). A thin 2px determinate progress
  bar may run along the row's bottom edge in `--accent`.
- Bottom pane, split left/right:
  - Left (60%): **syscall event stream** DataTable, streaming via SSE:
    `# · Syscall · PID · Target · Severity`. Severity colors row text.
    Auto-scroll pinned to bottom with a `hold` text-button to pause.
  - Right (40%): **Inspector** — Panel with an inner square tab row
    (`Raw │ Parsed │ Network │ Triage`), same tab styling as the main strip
    but 24px tall. `Raw` = RawWell of strace excerpt for selected event.
    `Parsed` = key/value grid (11px labels, 12px mono values). `Network` =
    small table of connections. `Triage` = plain paragraphs (LLM output when
    available, else `No triage available.` muted line).

### 5.3 Scan History
- `FilterBar` on top.
- Full-height DataTable of every scan from SQLite: sortable, right-click menu,
  columns as Dashboard's table + `Duration` + `Threats` (count).
- Left 200px optional tree (Burp sitemap style) grouping scans by
  watched-folder → date, using text glyphs `▸`/`▾` for expand state; selecting
  a node filters the table.

### 5.4 Evidence (scan detail)
Three-region layout, the Burp "Target" composition:
- Left (220px): artifact tree — the scanned file, extracted payloads,
  strace logs, YARA hits as tree nodes.
- Right-top: **Findings table**: `Severity · Finding · Source · Location`.
  Severity column = SeverityTag; rows text-colored by severity. Source values:
  `YARA`, `SIGNATURE`, `HEURISTIC`, `ML`, `TEMPORAL`.
- Right-bottom: **Detail pane** for the selected finding: finding title
  (13px, 600), then an 11px key/value block
  (`Rule · Confidence · File · Line`), then RawWell with the matching
  evidence excerpt, flagged lines highlighted. ML findings MUST render the
  label `Behavioral anomaly score (experimental)` — never present ML output
  as a definitive verdict.

### 5.5 Signatures
Read-only browser of loaded YARA rules + behavioral signatures. Left: rule
list (DataTable: `Rule · Type · Hits`). Right: RawWell showing rule source.

### 5.6 Settings
Single scrolling form inside a Panel, max-width 640px, left-aligned:
- Rows: 160px right-aligned 12px label column, control column. Section
  dividers: 1px `--border` line + `text-2xs` section label.
- Sections: `WATCHED FOLDERS` (list + Add/Remove buttons + ignore-glob
  input), `SCANNING` (auto-scan checkbox, Docker timeout number input),
  `NOTIFICATIONS` (checkboxes), `ADVANCED` (API port, log level select).
- One primary `Apply` button bottom-left. No floating save bars.

---

## 6. Data Contracts

Backend is local FastAPI (`http://127.0.0.1:8000`). Wire against:

- `POST /scan/file {path}` → `{scan_id, static_verdict}`
- `GET /scans?limit=&offset=` → scan rows (SQLite-backed)
- `GET /scans/{id}` → full detail incl. findings, events, graph stats
- `GET /events` → SSE: `scan_started`, `static_verdict`, `stage_change`,
  `syscall_event`, `final_verdict`
- `GET /docker/status` → `{available, version}`

Verdict schema: `{level: "safe"|"caution"|"danger", headline, details[]}` —
maps 1:1 to SeverityTag. `PENDING` when dynamic stage not finished.

Use plain `fetch` + `EventSource`. State: Zustand or React context — no
Redux, no react-query unless already in package.json.

---

## 7. Build Order

1. Tokens: `globals.css` variables + tailwind config + global
   `* { border-radius: 0 !important; box-shadow: none !important; }` reset.
2. Shell: title bar, tab strip, sidebar, status bar, tab switching via
   client-side state (not Next routes, so Electron static export stays
   trivial).
3. `DataTable`, `SeverityTag`, `Panel`, `SplitPane`, `FilterBar`, `RawWell`,
   buttons/inputs.
4. Dashboard.
5. Live Monitor (SSE wiring).
6. Scan History + Evidence.
7. Settings, Signatures.

Existing `frontend/` code: keep the Next.js + Tailwind scaffolding,
`next.config.js`, and API URL plumbing. The Win95-styled components
(`Win95Card`, `BevelButton`, `MSDosPrompt`, marquee, hit counters) are being
RETIRED from the main app — do not import them into new screens. Do not
delete them (a demo route may still reference them); build the new UI as the
new default `app/page.tsx` experience.

## 8. Acceptance Checklist (self-review before finishing)

- Zero rounded corners visible at any zoom level.
- Zero shadows/gradients/blur in computed styles.
- Every font size ∈ {10, 11, 12, 13, 15}px.
- All hashes/paths/syscalls render in monospace.
- Table rows are 24px; the Dashboard shows ≥15 rows on a 1440×900 window
  without scrolling the page chrome.
- The only orange elements: active tab top-border, focused input border,
  primary button, stage-progress text/bar, live dot.
- The only animation: 100ms background hovers, the 1.5s stepped status-dot
  blink, determinate progress bars.
- App is fully navigable with keyboard on tables (arrows + Enter).
- Docker-down state renders as the bordered inline row, not a toast/modal.
- No emoji, no illustrations, no marketing copy anywhere in the tool.
