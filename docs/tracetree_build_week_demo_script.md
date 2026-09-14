# TraceTree - Build Week Demo Script

**Target runtime:** 2 minutes 20 seconds to 2 minutes 40 seconds.  Do not include the optional material; leave margin for pauses and transitions.

**Recording rule:** Record the narration in the left column while showing the matching action in the right column.  Every scan shown must be a result you have reproduced on this machine with Docker running. Use only the included benign fixture and a controlled synthetic test fixture - do not run public malware during the recording.

| Time | Say this | Show this on screen |
|---|---|---|
| 0:00-0:14 | "Hi, I'm Tejas. This is TraceTree, a runtime behavioral security scanner. It runs supported targets in an isolated Docker sandbox, observes process, file, and network behavior, matches YARA and behavioral signatures, and then presents the evidence alongside a verdict." | Talking head. Optional: TraceTree logo or dashboard behind you. |
| 0:14-0:31 | "TraceTree existed before Build Week as a CLI-based analysis tool. For Build Week, I used Codex with GPT-5.6 to build TraceTree Workbench: a local dashboard that makes scans and their evidence much easier to run and review." | Briefly show the GitHub branch/PR timeline, then open the Workbench dashboard. Do not linger on GitHub. |
| 0:31-0:52 | "The Workbench brings together a command console, live activity, scan history, evidence, signatures, and service settings. Instead of treating a verdict as a black box, it makes the evidence and the running services visible to the person reviewing a scan." | Slowly pan across Dashboard, Live, History, Evidence, Signatures, and Settings. Pause on the command console and the recent-activity table. |
| 0:52-1:12 | "Here is a verified run on a known benign test fixture. The point is not that every text file is automatically safe: TraceTree shows the evidence it observed, so a reviewer can distinguish a clean result from a weak or unsupported signal." | Use the Command Console and show a **previously verified** benign run. Show the final result, its evidence, and the history row. If the live run is slow, use an edited clip of the completed local run. |
| 1:12-1:33 | "And here is a controlled synthetic malicious fixture. It models suspicious behavior such as sensitive-file access followed by a network connection. TraceTree surfaces the behavior and the reason for the higher-risk verdict - it is not presenting a magic label without context." | Show a **previously verified** synthetic-fixture run, then Evidence. Highlight the relevant signature/YARA/evidence lines and the verdict. Never use live malware or a download link in the video. |
| 1:33-2:00 | "Codex also helped me trace a real contract problem across the analysis pipeline. High-confidence malicious results could be stored or rendered with inconsistent severity words, which could make a danger-level result look like a caution. I traced the contract through the Python behavior receipt, the TypeScript telemetry server, and the scan-history store, then made all three use the same clean, suspicious, or malicious decision." | Show the focused three-file diff: `orchestrator/ai_mesh.py`, `orchestrator/src/server.ts`, and `orchestrator/src/store/index.ts`. Highlight the shared tri-state decision. Then show a dashboard history row with the matching danger/caution/safe presentation. |
| 2:00-2:17 | "Under the hood, the dashboard is Next.js and React; it talks to a FastAPI gateway and the local TypeScript orchestrator. TraceTree uses Docker and strace for behavioral observation, NetworkX for graphing, YARA for signature matching, and a small ML component for final triage." | Show the Settings view with service status, then a quick repository-folder or architecture view. Keep it moving. |
| 2:17-2:34 | "I used Codex and GPT-5.6 to design and implement the Workbench, connect it to the existing pipeline, and verify the verdict contract across the boundary between the Python and TypeScript services. The README explains how to install it and reproduce the dashboard locally. Thanks for watching." | Return to the dashboard, then talking head for the final sentence. |

## Before recording

1. Push the current verdict-contract commit to `codex/dashboard-hackathon`; it is currently local-only and must be on the branch judges can see.
2. Update the README before recording so it accurately identifies the Build Week Workbench work, the role of Codex/GPT-5.6, setup instructions, and the testing path.
3. Start Docker Desktop and confirm `docker info` succeeds. Start the dashboard with `cascade-analyze dashboard` and confirm the API, Workbench, and orchestrator are reachable.
4. Reproduce both screen-recorded scans first. If either result does not match the narration, change the narration to match the result; do not force a clean or malicious claim.
5. Use the exact Codex model name only if it is visible in the session you will submit. Replace "GPT-5.6" above if your actual session records a different model.
6. Keep the final exported video below 3:00, public on YouTube, and show only controlled local fixtures.

## Editing notes

- Cut Docker startup, dependency installation, typing, empty loading states, and long scan waits.
- Put the benign and synthetic-fixture recordings into short inserted clips if live scans take too long.
- Do not mention `graph.html`, an always-on desktop monitor, or a fully pluggable analyzer orchestrator: they are not part of the submitted, reproducible dashboard path.
- Do not call the repository public if it remains private; say that it is shared with the required judges instead.
