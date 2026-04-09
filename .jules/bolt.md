# Bolt's Journal - TraceTree Performance

## 2025-04-09 - [Initial Assessment]
**Learning:** The ML detection pipeline reloads the model from disk on every single analysis. While the current model is small (53KB), the README indicates it can grow to ~100MB. Deserializing a large Random Forest model repeatedly during bulk analysis of dependencies is a significant bottleneck.
**Action:** Implement model caching in `ml/detector.py` to ensure the model is loaded only once per process.

## 2025-04-09 - [Strace Parsing Efficiency]
**Learning:** `monitor/parser.py` uses `line.strip()` on every line of the strace log. For multi-megabyte logs, the repeated string allocations can add up. Additionally, regexes inside the loop are not pre-compiled.
**Action:** Pre-compile regexes and use more efficient line processing if needed.
