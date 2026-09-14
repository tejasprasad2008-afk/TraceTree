import json
from monitor.parser import parse_strace_log
from monitor.signatures import match_signatures, load_signatures

log = "/Users/tejasprasad/TraceTree/.tracetree/history/session-2026-07-09T13-43-03Z-b7e24999/runtime.log"
parsed = parse_strace_log(log)
sigs = load_signatures()
matches = match_signatures(parsed, sigs)

print(json.dumps(matches, indent=2))
print("===")
for ev in parsed['events']:
    print(ev['type'], ev['target'])
