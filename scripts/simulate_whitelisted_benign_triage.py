#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import json
from orchestrator.ai_mesh import AIMeshOrchestrator, AIConnectionRefusedError, AIBadResponseError

def main():
    print("==================================================")
    print("AI TRIAGE SIMULATION: WHITELISTED BENIGN TEST")
    print("==================================================")

    print("Initializing AIMeshOrchestrator...")
    orchestrator = AIMeshOrchestrator(verbose=True)

    # Define a benign package manager action that triggers a typosquat_exfil alert
    # but should match the whitelisted exception for pip.
    matched_rule = {
        "rule_name": "typosquat_exfil",
        "severity": 6.0
    }
    
    package_metadata = {
        "name": "pip",
        "type": "PIP",
        "total_severity": 6.0,
        "file_count": 50
    }

    print("\nWhitelisted Benign Triage Payload definition:")
    print("Matched Rule:", json.dumps(matched_rule, indent=2))
    print("Package Metadata:", json.dumps(package_metadata, indent=2))

    print("\nSending payload to AI false positive juror...")
    try:
        results = orchestrator.triage_false_positive(matched_rule, package_metadata)
        print("\n================== [AI TRIAGE RESULTS] ==================")
        print(json.dumps(results, indent=2))
        print("=========================================================")

        verdict = results.get("verdict", "SUSPICIOUS")
        if verdict == "FALSE_POSITIVE":
            print("\n[SUCCESS] AI Juror correctly classified the whitelisted package action as FALSE_POSITIVE!")
        else:
            print(f"\n[INFO] AI Juror returned verdict: {verdict}.")
            print("Reasoning: ", results.get("reasoning", "No reasoning provided"))
    except Exception as e:
        print(f"\n[FAILURE] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
