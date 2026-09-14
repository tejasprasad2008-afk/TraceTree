#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import json
from orchestrator.ai_mesh import AIMeshOrchestrator, AIConnectionRefusedError, AIBadResponseError

def main():
    print("==================================================")
    print("AI TRIAGE SIMULATION: BENIGN PAYLOAD TEST")
    print("==================================================")

    # 1. Instantiate the AI Mesh Orchestrator with verbose mode enabled
    # so we can see the prompt sent and response status code
    print("Initializing AIMeshOrchestrator...")
    orchestrator = AIMeshOrchestrator(verbose=True)

    # 2. Define a benign package telemetry payload
    # This represents a legitimate library making a standard query
    matched_rule = {
        "name": "network_connection_detected",
        "description": "Standard outbound socket connection on port 443",
        "severity": 6
    }
    
    package_metadata = {
        "name": "requests-simple-fetch",
        "type": "pip",
        "total_severity": 6.0,
        "description": "A benign utility designed to fetch content from public HTTPS endpoints.",
        "exception_rules": [
            "Allow connection to pypi.org on port 443",
            "Allow reading standard library system configurations"
        ]
    }

    print("\nBenign Triage Payload definition:")
    print("Matched Rule:", json.dumps(matched_rule, indent=2))
    print("Package Metadata:", json.dumps(package_metadata, indent=2))

    print("\nSending benign payload to AI false positive juror...")
    try:
        results = orchestrator.triage_false_positive(matched_rule, package_metadata)
        print("\n================== [AI TRIAGE RESULTS] ==================")
        print(json.dumps(results, indent=2))
        print("=========================================================")

        verdict = results.get("verdict", "SUSPICIOUS")
        if verdict == "FALSE_POSITIVE":
            print("\n[SUCCESS] AI Juror successfully classified the payload as FALSE_POSITIVE (BENIGN).")
            print("The system is fully capable of overriding paranoid false alerts when connection is successful!")
        else:
            print(f"\n[INFO] AI Juror returned verdict: {verdict}.")
            print("Reasoning: ", results.get("reasoning", "No reasoning provided"))
    except AIConnectionRefusedError as e:
        print(f"\n[FAILURE] AI Connection Refused: {e}")
        print("Ollama might be down or not running. Start it with 'ollama serve'.")
        sys.exit(1)
    except AIBadResponseError as e:
        print(f"\n[FAILURE] AI returned a bad response/invalid JSON: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[FAILURE] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
