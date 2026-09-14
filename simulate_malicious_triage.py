#!/usr/bin/env python3
import sys
import json
from orchestrator.ai_mesh import AIMeshOrchestrator, AIConnectionRefusedError, AIBadResponseError

def main():
    print("==================================================")
    print("AI TRIAGE SIMULATION: MALICIOUS PAYLOAD TEST")
    print("==================================================")

    # 1. Instantiate the AI Mesh Orchestrator with verbose mode enabled
    print("Initializing AIMeshOrchestrator...")
    orchestrator = AIMeshOrchestrator(verbose=True)

    # 2. Define the malicious package telemetry payload that was previously misclassified
    matched_rule = {
        "rule_name": "process_injection",
        "severity": 9.5
    }
    
    package_metadata = {
        "name": "d59a0308d2a3ba15b1f5f71269a3c0d4f673e9143414de954590504578b31910.zip",
        "type": "PIP",
        "total_severity": 23.5,
        "file_count": 2377
    }

    print("\nMalicious Triage Payload definition:")
    print("Matched Rule:", json.dumps(matched_rule, indent=2))
    print("Package Metadata:", json.dumps(package_metadata, indent=2))

    print("\nSending malicious payload to AI false positive juror...")
    try:
        results = orchestrator.triage_false_positive(matched_rule, package_metadata)
        print("\n================== [AI TRIAGE RESULTS] ==================")
        print(json.dumps(results, indent=2))
        print("=========================================================")

        verdict = results.get("verdict", "SUSPICIOUS")
        if verdict == "SUSPICIOUS":
            print("\n[SUCCESS] AI Juror correctly kept the verdict as SUSPICIOUS!")
            print("The system successfully blocked a false-positive override for the malicious file.")
        else:
            print("\n[FAILURE] AI Juror incorrectly classified the payload as FALSE_POSITIVE!")
            print("Reasoning: ", results.get("reasoning", "No reasoning provided"))
            sys.exit(1)
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
