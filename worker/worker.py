import time
import os
import sys
from pathlib import Path

# Add root directory to sys.path to allow importing project modules
sys.path.append(str(Path(__file__).parent.parent))

from monitor.parser import parse_strace_log
from graph.builder import build_cascade_graph
from ml.detector import detect_anomaly
from sandbox.sandbox import run_sandbox

def process_job(job_data):
    """
    Processes a single analysis job.
    """
    analysis_id = job_data["id"]
    package_name = job_data["package_name"]
    target_type = job_data.get("target_type", "pip")
    env_vars = job_data.get("env_vars")
    
    print(f"[*] Worker processing job {analysis_id} for {package_name}...")
    
    try:
        # 1. Sandbox Execution
        log_path = run_sandbox(package_name, target_type=target_type, env=env_vars)
        if not log_path:
            return {"id": analysis_id, "status": "failed", "error": "Sandbox failed to produce logs"}

        # 2. Parsing
        parsed = parse_strace_log(log_path)
        
        # 3. Graphing
        graph = build_cascade_graph(parsed)
        
        # 4. ML Detection
        is_malicious, confidence = detect_anomaly(graph, parsed)
        
        print(f"[+] Job {analysis_id} complete: {is_malicious} ({confidence}%)")
        
        return {
            "id": analysis_id,
            "status": "completed",
            "verdict": "MALICIOUS" if is_malicious else "CLEAN",
            "confidence_score": confidence,
            "graph": graph
        }
    except Exception as e:
        print(f"[-] Job {analysis_id} failed: {e}")
        return {"id": analysis_id, "status": "failed", "error": str(e)}

if __name__ == "__main__":
    # Placeholder for Redis worker loop
    # In a real implementation, this would use 'rq' or 'celery'
    print("[*] TraceTree Worker started. Waiting for jobs (Redis placeholder)...")
