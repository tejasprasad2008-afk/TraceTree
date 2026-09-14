#!/usr/bin/env python3
import time
import requests
import json
import sys

OLLAMA_HOST = "http://localhost:11434"
MODEL_NAME = "qwen2.5-coder:7b"

def main():
    print("==================================================")
    print("OLLAMA MODEL ROUND-TRIP DIAGNOSTIC TEST")
    print("==================================================")
    
    # 1. Connection check
    tags_url = f"{OLLAMA_HOST}/api/tags"
    print(f"Connecting to Ollama health check: {tags_url}...")
    start_time = time.time()
    try:
        response = requests.get(tags_url, timeout=5)
        conn_time = time.time() - start_time
        if response.status_code == 200:
            print(f"✔ Connection successful! Status code: 200")
            print(f"✔ Ping response time: {conn_time:.4f} seconds")
        else:
            print(f"❌ Connection check failed with status: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"❌ CONNECTION_ERROR: Failed to connect to Ollama at {OLLAMA_HOST}.")
        print(f"Details: {e}")
        print("Please ensure 'ollama serve' is running.")
        sys.exit(1)

    # 2. Check model presence
    try:
        models = [m["name"] for m in response.json().get("models", [])]
        if MODEL_NAME in models or f"{MODEL_NAME}:latest" in models:
            print(f"✔ Model '{MODEL_NAME}' is loaded and available locally.")
        else:
            print(f"⚠ Model '{MODEL_NAME}' is NOT found in pulled models list.")
            print(f"Available models: {models}")
            print(f"Please run: ollama pull {MODEL_NAME}")
            sys.exit(1)
    except Exception as e:
        print(f"❌ Failed to parse models: {e}")
        sys.exit(1)

    # 3. Test prompt round-trip
    generate_url = f"{OLLAMA_HOST}/api/generate"
    test_payload = {
        "model": MODEL_NAME,
        "prompt": "Say hello and nothing else.",
        "stream": False,
        "options": {
            "temperature": 0.0,
            "num_predict": 10
        }
    }
    print(f"\nSending test prompt to model '{MODEL_NAME}'...")
    start_time = time.time()
    try:
        res = requests.post(generate_url, json=test_payload, timeout=60)
        duration = time.time() - start_time
        if res.status_code == 200:
            print(f"✔ Response received in {duration:.2f} seconds!")
            print(f"Raw Output: {res.json().get('response', '').strip()}")
            
            # Evaluate timeouts
            if duration < 15.0:
                print("✔ Response time is within the MCP 15s execution timeout.")
            elif duration < 60.0:
                print("⚠ Response time is within the 60s cascade-analyze timeout, but exceeds 15s MCP threshold.")
            else:
                print("❌ Response time is extremely slow and will trigger timeouts.")
        else:
            print(f"❌ Ollama returned status: {res.status_code}")
            print(res.text)
    except requests.exceptions.Timeout:
        print("❌ TIMEOUT: Ollama took more than 60 seconds to respond.")
    except Exception as e:
        print(f"❌ Failed to invoke model: {e}")

if __name__ == "__main__":
    main()
