#!/usr/bin/env python3
import socket
import os
import requests
import sys
from urllib.parse import urlparse

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

def main():
    print("==================================================")
    print("PYTHON OLLAMA PORT 11434 CONNECTIVITY DIAGNOSTIC")
    print("==================================================")
    
    print(f"OLLAMA_HOST environment variable: {os.getenv('OLLAMA_HOST', '(not set, defaulting to http://localhost:11434)')}")
    
    parsed = urlparse(OLLAMA_HOST)
    host = parsed.hostname or "localhost"
    port = parsed.port or 11434
    
    print(f"Testing direct TCP socket connection to {host}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"✔ Direct TCP connection to {host}:{port} succeeded!")
        else:
            print(f"❌ Direct TCP connection to {host}:{port} failed (error code: {result}).")
            print("Please make sure Ollama is serving on port 11434.")
            sys.exit(1)
        sock.close()
    except Exception as e:
        print(f"❌ Direct socket test crashed: {e}")
        sys.exit(1)
        
    print(f"\nTesting HTTP connection to {OLLAMA_HOST}/api/tags...")
    try:
        response = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        if response.status_code == 200:
            print("✔ HTTP connection succeeded! Ollama is responsive.")
            print("Models currently loaded in local Ollama:")
            models = response.json().get("models", [])
            for m in models:
                print(f"  - {m['name']}")
        else:
            print(f"❌ HTTP request completed but returned status code: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"❌ HTTP request to Ollama failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
