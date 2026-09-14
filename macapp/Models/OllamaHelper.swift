import Foundation
import Combine

struct OllamaResponse: Codable {
    let response: String
}

struct Recommendation: Codable {
    let command: String
    let explanation: String
}

@MainActor
class OllamaHelper: ObservableObject {
    @Published var isProcessing = false
    @Published var recommendation: Recommendation? = nil
    @Published var errorMessage: String? = nil
    
    private let urlString = "http://localhost:11434/api/generate"
    
    func parseUserGoal(_ goal: String) async {
        isProcessing = true
        recommendation = nil
        errorMessage = nil
        
        let systemPrompt = """
        You are a routing agent for TraceTree, a malware behavioral and security analysis platform.
        Given the user's security goal, select the single most appropriate command.
        
        Available commands:
        - scan: Security Guardian. Scans for hardcoded secrets, API keys, and static malicious patterns. Use for fast scanning of local directories.
        - analyze: Behavioral Cascade Analysis. Evaluates packages dynamically inside an isolated Docker sandbox. Best for installers like .dmg, .exe, or suspicious packages where behavior monitoring is needed.
        - check: Quick, on-demand dynamic container scan of a specific script or target file without full extraction.
        - mcp: Model Context Protocol server analysis. Tests and probes custom MCP tools with adversarial inputs.
        - watch: Continuous background sentinel. Polls local repository manifests (requirements.txt, package.json) for changes and triggers dynamic checking.
        - diff: Evaluates and compares behavioral graphs of two packages.
        - train: Gathers external MalwareBazaar samples and compiles the local Random Forest ML model.
        - update: Fetches the latest YARA threat signatures and ML model objects from Cloud Storage.
        
        You MUST respond ONLY with a raw JSON object matching this structure:
        {
          "command": "<one of the command names listed above>",
          "explanation": "<brief 1-2 sentence explanation of why this command fits the goal>"
        }
        """
        
        let prompt = "User's goal: \(goal)"
        
        let requestBody: [String: Any] = [
            "model": "qwen2.5-coder:7b",
            "prompt": "\(systemPrompt)\n\n\(prompt)",
            "stream": false,
            "options": [
                "temperature": 0.1
            ]
        ]
        
        guard let url = URL(string: urlString) else {
            self.errorMessage = "Invalid Ollama endpoint URL"
            self.isProcessing = false
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: requestBody, options: [])
        } catch {
            self.errorMessage = "Failed to serialize request data"
            self.isProcessing = false
            return
        }
        
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                self.errorMessage = "Ollama returned an invalid status. Make sure the Ollama app is running locally."
                self.isProcessing = false
                return
            }
            
            let ollamaRes = try JSONDecoder().decode(OllamaResponse.self, from: data)
            let rawResponse = ollamaRes.response.trimmingCharacters(in: .whitespacesAndNewlines)
            
            // Clean up backticks in case LLM outputs markdown fences
            var jsonString = rawResponse
            if jsonString.hasPrefix("```json") {
                jsonString = String(jsonString.dropFirst(7))
            }
            if jsonString.hasSuffix("```") {
                jsonString = String(jsonString.dropLast(3))
            }
            jsonString = jsonString.trimmingCharacters(in: .whitespacesAndNewlines)
            
            if let jsonData = jsonString.data(using: .utf8) {
                let rec = try JSONDecoder().decode(Recommendation.self, from: jsonData)
                self.recommendation = rec
                self.isProcessing = false
            } else {
                throw NSError(domain: "OllamaHelper", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to extract JSON bytes"])
            }
            
        } catch {
            self.errorMessage = "Ollama query failed: \(error.localizedDescription). Verify Ollama is running and qwen2.5-coder:7b is pulled."
            self.isProcessing = false
        }
    }
    
    private func pingOllama() async -> Bool {
        guard let url = URL(string: "http://localhost:11434/") else { return false }
        var req = URLRequest(url: url)
        req.timeoutInterval = 2.0
        return (try? await URLSession.shared.data(for: req)) != nil
    }

    // Launch Ollama.app if not already running, poll until HTTP 200 (up to 30s)
    func wakeOllama(statusCallback: @escaping (String) -> Void) async -> Bool {
        if await pingOllama() { return true }
        statusCallback("Ollama not responding — launching Ollama.app...")
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        p.arguments = ["-a", "Ollama"]
        try? p.run()
        for attempt in 1...15 {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            statusCallback("Waiting for Ollama to start... (\(attempt * 2)s)")
            if await pingOllama() {
                statusCallback("[Success] Ollama is now running.")
                return true
            }
        }
        return false
    }

    func verifyOllamaAndModel() async -> (success: Bool, error: String?) {
        guard let url = URL(string: "http://localhost:11434/api/generate") else {
            return (false, "Invalid Ollama URL configuration")
        }
        let requestBody: [String: Any] = [
            "model": "qwen2.5-coder:7b",
            "prompt": "ping",
            "stream": false,
            "options": ["temperature": 0.1]
        ]
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 8.0
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: requestBody, options: [])
            let (_, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                return (false, "Received invalid HTTP response from Ollama")
            }
            return httpResponse.statusCode == 200
                ? (true, nil)
                : (false, "Ollama running but qwen2.5-coder:7b not responding (HTTP \(httpResponse.statusCode))")
        } catch {
            return (false, "Ollama model check failed: \(error.localizedDescription)")
        }
    }
    
    @Published var aiReport: AIReport? = nil
    
    func generateAIReport(logs: [String]) async {
        isProcessing = true
        aiReport = nil
        errorMessage = nil
        
        guard let url = URL(string: urlString) else {
            isProcessing = false
            return
        }
        
        let logsText = logs.joined(separator: "\n")
        let systemPrompt = """
        You are a senior forensic security analyst assistant for the TraceTree malware analysis suite.
        Analyze the provided execution stream logs of a scanned/executed target.
        Your task is to determine the security status of the run.
        
        You MUST respond ONLY with a raw JSON object conforming exactly to this schema:
        {
          "verdict": "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "ESCAPE_DETECTED" | "ERROR",
          "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE",
          "color": "red" | "orange" | "green",
          "reason": "a detailed, non-technical explanation summarizing the threat or finding. If a sandbox escape or container threat was flagged, explain that specifically.",
          "keyFindings": ["finding 1", "finding 2", ...]
        }
        
        Rules:
        - If the logs mention "SECURITY THREAT DETECTED" or "SANDBOX ESCAPE" or "Container killed and removed" or "Mount Namespace Modification", categorize it as "ESCAPE_DETECTED" / "MALICIOUS", severity "CRITICAL", and color "red".
        - If other critical/malicious actions are found, use color "red".
        - If suspicious behaviors are found, use color "orange".
        - If it is safe/clean, use color "green".
        """
        
        let prompt = "Execution logs:\n\(logsText)"
        let requestBody: [String: Any] = [
            "model": "qwen2.5-coder:7b",
            "prompt": "\(systemPrompt)\n\n\(prompt)",
            "stream": false,
            "format": "json",
            "options": [
                "temperature": 0.1
            ]
        ]
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 30.0 // Allow time for full summary compilation
        
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: requestBody, options: [])
            let (data, response) = try await URLSession.shared.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                isProcessing = false
                return
            }
            
            let ollamaRes = try JSONDecoder().decode(OllamaResponse.self, from: data)
            let rawResponse = ollamaRes.response.trimmingCharacters(in: .whitespacesAndNewlines)
            
            var jsonString = rawResponse
            if jsonString.hasPrefix("```json") {
                jsonString = String(jsonString.dropFirst(7))
            }
            if jsonString.hasSuffix("```") {
                jsonString = String(jsonString.dropLast(3))
            }
            jsonString = jsonString.trimmingCharacters(in: .whitespacesAndNewlines)
            
            if let jsonData = jsonString.data(using: .utf8) {
                let report = try JSONDecoder().decode(AIReport.self, from: jsonData)
                self.aiReport = report
            }
        } catch {
            print("Failed to generate AI report: \(error.localizedDescription)")
            self.errorMessage = error.localizedDescription
        }
        isProcessing = false
    }
}

struct AIReport: Codable, Equatable {
    let verdict: String
    let severity: String
    let color: String
    let reason: String
    let keyFindings: [String]
}
