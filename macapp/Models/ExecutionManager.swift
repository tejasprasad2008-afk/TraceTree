import Foundation
import Combine

// Top-level so all views can reference without qualification
enum Verdict: String {
    case clean = "CLEAN"
    case suspicious = "SUSPICIOUS"
    case malicious = "MALICIOUS"
    case unknown = "PENDING"
}

@MainActor
class ExecutionManager: ObservableObject {
    @Published var logs: [String] = []
    @Published var isRunning: Bool = false
    @Published var currentPhase: String = "Idle"
    @Published var verdict: Verdict = .unknown
    @Published var progress: Double = 0.0
    
    private var process: Process?
    private var outputPipe: Pipe?
    
    // Find the binary executable path in common macOS location hierarchies
    private func getBinaryPath(for command: String) -> String? {
        let fileManager = FileManager.default
        
        // 1. Resolve via PATH environment variable
        if let pathEnv = ProcessInfo.processInfo.environment["PATH"] {
            let dirs = pathEnv.components(separatedBy: ":")
            for dir in dirs {
                let fullPath = (dir as NSString).appendingPathComponent(command)
                if fileManager.fileExists(atPath: fullPath) {
                    return fullPath
                }
            }
        }
        
        // 2. Direct lookup fallbacks
        let paths = [
            "/usr/local/bin/\(command)",
            "/opt/homebrew/bin/\(command)",
            "\(NSHomeDirectory())/.local/bin/\(command)",
            "/Users/tejasprasad/TraceTree/venv/bin/\(command)" // Absolute fallback to project venv
        ]
        
        for path in paths {
            if fileManager.fileExists(atPath: path) {
                return path
            }
        }
        
        // 3. Check relative venv in the current directory if it exists
        let currentDir = fileManager.currentDirectoryPath
        let venvPath = "\(currentDir)/venv/bin/\(command)"
        if fileManager.fileExists(atPath: venvPath) {
            return venvPath
        }
        
        return nil
    }
    
    // Clean ANSI escape codes from output lines
    nonisolated private func cleanLine(_ line: String) -> String {
        guard let regex = try? NSRegularExpression(pattern: "\\x1b\\[[0-9;]*[mKJ]", options: []) else {
            return line
        }
        let range = NSRange(location: 0, length: line.utf16.count)
        let cleaned = regex.stringByReplacingMatches(in: line, options: [], range: range, withTemplate: "")
        
        // Also strip box-drawing decorations
        let boxChars = CharacterSet(charactersIn: "─│╭╰╮╯└┘├┤┬┴┼ ✔✗·")
        return cleaned.trimmingCharacters(in: boxChars).trimmingCharacters(in: .whitespacesAndNewlines)
    }
    
    // Parse the output line to detect current phase, progress, and verdict
    private func parseLine(_ line: String) {
        let lowerLine = line.lowercased()
        
        // Detect phase changes
        let phases: [String: (name: String, weight: Double)] = [
            "sandboxing": ("Sandboxing in Docker", 0.15),
            "parsing": ("Parsing System Trace", 0.40),
            "graphing": ("Building Behavioral Graph", 0.60),
            "detecting": ("Running ML Classifier", 0.75),
            "analyzing": ("Ollama AI Triage", 0.90),
            "scanning": ("Static Signature Check", 0.30),
            "checking": ("Quick scan", 0.50),
            "initialize": ("MCP Handshake", 0.20),
            "tools/list": ("Discovering MCP Tools", 0.40),
            "probing": ("Adversarial Probing", 0.70)
        ]
        
        for (keyword, value) in phases {
            if lowerLine.contains(keyword) {
                self.currentPhase = value.name
                self.progress = value.weight
                break
            }
        }
        
        // Detect verdict — only on explicit terminal verdict lines, not incidental mentions
        // e.g. "No issues detected" or "clean environment" must NOT flip verdict to CLEAN
        let trimmed = lowerLine.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed == "malicious" || lowerLine.contains("verdict: malicious") || lowerLine.contains("flagged as malicious") {
            self.verdict = .malicious
            self.progress = 1.0
        } else if trimmed == "suspicious" || lowerLine.contains("verdict: suspicious") {
            if self.verdict != .malicious { self.verdict = .suspicious }
            self.progress = 1.0
        } else if trimmed == "clean" || lowerLine.contains("verdict: clean") {
            if self.verdict == .unknown { self.verdict = .clean }
            self.progress = 1.0
        }
    }
    
    func checkDockerDaemon() async -> Bool {
        guard let dockerPath = getBinaryPath(for: "docker") else {
            return false
        }
        
        return await Task.detached(priority: .userInitiated) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: dockerPath)
            process.arguments = ["ps"]
            
            var env = ProcessInfo.processInfo.environment
            let existingPath = env["PATH"] ?? ""
            env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:\(existingPath)"
            process.environment = env
            
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            
            do {
                try process.run()
                process.waitUntilExit()
                return process.terminationStatus == 0
            } catch {
                return false
            }
        }.value
    }

    func runCommand(name: String, arguments: [String], initialLogs: [String] = []) async {
        guard let binaryPath = getBinaryPath(for: name) else {
            logs = initialLogs
            logs.append("Error: Command '\(name)' not found. Please install the CLI package: pip install -e .")
            return
        }
        
        // Reset states
        logs = initialLogs
        isRunning = true
        currentPhase = "Initializing"
        verdict = .unknown
        progress = 0.05
        
        let process = Process()
        process.executableURL = URL(fileURLWithPath: binaryPath)
        process.arguments = arguments
        process.currentDirectoryURL = URL(fileURLWithPath: "/Users/tejasprasad/TraceTree")
        
        // Pass expanded environment so subprocesses can locate docker, python, and other utilities
        var env = ProcessInfo.processInfo.environment
        let existingPath = env["PATH"] ?? ""
        env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:\(existingPath)"
        process.environment = env
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        self.process = process
        self.outputPipe = pipe
        
        let fileHandle = pipe.fileHandleForReading
        
        do {
            try process.run()
        } catch {
            logs.append("Failed to execute process: \(error.localizedDescription)")
            isRunning = false
            return
        }
        
        // Set up notification observer for data reading to avoid blocking the background task thread on empty pipes
        NotificationCenter.default.addObserver(
            forName: NSNotification.Name.NSFileHandleDataAvailable,
            object: fileHandle,
            queue: nil
        ) { [weak self] _ in
            guard let self = self else { return }
            let data = fileHandle.availableData
            if data.isEmpty {
                // Pipe reached EOF
                Task { @MainActor in
                    self.finishExecution()
                }
                return
            }
            
            if let outputString = String(data: data, encoding: .utf8) {
                let lines = outputString.components(separatedBy: .newlines)
                for line in lines {
                    let cleaned = self.cleanLine(line)
                    if !cleaned.isEmpty {
                        Task { @MainActor in
                            self.addLog(cleaned)
                        }
                    }
                }
            }
            
            fileHandle.waitForDataInBackgroundAndNotify()
        }
        
        fileHandle.waitForDataInBackgroundAndNotify()
    }
    
    private func addLog(_ log: String) {
        logs.append(log)
        parseLine(log)
    }
    
    private func finishExecution() {
        isRunning = false
        if progress < 1.0 {
            progress = 1.0
        }
        
        // Scan backwards to find the definitive final verdict printed at the end
        var foundVerdict: Verdict? = nil
        for i in (0..<logs.count).reversed() {
            let line = logs[i].trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            if line == "CLEAN" {
                foundVerdict = .clean
                break
            } else if line == "SUSPICIOUS" {
                foundVerdict = .suspicious
                break
            } else if line == "MALICIOUS" {
                foundVerdict = .malicious
                break
            }
        }
        
        if let fv = foundVerdict {
            self.verdict = fv
        } else {
            // Only escalate on explicit threat keywords; never default to CLEAN
            // "No issues detected" from a static tool is not a behavioral verdict
            let allLogs = logs.joined(separator: "\n").lowercased()
            if allLogs.contains("malicious") || allLogs.contains("flagged") {
                verdict = .malicious
            } else if allLogs.contains("suspicious") {
                verdict = .suspicious
            }
            // If nothing definitive found, leave verdict as .unknown
        }
        currentPhase = "Analysis Complete"
    }
    
    func terminate() {
        if process?.isRunning == true {
            process?.terminate()
        }
        isRunning = false
        currentPhase = "Stopped"
    }
}
