import Foundation

struct ScanLog: Codable, Identifiable {
    let id: UUID
    let date: Date
    let target: String
    let command: String
    let verdict: String
    let confidence: String?
    let signatures: String?
    let logLines: [String]

    var verdictEnum: Verdict {
        switch verdict.uppercased() {
        case "MALICIOUS": return .malicious
        case "SUSPICIOUS": return .suspicious
        case "CLEAN":     return .clean
        default:          return .unknown
        }
    }
}

final class ScanLogStore: ObservableObject {
    static let shared = ScanLogStore()

    @Published private(set) var logs: [ScanLog] = []

    private let key = "tracetree.scan_logs"

    private init() { load() }

    func save(target: String, command: String, verdict: Verdict,
              logLines: [String], confidence: String?, signatures: String?) {
        let entry = ScanLog(
            id: UUID(),
            date: Date(),
            target: target,
            command: command,
            verdict: verdict.rawValue,
            confidence: confidence,
            signatures: signatures,
            logLines: Array(logLines.suffix(200))
        )
        logs.insert(entry, at: 0)
        persist()
    }

    func delete(_ id: UUID) {
        logs.removeAll { $0.id == id }
        persist()
    }

    func clearAll() {
        logs = []
        persist()
    }

    private func load() {
        guard let data = UserDefaults.standard.data(forKey: key),
              let decoded = try? JSONDecoder().decode([ScanLog].self, from: data) else { return }
        logs = decoded
    }

    private func persist() {
        guard let data = try? JSONEncoder().encode(logs) else { return }
        UserDefaults.standard.set(data, forKey: key)
    }
}
