import SwiftUI

struct PastLogsView: View {
    @Binding var isPresented: Bool
    @ObservedObject private var store = ScanLogStore.shared
    @State private var selectedLog: ScanLog? = nil

    private let df: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    var body: some View {
        HSplitView {
            logList
                .frame(minWidth: 280, maxWidth: 340)
            detailPanel
                .frame(minWidth: 400)
        }
        .frame(width: 780, height: 520)
    }

    private var logList: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Past Scans")
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                Spacer()
                if !store.logs.isEmpty {
                    Button("Clear All") { store.clearAll(); selectedLog = nil }
                        .buttonStyle(.borderless)
                        .foregroundStyle(.secondary)
                        .font(.system(size: 11))
                }
                Button("Done") { isPresented = false }
                    .buttonStyle(.borderedProminent)
                    .tint(.summerOrange)
                    .font(.system(size: 11))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)

            Divider()

            if store.logs.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "clock.badge.xmark")
                        .font(.system(size: 32, weight: .thin))
                        .foregroundStyle(.quaternary)
                    Text("No past scans yet")
                        .font(.system(size: 12))
                        .foregroundStyle(.tertiary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(store.logs, selection: Binding(
                    get: { selectedLog?.id },
                    set: { id in selectedLog = store.logs.first { $0.id == id } }
                )) { log in
                    logRow(log)
                        .tag(log.id)
                        .listRowInsets(EdgeInsets(top: 4, leading: 8, bottom: 4, trailing: 8))
                }
                .listStyle(.sidebar)
            }
        }
        .background(Color(NSColor.windowBackgroundColor))
    }

    private func logRow(_ log: ScanLog) -> some View {
        let accent = verdictColor(log.verdictEnum)
        return HStack(spacing: 8) {
            RoundedRectangle(cornerRadius: 3)
                .fill(accent)
                .frame(width: 4, height: 40)

            VStack(alignment: .leading, spacing: 3) {
                Text(URL(fileURLWithPath: log.target).lastPathComponent)
                    .font(.system(size: 11, weight: .semibold))
                    .lineLimit(1)
                HStack(spacing: 4) {
                    Text(log.verdict)
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .foregroundColor(accent)
                    Text("·")
                        .foregroundStyle(.tertiary)
                    Text(log.command.uppercased())
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                Text(df.string(from: log.date))
                    .font(.system(size: 9))
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder
    private var detailPanel: some View {
        if let log = selectedLog {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 10) {
                    Circle()
                        .fill(verdictColor(log.verdictEnum))
                        .frame(width: 10, height: 10)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(URL(fileURLWithPath: log.target).lastPathComponent)
                            .font(.system(size: 13, weight: .bold))
                        Text(log.target)
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(log.verdict)
                            .font(.system(size: 11, weight: .black, design: .monospaced))
                            .foregroundColor(verdictColor(log.verdictEnum))
                        Text(df.string(from: log.date))
                            .font(.system(size: 9))
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(14)
                .background(verdictColor(log.verdictEnum).opacity(0.1))

                Divider()

                if let conf = log.confidence, !conf.isEmpty {
                    metaRow("Confidence", value: conf)
                }
                if let sigs = log.signatures, !sigs.isEmpty {
                    metaRow("Signatures", value: sigs)
                    Divider()
                }

                Text("TERMINAL OUTPUT")
                    .font(.system(size: 9, weight: .semibold, design: .monospaced))
                    .kerning(1.2)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 14)
                    .padding(.top, 10)
                    .padding(.bottom, 6)

                ScrollViewReader { proxy in
                    ScrollView {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(Array(log.logLines.enumerated()), id: \.offset) { i, line in
                                Text(line)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(logLineColor(line))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(i)
                            }
                        }
                        .padding(12)
                    }
                    .background(Color.black.opacity(0.85))
                    .onAppear {
                        if let last = log.logLines.indices.last { proxy.scrollTo(last) }
                    }
                }

                HStack {
                    Spacer()
                    Button(role: .destructive) {
                        store.delete(log.id)
                        selectedLog = nil
                    } label: {
                        Label("Delete", systemImage: "trash")
                            .font(.system(size: 11))
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.red.opacity(0.8))
                    .padding(10)
                }
            }
        } else {
            VStack(spacing: 10) {
                Image(systemName: "arrow.left.square")
                    .font(.system(size: 36, weight: .thin))
                    .foregroundStyle(.quaternary)
                Text("Select a scan to view details")
                    .font(.system(size: 12))
                    .foregroundStyle(.tertiary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(NSColor.underPageBackgroundColor))
        }
    }

    private func metaRow(_ label: String, value: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label.uppercased() + ":")
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .kerning(1.0)
                .foregroundStyle(.secondary)
                .frame(width: 80, alignment: .trailing)
            Text(value)
                .font(.system(size: 10))
                .foregroundStyle(.primary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 4)
    }

    private func verdictColor(_ v: Verdict) -> Color {
        switch v {
        case .malicious:  return .red
        case .suspicious: return .orange
        case .clean:      return .green
        case .unknown:    return .secondary
        }
    }

    private func logLineColor(_ line: String) -> Color {
        let l = line.lowercased()
        if l.contains("error") || l.contains("malicious") || l.contains("failed") { return .red }
        if l.contains("suspicious") || l.contains("warning") || l.contains("flagged") { return .orange }
        if l.contains("success") || l.contains("clean") || l.contains("complete") { return .green }
        return Color.white.opacity(0.85)
    }
}
