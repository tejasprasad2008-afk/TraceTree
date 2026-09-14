import SwiftUI
import AppKit

// MARK: - Manager (owned by DashboardView as @StateObject)

final class TerminalPanelManager: ObservableObject {
    @Published var logs: [String] = []

    private var panel: NSPanel?

    func push(logs: [String]) {
        self.logs = logs
    }

    func open() {
        if panel == nil {
            let hc = NSHostingController(rootView: TerminalPanelContent(manager: self))
            let p = NSPanel(
                contentRect: NSRect(x: 0, y: 0, width: 680, height: 440),
                styleMask: [.titled, .resizable, .closable, .miniaturizable, .utilityWindow],
                backing: .buffered,
                defer: false
            )
            p.title = "TraceTree — Terminal Output"
            p.contentViewController = hc
            p.isFloatingPanel = true
            p.hidesOnDeactivate = false
            p.minSize = NSSize(width: 400, height: 260)
            p.center()
            self.panel = p
        }
        panel?.makeKeyAndOrderFront(nil)
    }
}

// MARK: - Panel content (hosted inside NSPanel via NSHostingController)

private struct TerminalPanelContent: View {
    @ObservedObject var manager: TerminalPanelManager

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    if manager.logs.isEmpty {
                        Text("No output yet.")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.tertiary)
                            .padding(12)
                    } else {
                        ForEach(Array(manager.logs.enumerated()), id: \.offset) { idx, line in
                            LogLineView(line: line).id(idx)
                        }
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(Color.black.opacity(0.88))
            .onChange(of: manager.logs.count) { _, _ in
                if let last = manager.logs.indices.last {
                    proxy.scrollTo(last)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Floating blob button

struct TerminalBlobButton: View {
    let isActive: Bool
    let hasLogs: Bool
    let action: () -> Void

    @State private var isPulsing = false

    var body: some View {
        Button(action: action) {
            ZStack {
                if isActive {
                    Circle()
                        .fill(Color.summerOrange.opacity(0.35))
                        .frame(width: 56, height: 56)
                        .scaleEffect(isPulsing ? 1.3 : 1.0)
                        .opacity(isPulsing ? 0 : 1)
                        .animation(.easeOut(duration: 1.1).repeatForever(autoreverses: false), value: isPulsing)
                }
                Circle()
                    .fill(Color.summerOrange)
                    .frame(width: 44, height: 44)
                    .shadow(color: Color.summerOrange.opacity(isActive ? 0.5 : 0.2),
                            radius: isActive ? 10 : 4)
                Image(systemName: "terminal.fill")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundColor(.white)
            }
        }
        .buttonStyle(PlainButtonStyle())
        .opacity(hasLogs ? 1.0 : 0.4)
        .animation(.easeInOut(duration: 0.2), value: hasLogs)
        .onAppear { isPulsing = isActive }
        .onChange(of: isActive) { _, active in isPulsing = active }
        .help("Open terminal output")
    }
}
