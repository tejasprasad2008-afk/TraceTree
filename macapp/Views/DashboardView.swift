import SwiftUI

struct CommandOption: Identifiable {
    let id: String
    let name: String
    let icon: String
    let description: String
    let executableName: String
}

struct DashboardView: View {
    @EnvironmentObject var authManager: SupabaseAuthManager
    @StateObject var execManager = ExecutionManager()
    @StateObject private var ollamaHelper = OllamaHelper()
    @StateObject private var terminalManager = TerminalPanelManager()

    @State private var targetPath: String = ""
    @State private var selectedCommand: String? = nil
    @State private var showCommandPrompt = false
    @State private var useAITriage = true
    @State private var showAlert = false
    @State private var alertTitle = ""
    @State private var alertMessage = ""
    @State private var showIntakeScreen = false
    @State private var showContributionScreen = false
    @State private var showSettingsScreen = false
    @State private var showPastLogs = false

    let commands = [
        CommandOption(id: "scan",    name: "Scan",    icon: "shield.fill",                    description: "Static secrets & signature audit",        executableName: "cascade-scan"),
        CommandOption(id: "analyze", name: "Analyze", icon: "shippingbox.fill",               description: "Deep dynamic Docker sandbox",             executableName: "cascade-analyze"),
        CommandOption(id: "check",   name: "Check",   icon: "checkmark.seal.fill",            description: "Quick script sandbox audit",              executableName: "cascade-check"),
        CommandOption(id: "mcp",     name: "MCP",     icon: "network",                        description: "Fuzz Model Context Protocol tools",       executableName: "cascade-mcp"),
        CommandOption(id: "watch",   name: "Watch",   icon: "eye.fill",                       description: "Watch repo manifests continuously",       executableName: "cascade-watch"),
        CommandOption(id: "diff",    name: "Diff",    icon: "arrow.up.arrow.down.square.fill", description: "Compare behavior of two targets",        executableName: "cascade-diff"),
        CommandOption(id: "train",   name: "Train",   icon: "chart.line.uptrend.xyaxis",      description: "Compile Random Forest model",            executableName: "cascade-train"),
        CommandOption(id: "update",  name: "Update",  icon: "arrow.clockwise.circle.fill",    description: "Sync signature dictionaries",            executableName: "cascade-update"),
    ]

    // MARK: - Root layout

    var body: some View {
        HStack(spacing: 0) {
            sidebar
                .frame(width: 280)

            Divider()

            mainPanel
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(minWidth: 760, minHeight: 480)
        .overlay(alignment: .bottomTrailing) {
            TerminalBlobButton(
                isActive: execManager.isRunning,
                hasLogs: !execManager.logs.isEmpty,
                action: { terminalManager.open() }
            )
            .padding(20)
        }
        .sheet(isPresented: $showIntakeScreen) {
            IntakeView(isPresented: $showIntakeScreen, selectedCommand: $selectedCommand)
        }
        .sheet(isPresented: $showContributionScreen) {
            ContributionView(isPresented: $showContributionScreen)
        }
        .sheet(isPresented: $showSettingsScreen) {
            SettingsSheet(isPresented: $showSettingsScreen)
        }
        .sheet(isPresented: $showPastLogs) {
            PastLogsView(isPresented: $showPastLogs)
        }
        .alert(isPresented: $showAlert) {
            Alert(title: Text(alertTitle), message: Text(alertMessage), dismissButton: .default(Text("OK")))
        }
        .onChange(of: execManager.logs) { _, logs in
            terminalManager.push(logs: logs)
        }
        .onChange(of: execManager.isRunning) { _, isRunning in
            guard !isRunning else { return }
            // Only fire Swift Ollama for "check" — analyze already ran Ollama via --ai in CLI
            if useAITriage, selectedCommand == "check" {
                Task { await ollamaHelper.generateAIReport(logs: execManager.logs) }
            }
            // Persist scan to local history
            let fields = parseCLIFields(execManager.logs)
            ScanLogStore.shared.save(
                target: targetPath,
                command: selectedCommand ?? "unknown",
                verdict: execManager.verdict,
                logLines: execManager.logs,
                confidence: fields.confidence,
                signatures: fields.signatures
            )
        }
        .onChange(of: ollamaHelper.aiReport) { _, report in
            guard let report else { return }
            let v = report.verdict.lowercased()
            if v.contains("malicious") || v.contains("escape") { execManager.verdict = .malicious }
            else if v.contains("suspicious")                    { execManager.verdict = .suspicious }
            else if v.contains("clean") || v.contains("benign"){ execManager.verdict = .clean }
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            sidebarHeader
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    targetSection
                    commandSection
                }
                .padding(16)
            }

            Divider()
            runArea
        }
        .background(Color(NSColor.windowBackgroundColor))
    }

    private var sidebarHeader: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 2) {
                Text("TraceTree")
                    .font(.system(size: 14, weight: .bold, design: .rounded))
                Text("Malware Detection Engine")
                    .font(.system(size: 10))
                    .foregroundStyle(.tertiary)
            }
            Spacer()
            Menu {
                Button(action: { showPastLogs = true }) {
                    Label("Past Logs", systemImage: "clock.arrow.circlepath")
                }
                Divider()
                Button(action: { showSettingsScreen = true }) {
                    Label("Settings", systemImage: "gearshape")
                }
            } label: {
                Image(systemName: "person.crop.circle")
                    .font(.system(size: 18, weight: .light))
                    .foregroundStyle(.secondary)
            }
            .menuStyle(BorderlessButtonMenuStyle())
            .menuIndicator(.hidden)
            .fixedSize()
        }
        .padding(.horizontal, 16)
        .padding(.top, 20)
        .padding(.bottom, 14)
    }

    private var targetSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("TARGET")
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .kerning(1.5)
                .foregroundStyle(.secondary)

            HStack(spacing: 6) {
                TextField("Path or package name", text: $targetPath)
                    .textFieldStyle(PlainTextFieldStyle())
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                    .background(Color(NSColor.controlBackgroundColor))
                    .cornerRadius(6)
                    .font(.system(size: 11, design: .monospaced))
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color(NSColor.separatorColor), lineWidth: 0.5))

                Button("Browse", action: openFilePicker)
                    .buttonStyle(.bordered)
                    .font(.system(size: 11))
            }
        }
    }

    private var commandSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("COMMAND")
                    .font(.system(size: 9, weight: .semibold, design: .monospaced))
                    .kerning(1.5)
                    .foregroundStyle(.secondary)
                Spacer()
                if showCommandPrompt {
                    Text("Pick one")
                        .font(.system(size: 10))
                        .foregroundColor(.summerOrange)
                }
            }

            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                ForEach(commands) { cmd in
                    commandCell(cmd)
                }
            }

            Button(action: { showIntakeScreen = true }) {
                HStack(spacing: 4) {
                    Image(systemName: "questionmark.circle")
                        .font(.system(size: 10))
                    Text("Which command do I need?")
                        .font(.system(size: 10))
                }
                .foregroundStyle(.secondary)
            }
            .buttonStyle(PlainButtonStyle())
            .padding(.top, 2)
        }
    }

    private func commandCell(_ cmd: CommandOption) -> some View {
        let isSelected = selectedCommand == cmd.id
        return Button(action: {
            selectedCommand = cmd.id
            showCommandPrompt = false
            if cmd.id == "train" { showContributionScreen = true }
        }) {
            VStack(spacing: 6) {
                Image(systemName: cmd.icon)
                    .font(.system(size: 16, weight: isSelected ? .semibold : .regular))
                    .foregroundStyle(isSelected ? Color.white : Color.summerOrange)
                Text(cmd.name)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(isSelected ? Color.white : Color.primary)
            }
            .frame(maxWidth: .infinity)
            .frame(height: 64)
            .background(isSelected ? Color.summerOrange : Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(isSelected ? Color.clear : Color(NSColor.separatorColor), lineWidth: 0.5)
            )
        }
        .buttonStyle(PlainButtonStyle())
        .animation(.easeInOut(duration: 0.15), value: isSelected)
        .help(cmd.description)
    }

    private var runArea: some View {
        VStack(spacing: 10) {
            if selectedCommand == "analyze" {
                Toggle(isOn: $useAITriage) {
                    HStack(spacing: 5) {
                        Image(systemName: "cpu")
                            .font(.system(size: 10))
                            .foregroundColor(.summerOrange)
                        Text("Local AI Triage (Ollama)")
                            .font(.system(size: 11))
                    }
                }
                .toggleStyle(CheckboxToggleStyle())
            }

            if execManager.isRunning {
                VStack(spacing: 6) {
                    HStack {
                        Text(execManager.currentPhase)
                            .font(.system(size: 11, weight: .semibold))
                            .lineLimit(1)
                        Spacer()
                        Button("Stop") { execManager.terminate() }
                            .buttonStyle(.borderless)
                            .foregroundStyle(.secondary)
                            .font(.system(size: 11))
                    }
                    ProgressView(value: execManager.progress, total: 1.0)
                        .accentColor(.summerOrange)
                }
            } else {
                Button(action: triggerExecution) {
                    Text("Run Analysis")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(targetPath.isEmpty ? Color.secondary : Color.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                        .background(targetPath.isEmpty ? Color(NSColor.controlBackgroundColor) : Color.summerOrange)
                        .cornerRadius(8)
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color(NSColor.separatorColor), lineWidth: targetPath.isEmpty ? 0.5 : 0)
                        )
                }
                .buttonStyle(PlainButtonStyle())
                .disabled(targetPath.isEmpty)
                .animation(.easeInOut(duration: 0.15), value: targetPath.isEmpty)
            }
        }
        .padding(16)
    }

    // MARK: - Main Panel

    private var mainPanel: some View {
        Group {
            if execManager.isRunning {
                runningPanel
            } else if !execManager.logs.isEmpty {
                donePanel
            } else {
                idlePanel
            }
        }
    }

    private var runningPanel: some View {
        VStack(spacing: 16) {
            ProgressView()
                .progressViewStyle(CircularProgressViewStyle(tint: .summerOrange))
                .scaleEffect(1.4)
            Text(execManager.currentPhase)
                .font(.system(size: 14, weight: .medium, design: .rounded))
                .foregroundStyle(.secondary)
            Text("Tap the terminal button for live output")
                .font(.system(size: 11))
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.underPageBackgroundColor))
    }

    private var donePanel: some View {
        VStack(alignment: .leading, spacing: 0) {
            if execManager.verdict != .unknown {
                verdictBanner
            }

            if ollamaHelper.isProcessing {
                HStack(spacing: 8) {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .summerOrange))
                        .scaleEffect(0.75)
                    Text("AI Forensic Auditor compiling report...")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            } else if let report = ollamaHelper.aiReport {
                ScrollView {
                    aiReportBox(report).padding(16)
                }
            } else {
                ScrollView {
                    cliReportCard(logs: execManager.logs).padding(16)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.underPageBackgroundColor))
    }

    private var idlePanel: some View {
        VStack(spacing: 16) {
            Image(systemName: "shield.lefthalf.filled.slash")
                .font(.system(size: 52, weight: .thin))
                .foregroundStyle(.quaternary)

            VStack(spacing: 6) {
                Text("No analysis in progress")
                    .font(.system(size: 15, weight: .medium, design: .rounded))
                    .foregroundStyle(.secondary)
                Text("Select a target, choose a command, then run analysis.")
                    .font(.system(size: 12))
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
            }

            if let cmd = commands.first(where: { $0.id == selectedCommand }) {
                commandInfoCard(cmd)
                    .padding(.top, 8)
                    .frame(maxWidth: 360)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.underPageBackgroundColor))
    }

    private func commandInfoCard(_ cmd: CommandOption) -> some View {
        HStack(spacing: 12) {
            Image(systemName: cmd.icon)
                .font(.system(size: 22))
                .foregroundColor(.summerOrange)
                .frame(width: 36)

            VStack(alignment: .leading, spacing: 4) {
                Text("cascade-\(cmd.id)")
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                Text(cmd.description)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(14)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(10)
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(NSColor.separatorColor), lineWidth: 0.5))
    }

    private var verdictBanner: some View {
        HStack(spacing: 10) {
            Image(systemName: verdictIcon)
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(verdictForegroundColor)
            Text(execManager.verdict.rawValue)
                .font(.system(size: 13, weight: .bold, design: .monospaced))
                .foregroundStyle(verdictForegroundColor)
            Spacer()
            Text("Analysis Complete")
                .font(.system(size: 10))
                .foregroundStyle(verdictForegroundColor.opacity(0.7))
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(verdictBackgroundColor)
    }

    private var verdictIcon: String {
        switch execManager.verdict {
        case .clean:      return "checkmark.shield.fill"
        case .suspicious: return "exclamationmark.triangle.fill"
        case .malicious:  return "xmark.shield.fill"
        case .unknown:    return "questionmark.circle"
        }
    }

    // MARK: - Helpers

    private func openFilePicker() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.title = "Select File or Folder to Scan"
        panel.prompt = "Select"
        if panel.runModal() == .OK {
            targetPath = panel.url?.path ?? ""
        }
    }

    private func triggerExecution() {
        guard !targetPath.isEmpty else { return }
        guard let commandId = selectedCommand else {
            showCommandPrompt = true
            return
        }

        Task {
            ollamaHelper.aiReport = nil
            ollamaHelper.errorMessage = nil

            // Validate target exists (skip for train/update which need no path)
            let needsPath = !["train", "update"].contains(commandId)
            if needsPath && !FileManager.default.fileExists(atPath: targetPath) {
                alertTitle = "Target Not Found"
                alertMessage = "'\(targetPath)' does not exist on disk. Use Browse to select a valid file or directory."
                showAlert = true
                return
            }

            execManager.isRunning = true
            execManager.logs = ["Starting Preflight Checks..."]
            execManager.currentPhase = "Preflight Checks"

            // Docker sandbox only used by analyze and mcp commands
            let needsDocker = ["analyze", "mcp"].contains(commandId)
            if needsDocker {
                execManager.logs.append("Checking Docker daemon status...")
                let isDockerActive = await execManager.checkDockerDaemon()
                if !isDockerActive {
                    execManager.logs.append("[Error] Docker is not running or unreachable.")
                    execManager.logs.append("[Security Guard] Safety check FAILED. Analysis aborted.")
                    execManager.logs.append("Please start Docker Desktop and try again.")
                    execManager.currentPhase = "Safety Check Failed"
                    execManager.isRunning = false
                    alertTitle = "Docker Daemon Off"
                    alertMessage = "Docker is not running. Start Docker Desktop before running analysis."
                    showAlert = true
                    return
                }
                execManager.logs.append("[Success] Docker sandbox ready.")
            }

            let isAIEnabled = (["analyze", "check"].contains(commandId) && useAITriage)
            if isAIEnabled {
                execManager.logs.append("Verifying local AI Triage (Ollama)...")
                execManager.currentPhase = "AI Validation"

                // Auto-wake Ollama if not running; stream status into logs
                let woke = await ollamaHelper.wakeOllama { msg in
                    Task { @MainActor in execManager.logs.append(msg) }
                }
                if !woke {
                    execManager.logs.append("[Error] Could not start Ollama after 30s. Aborting.")
                    execManager.currentPhase = "AI Validation Failed"
                    execManager.isRunning = false
                    alertTitle = "Ollama Unreachable"
                    alertMessage = "Ollama did not start within 30 seconds. Open Ollama manually and try again."
                    showAlert = true
                    return
                }

                let ollamaStatus = await ollamaHelper.verifyOllamaAndModel()
                if !ollamaStatus.success {
                    execManager.logs.append("[Error] \(ollamaStatus.error ?? "Model not ready")")
                    execManager.currentPhase = "AI Validation Failed"
                    execManager.isRunning = false
                    alertTitle = "Ollama / Model Error"
                    alertMessage = ollamaStatus.error ?? "Ensure qwen2.5-coder:7b is pulled."
                    showAlert = true
                    return
                }
                execManager.logs.append("[Success] Ollama model 'qwen2.5-coder:7b' active.")
            }

            // Warn when static tools can't inspect archive/binary payloads
            if ["scan", "check"].contains(commandId) {
                let ext = URL(fileURLWithPath: targetPath).pathExtension.lowercased()
                let archiveExts: Set<String> = ["zip", "tar", "gz", "tgz", "7z", "rar", "dmg", "exe", "msi", "pkg"]
                if archiveExts.contains(ext) {
                    execManager.isRunning = false
                    alertTitle = "Static Scan Can't Inspect \(ext.uppercased()) Files"
                    alertMessage = "'\(URL(fileURLWithPath: targetPath).lastPathComponent)' is a \(ext.uppercased()) archive or binary. Static signature scanning cannot execute or unpack it — behavioral malware will not be detected.\n\nUse Analyze instead. It runs the payload inside a Docker sandbox and applies ML + AI triage."
                    showAlert = true
                    return
                }
            }

            var preflightLogs = execManager.logs
            preflightLogs.append("Initializing analysis...")

            if commandId == "analyze" {
                let ext = URL(fileURLWithPath: targetPath).pathExtension.lowercased()
                let typeParam: String
                switch ext {
                case "dmg":                          typeParam = "dmg"
                case "exe", "msi":                   typeParam = "exe"
                case "zip", "tar", "gz", "tgz", "7z", "rar": typeParam = "pip"
                default:                             typeParam = "pip"
                }
                var args = [targetPath, "--type", typeParam]
                if useAITriage { args.append("--ai") }
                await execManager.runCommand(name: "cascade-analyze", arguments: args, initialLogs: preflightLogs)
            } else if commandId == "scan" {
                await execManager.runCommand(name: "cascade-scan", arguments: [targetPath], initialLogs: preflightLogs)
            } else if commandId == "check" {
                await execManager.runCommand(name: "cascade-check", arguments: [targetPath], initialLogs: preflightLogs)
            } else if commandId == "mcp" {
                await execManager.runCommand(name: "cascade-analyze", arguments: ["mcp", "--npm", targetPath], initialLogs: preflightLogs)
            } else if commandId == "watch" {
                await execManager.runCommand(name: "cascade-watch", arguments: [targetPath], initialLogs: preflightLogs)
            } else if commandId == "diff" {
                await execManager.runCommand(name: "cascade-analyze", arguments: ["diff", targetPath], initialLogs: preflightLogs)
            } else if commandId == "train" {
                await execManager.runCommand(name: "cascade-train", arguments: [], initialLogs: preflightLogs)
            } else if commandId == "update" {
                await execManager.runCommand(name: "cascade-update", arguments: [], initialLogs: preflightLogs)
            }
        }
    }

    private func aiReportBox(_ report: AIReport) -> some View {
        let boxColor: Color
        switch report.color.lowercased() {
        case "red":    boxColor = .red
        case "orange": boxColor = .orange
        case "green":  boxColor = .green
        default:       boxColor = .secondary
        }

        return VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: report.color.lowercased() == "green"
                    ? "checkmark.circle.fill"
                    : report.color.lowercased() == "orange"
                        ? "exclamationmark.triangle.fill"
                        : "exclamationmark.octagon.fill")
                    .foregroundColor(boxColor)
                    .font(.title3)

                VStack(alignment: .leading, spacing: 2) {
                    Text("AI Forensic Audit Summary")
                        .font(.system(size: 12, weight: .bold, design: .rounded))
                    Text("Severity: \(report.severity)")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(.secondary)
                }
                Spacer()
                Text(report.verdict.uppercased())
                    .font(.system(size: 10, weight: .black))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(boxColor)
                    .foregroundColor(.white)
                    .cornerRadius(6)
            }

            Divider().background(boxColor.opacity(0.3))

            VStack(alignment: .leading, spacing: 6) {
                Text("Reason:")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(.secondary)
                Text(report.reason)
                    .font(.system(size: 11))
                    .lineSpacing(2)
            }

            if !report.keyFindings.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Key Findings:")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.secondary)
                    ForEach(report.keyFindings, id: \.self) { finding in
                        HStack(alignment: .top, spacing: 6) {
                            Text("•").foregroundColor(boxColor).font(.system(size: 12, weight: .bold))
                            Text(finding).font(.system(size: 11))
                        }
                    }
                }
                .padding(.top, 4)
            }
        }
        .padding(14)
        .background(boxColor.opacity(0.12))
        .cornerRadius(12)
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(boxColor, lineWidth: 1.5))
    }

    private func cliReportCard(logs: [String]) -> some View {
        let fields = parseCLIFields(logs)
        let accentColor = verdictForegroundColor

        return VStack(alignment: .leading, spacing: 12) {
            // Header
            HStack(spacing: 8) {
                Image(systemName: verdictIcon)
                    .font(.system(size: 18))
                    .foregroundColor(accentColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Analysis Report")
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                    if let conf = fields.confidence {
                        Text("Confidence: \(conf)")
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if fields.hardBlock {
                    Text("HARD BLOCK")
                        .font(.system(size: 9, weight: .black))
                        .padding(.horizontal, 8).padding(.vertical, 3)
                        .background(Color.red.opacity(0.2))
                        .foregroundColor(.red)
                        .cornerRadius(4)
                }
            }

            Divider().background(accentColor.opacity(0.3))

            if let threat = fields.suspectedThreat {
                reportRow(label: "Suspected Threat", value: threat, color: accentColor)
            }
            if let sigs = fields.signatures {
                reportRow(label: "Signatures", value: sigs, color: .orange)
            }
            if let jury = fields.juryVerdict {
                reportRow(label: "Jury Verdict", value: jury,
                          color: jury.lowercased().contains("malicious") ? .red :
                                 jury.lowercased().contains("suspicious") ? .orange : .green)
            }
            if let reason = fields.reasoning {
                VStack(alignment: .leading, spacing: 4) {
                    Text("REASONING")
                        .font(.system(size: 9, weight: .semibold, design: .monospaced))
                        .kerning(1.2)
                        .foregroundStyle(.secondary)
                    Text(reason)
                        .font(.system(size: 11))
                        .lineSpacing(2)
                        .foregroundStyle(.primary)
                }
            }

            if fields.peakMemory != nil || fields.filesInstalled != nil {
                Divider().background(Color(NSColor.separatorColor))
                HStack(spacing: 16) {
                    if let mem = fields.peakMemory {
                        statPill(icon: "memorychip", label: mem)
                    }
                    if let disk = fields.diskUsed {
                        statPill(icon: "internaldrive", label: disk)
                    }
                    if let files = fields.filesInstalled {
                        statPill(icon: "doc.on.doc", label: "\(files) files")
                    }
                }
            }

            HStack(spacing: 6) {
                Image(systemName: "terminal")
                    .font(.system(size: 9))
                    .foregroundStyle(.tertiary)
                Text("Full trace available in terminal output")
                    .font(.system(size: 10))
                    .foregroundStyle(.tertiary)
            }
            .padding(.top, 4)
        }
        .padding(16)
        .background(accentColor.opacity(0.07))
        .cornerRadius(12)
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(accentColor.opacity(0.25), lineWidth: 1))
    }

    private func reportRow(label: String, value: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label.uppercased())
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .kerning(1.2)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(color)
        }
    }

    private func statPill(icon: String, label: String) -> some View {
        HStack(spacing: 4) {
            Image(systemName: icon).font(.system(size: 9)).foregroundStyle(.secondary)
            Text(label).font(.system(size: 10)).foregroundStyle(.secondary)
        }
    }

    private struct CLIFields {
        var confidence: String?
        var signatures: String?
        var juryVerdict: String?
        var reasoning: String?
        var suspectedThreat: String?
        var peakMemory: String?
        var diskUsed: String?
        var filesInstalled: String?
        var hardBlock = false
    }

    private func parseCLIFields(_ logs: [String]) -> CLIFields {
        var f = CLIFields()
        for line in logs {
            let t = line.trimmingCharacters(in: .whitespacesAndNewlines)
            let l = t.lowercased()
            if l.hasPrefix("confidence score:") { f.confidence = after(t, "Confidence Score:") }
            else if l.hasPrefix("signatures:") { f.signatures = after(t, "Signatures:") }
            else if l.hasPrefix("jury verdict:") { f.juryVerdict = after(t, "Jury Verdict:") }
            else if l.hasPrefix("reasoning:") { f.reasoning = after(t, "Reasoning:") }
            else if l.hasPrefix("suspected threat:") { f.suspectedThreat = after(t, "Suspected Threat:") }
            else if l.contains("peak memory:") {
                // "Peak memory: 30.8 MB | Disk used: 2.6 MB | Files installed: 2377"
                let parts = t.components(separatedBy: "|")
                for part in parts {
                    let p = part.trimmingCharacters(in: .whitespaces)
                    if p.lowercased().hasPrefix("peak memory:") { f.peakMemory = after(p, "Peak memory:") }
                    else if p.lowercased().hasPrefix("disk used:") { f.diskUsed = after(p, "Disk used:") }
                    else if p.lowercased().hasPrefix("files installed:") { f.filesInstalled = after(p, "Files installed:") }
                }
            }
            if l.contains("hard block") { f.hardBlock = true }
        }
        return f
    }

    private func after(_ s: String, _ prefix: String) -> String? {
        guard let r = s.range(of: prefix, options: .caseInsensitive) else { return nil }
        return String(s[r.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
            .components(separatedBy: "\n").first.map { $0.trimmingCharacters(in: .whitespaces) }
    }

    private var verdictBackgroundColor: Color {
        switch execManager.verdict {
        case .clean:      return Color.green.opacity(0.18)
        case .suspicious: return Color.orange.opacity(0.18)
        case .malicious:  return Color.red.opacity(0.9)
        case .unknown:    return Color.secondary.opacity(0.12)
        }
    }

    private var verdictForegroundColor: Color {
        switch execManager.verdict {
        case .clean:      return .green
        case .suspicious: return .orange
        case .malicious:  return .white
        case .unknown:    return .secondary
        }
    }
}

// MARK: - Settings Sheet

struct SettingsSheet: View {
    @Binding var isPresented: Bool
    @EnvironmentObject var authManager: SupabaseAuthManager

    var body: some View {
        VStack(spacing: 20) {
            Text("Settings")
                .font(.headline)

            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("User:")
                    Spacer()
                    Text(authManager.currentUser?.name ?? "Alex").foregroundColor(.secondary)
                }
                HStack {
                    Text("Email:")
                    Spacer()
                    Text(authManager.currentUser?.email ?? "").foregroundColor(.secondary)
                }
            }
            .padding()
            .background(Color.secondary.opacity(0.08))
            .cornerRadius(10)

            Button("Sign Out") {
                authManager.signOut()
                isPresented = false
            }
            .buttonStyle(.borderedProminent)
            .tint(.summerOrange)

            Button("Done") { isPresented = false }
                .buttonStyle(.borderless)
                .foregroundColor(.secondary)
        }
        .padding()
        .frame(width: 300, height: 260)
    }
}

// MARK: - Log Line View

struct LogLineView: View {
    let line: String

    var body: some View {
        if let (key, value) = parseKeyValue(line) {
            HStack(alignment: .top, spacing: 6) {
                Text(key + ":")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundColor(.white)
                Text(value)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(logColor(for: value, fallback: .secondary))
            }
        } else {
            Text(line)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(logColor(for: line))
        }
    }

    private func parseKeyValue(_ text: String) -> (String, String)? {
        let parts = text.components(separatedBy: "  ").filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        if parts.count == 2 {
            let k = parts[0].trimmingCharacters(in: .whitespacesAndNewlines)
            let v = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
            if k.count > 2 && k.count < 35 { return (k, v) }
        }
        return nil
    }

    private func logColor(for text: String, fallback: Color = .white) -> Color {
        let l = text.lowercased()
        if l.contains("error") || l.contains("failed") || l.contains("exception") || l.contains("errno") { return .red }
        if l.contains("warning") || l.contains("suspicious") || l.contains("flagged") || l.contains("malicious") { return .summerOrange }
        if l.contains("success") || l.contains("clean") || l.contains("complete") || l.contains("safe") { return .green }
        if text.range(of: "^\\s*\\d+\\s*\\|", options: .regularExpression) != nil { return .summerPink }
        if l.contains("locals") || l.contains("exist_ok") || l.contains("mode =") { return .summerPeach }
        return fallback
    }
}
