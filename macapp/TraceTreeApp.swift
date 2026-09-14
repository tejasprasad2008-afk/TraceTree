import SwiftUI
import AppKit

@main
struct TraceTreeApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    var body: some Scene {
        // We manage windows programmatically via AppDelegate to combine Dock/MenuBar Extra
        Settings {
            SettingsView()
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    var statusItem: NSStatusItem?
    var mainWindow: NSWindow?
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Run as a standard macOS application with Dock icon and app menu
        NSApp.setActivationPolicy(.regular)
        
        // Open the primary application window on launch
        setupMainWindow()
        
        // Add the helper icon in the top menu bar
        setupStatusItem()
    }
    
    func setupMainWindow() {
        if mainWindow == nil {
            let contentView = RootContentView()
            
            let window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 850, height: 650),
                styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                backing: .buffered,
                defer: false
            )
            window.title = "TraceTree Security Guardian"
            window.titlebarAppearsTransparent = true
            window.titleVisibility = .hidden
            window.isReleasedWhenClosed = false
            window.delegate = self
            window.center()
            
            // Apply standard window sizing constraints
            window.minSize = NSSize(width: 500, height: 600)
            
            window.contentViewController = NSHostingController(rootView: contentView)
            self.mainWindow = window
        }
        
        mainWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    
    func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        
        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "shield.trianglebadge.exclamationmark", accessibilityDescription: "TraceTree Status")
            button.contentTintColor = NSColor(red: 1.0, green: 0.55, blue: 0.16, alpha: 1.0) // Summer Orange
            button.action = #selector(statusBarClicked(_:))
        }
    }
    
    @objc func statusBarClicked(_ sender: AnyObject?) {
        if let window = mainWindow {
            if window.isVisible && window.isKeyWindow {
                window.orderOut(nil)
            } else {
                window.makeKeyAndOrderFront(nil)
                NSApp.activate(ignoringOtherApps: true)
            }
        } else {
            setupMainWindow()
        }
    }
    
    // Support reopening the window when user clicks the Dock icon
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            setupMainWindow()
        } else {
            mainWindow?.makeKeyAndOrderFront(nil)
        }
        return true
    }
    
    // Hide the window instead of destroying it when closed
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }
}

struct SettingsView: View {
    var body: some View {
        VStack(spacing: 20) {
            Text("TraceTree Preferences")
                .font(.headline)
            Text("Configure Docker environment, local Ollama endpoints, and developer models.")
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .padding()
        .frame(width: 400, height: 200)
    }
}
