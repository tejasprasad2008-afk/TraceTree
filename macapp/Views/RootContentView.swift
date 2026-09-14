import SwiftUI

extension Color {
    static let summerPeach = Color(red: 255/255, green: 229/255, blue: 180/255) // #FFE5B4
    static let summerPink = Color(red: 255/255, green: 192/255, blue: 203/255)  // #FFC0CB
    static let summerOrange = Color(red: 255/255, green: 140/255, blue: 42/255) // #FF8C2A
    static let summerVivid = Color(red: 255/255, green: 87/255, blue: 34/255)   // #FF5722
}

struct RootContentView: View {
    @StateObject var authManager = SupabaseAuthManager()
    
    var body: some View {
        Group {
            if !authManager.isAuthenticated {
                OnboardingView()
                    .environmentObject(authManager)
            } else if let user = authManager.currentUser, !user.quizCompleted {
                QuizView()
                    .environmentObject(authManager)
            } else {
                DashboardView()
                    .environmentObject(authManager)
            }
        }
        .frame(minWidth: 450, maxWidth: .infinity, minHeight: 600, maxHeight: .infinity)
        .background(
            VisualEffectView(material: .headerView, blendingMode: .withinWindow)
                .ignoresSafeArea()
        )
    }
}

// Background blur helper for premium native feel
struct VisualEffectView: NSViewRepresentable {
    let material: NSVisualEffectView.Material
    let blendingMode: NSVisualEffectView.BlendingMode
    
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = blendingMode
        view.state = .active
        return view
    }
    
    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
        nsView.blendingMode = blendingMode
    }
}
