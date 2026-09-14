import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var authManager: SupabaseAuthManager
    @State private var currentStep = 0
    
    let features = [
        OnboardingStep(
            title: "Dynamic Docker Sandbox",
            description: "Audits installers (.dmg, .exe) and custom packages inside an isolated container to intercept kernel-level interactions safely.",
            icon: "shippingbox.and.arrow.outward"
        ),
        OnboardingStep(
            title: "Machine Learning Detection",
            description: "Translates complex system call cascades into high-dimensional feature vectors evaluated by optimized Random Forest models.",
            icon: "cpu.fill"
        ),
        OnboardingStep(
            title: "Ollama-Powered AI Triage",
            description: "Leverages local GPU models (qwen2.5-coder:7b) to verify anomalies, filter out benign behavior, and deliver clear security verdicts.",
            icon: "brain.head.profile"
        )
    ]
    
    var body: some View {
        VStack(spacing: 20) {
            // Header
            HStack(spacing: 12) {
                Image(systemName: "shield.trianglebadge.exclamationmark.fill")
                    .font(.system(size: 32))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [.summerVivid, .summerOrange, .summerPink],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                
                VStack(alignment: .leading, spacing: 2) {
                    Text("TraceTree")
                        .font(.system(size: 26, weight: .bold, design: .rounded))
                    Text("Runtime Behavioral Security")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .padding(.top, 40)
            
            // Custom Onboarding Step Display with transition animations
            VStack(spacing: 16) {
                Image(systemName: features[currentStep].icon)
                    .font(.system(size: 48))
                    .foregroundColor(.summerOrange)
                    .padding(.bottom, 8)
                    .id("icon-\(currentStep)")
                
                Text(features[currentStep].title)
                    .font(.headline)
                    .foregroundColor(.primary)
                    .id("title-\(currentStep)")
                
                Text(features[currentStep].description)
                    .font(.subheadline)
                    .multilineTextAlignment(.center)
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 24)
                    .lineSpacing(4)
                    .frame(height: 60)
                    .id("desc-\(currentStep)")
                
                // Indicators / Navigation Buttons
                HStack(spacing: 16) {
                    Button(action: {
                        if currentStep > 0 {
                            withAnimation(.spring()) {
                                currentStep -= 1
                            }
                        }
                    }) {
                        Image(systemName: "chevron.left")
                            .foregroundColor(currentStep > 0 ? .summerOrange : .secondary.opacity(0.3))
                            .padding(8)
                    }
                    .disabled(currentStep == 0)
                    .buttonStyle(PlainButtonStyle())
                    
                    HStack(spacing: 8) {
                        ForEach(0..<features.count, id: \.self) { idx in
                            Circle()
                                .fill(idx == currentStep ? Color.summerOrange : Color.secondary.opacity(0.3))
                                .frame(width: 8, height: 8)
                        }
                    }
                    
                    Button(action: {
                        if currentStep < features.count - 1 {
                            withAnimation(.spring()) {
                                currentStep += 1
                            }
                        }
                    }) {
                        Image(systemName: "chevron.right")
                            .foregroundColor(currentStep < features.count - 1 ? .summerOrange : .secondary.opacity(0.3))
                            .padding(8)
                    }
                    .disabled(currentStep == features.count - 1)
                    .buttonStyle(PlainButtonStyle())
                }
                .padding(.top, 8)
            }
            .frame(height: 240)
            
            Spacer()
            
            // Google Sign In
            VStack(spacing: 12) {
                Button(action: {
                    Task {
                        await authManager.signInWithGoogle()
                    }
                }) {
                    HStack(spacing: 12) {
                        if authManager.isAuthenticating {
                            ProgressView()
                                .controlSize(.small)
                        } else {
                            Image(systemName: "g.circle.fill")
                                .font(.title3)
                        }
                        Text("Sign in with Google")
                            .fontWeight(.semibold)
                    }
                    .foregroundColor(.black)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(Color.summerPeach)
                    .cornerRadius(12)
                }
                .buttonStyle(PlainButtonStyle())
                .disabled(authManager.isAuthenticating)
                
                Text("Distributed securely outside the App Store. Hardened runtime enforced.")
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 40)
        }
        .padding()
    }
}

struct OnboardingStep {
    let title: String
    let description: String
    let icon: String
}
