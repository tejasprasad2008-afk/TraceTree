import SwiftUI

struct ContributionView: View {
    @Binding var isPresented: Bool
    @State private var contributeData = true
    @State private var isSubmitting = false
    @State private var submissionComplete = false
    
    var body: some View {
        VStack(spacing: 20) {
            // Header
            HStack {
                Text("Federated Model Ingestion")
                    .font(.headline)
                    .foregroundColor(.summerOrange)
                Spacer()
                Button(action: { isPresented = false }) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(PlainButtonStyle())
            }
            .padding(.top, 16)
            
            Text("Help protect the ecosystem. Contribute anonymous sandbox execution graphs, YARA signatures, and false positive metrics back to the core TraceTree datasets.")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            
            // Statistics Card
            VStack(alignment: .leading, spacing: 12) {
                Text("Your Local Telemetry Nodes")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(.primary)
                
                HStack {
                    Text("Cached Execution Trees:")
                    Spacer()
                    Text("14 Profiles")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                }
                HStack {
                    Text("Random Forest Version:")
                    Spacer()
                    Text("v1.4.2 (RandomForest)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                }
                HStack {
                    Text("Last Compilation:")
                    Spacer()
                    Text("Yesterday at 18:24")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                }
            }
            .padding()
            .background(Color.white.opacity(0.04))
            .cornerRadius(12)
            
            // Toggle Ingestion Opt-In
            Toggle(isOn: $contributeData) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Contribute Sandbox Snapshots")
                        .font(.system(size: 12, weight: .bold))
                    Text("Anonymize all process names and environment variables before publishing.")
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)
                }
            }
            .toggleStyle(SwitchToggleStyle(tint: .summerOrange))
            .padding(.horizontal, 8)
            .padding(.vertical, 8)
            
            if !submissionComplete {
                Button(action: startContributionSubmission) {
                    HStack {
                        if isSubmitting {
                            ProgressView()
                                .controlSize(.small)
                                .padding(.trailing, 8)
                        }
                        Text(isSubmitting ? "Syncing snapshots..." : "Request Model Ingestion")
                            .font(.system(size: 13, weight: .bold))
                    }
                    .foregroundColor(.black)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(Color.summerPeach)
                    .cornerRadius(10)
                }
                .buttonStyle(PlainButtonStyle())
                .disabled(isSubmitting)
            } else {
                HStack {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundColor(.summerOrange)
                    Text("Contribution successfully queued for verification!")
                        .font(.system(size: 12, weight: .semibold))
                }
                .padding()
                .background(Color.summerPeach.opacity(0.12))
                .cornerRadius(10)
            }
            
            Spacer()
        }
        .padding(.horizontal, 20)
        .frame(width: 380, height: 420)
    }
    
    private func startContributionSubmission() {
        isSubmitting = true
        
        // Simulating upload of serialized graphs to Supabase tables
        Task {
            try? await Task.sleep(nanoseconds: 2_000_000_000) // 2s delay
            DispatchQueue.main.async {
                isSubmitting = false
                submissionComplete = true
            }
        }
    }
}
