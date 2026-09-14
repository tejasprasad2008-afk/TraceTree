import SwiftUI

struct IntakeView: View {
    @Binding var isPresented: Bool
    @Binding var selectedCommand: String?
    
    @StateObject private var ollamaHelper = OllamaHelper()
    @State private var goalText: String = ""
    
    var body: some View {
        VStack(spacing: 20) {
            // Header
            HStack {
                Text("AI Security Intake Helper")
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
            
            Text("Describe what you are trying to do with the package or project target, and Ollama will select the optimal execution parameters.")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            
            // Text Input Goal
            TextEditor(text: $goalText)
                .padding(8)
                .background(Color.secondary.opacity(0.08))
                .cornerRadius(10)
                .frame(height: 100)
                .font(.system(size: 12))
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(Color.summerPeach.opacity(0.5), lineWidth: 1)
                )
            
            if !ollamaHelper.isProcessing && ollamaHelper.recommendation == nil {
                Button(action: askOllama) {
                    Text("Analyze with local Ollama")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.black)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                        .background(goalText.isEmpty ? Color.secondary.opacity(0.15) : Color.summerPeach)
                        .cornerRadius(10)
                }
                .buttonStyle(PlainButtonStyle())
                .disabled(goalText.isEmpty)
            }
            
            // Processing state
            if ollamaHelper.isProcessing {
                VStack(spacing: 12) {
                    ProgressView()
                        .controlSize(.small)
                    Text("Consulting local Qwen model...")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                .frame(height: 80)
            }
            
            // Recommendation result
            if let rec = ollamaHelper.recommendation {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Image(systemName: "lightbulb.fill")
                            .foregroundColor(.yellow)
                        Text("Recommended Action: \(rec.command.uppercased())")
                            .font(.system(size: 12, weight: .bold))
                    }
                    
                    Text(rec.explanation)
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                        .lineSpacing(2)
                    
                    HStack(spacing: 12) {
                        Button(action: {
                            selectedCommand = rec.command.lowercased()
                            isPresented = false
                        }) {
                            Text("Use Preferred Option")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.black)
                                .padding(.horizontal, 16)
                                .padding(.vertical, 8)
                                .background(Color.summerOrange)
                                .cornerRadius(8)
                        }
                        .buttonStyle(PlainButtonStyle())
                        
                        Button(action: { isPresented = false }) {
                            Text("Do Something Else")
                                .font(.system(size: 12))
                                .foregroundColor(.primary)
                                .padding(.horizontal, 16)
                                .padding(.vertical, 8)
                                .background(Color.secondary.opacity(0.12))
                                .cornerRadius(8)
                        }
                        .buttonStyle(PlainButtonStyle())
                    }
                    .padding(.top, 4)
                }
                .padding()
                .background(Color.white.opacity(0.04))
                .cornerRadius(12)
            }
            
            if let err = ollamaHelper.errorMessage {
                Text(err)
                    .font(.system(size: 11))
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
            }
            
            Spacer()
        }
        .padding(.horizontal, 20)
        .frame(width: 380, height: 420)
    }
    
    private func askOllama() {
        Task {
            await ollamaHelper.parseUserGoal(goalText)
        }
    }
}
