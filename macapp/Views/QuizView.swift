import SwiftUI

struct QuizQuestion {
    let id: String
    let text: String
    let options: [String]
}

struct QuizView: View {
    @EnvironmentObject var authManager: SupabaseAuthManager
    @State private var currentQuestionIndex = 0
    @State private var selectedAnswers: [String: String] = [:]
    
    let questions = [
        QuizQuestion(
            id: "role",
            text: "What is your primary security role?",
            options: ["Developer", "Security Analyst", "DevOps Engineer", "Hobbyist"]
        ),
        QuizQuestion(
            id: "targets",
            text: "Which target environments do you analyze most?",
            options: ["Python Packages", "NPM Packages", "DMG / EXE Installers", "Cross-Platform / All"]
        ),
        QuizQuestion(
            id: "ollama",
            text: "Do you run local GPU models (Ollama)?",
            options: ["Yes, regularly", "No, but interested", "Not planned / CPU only"]
        ),
        QuizQuestion(
            id: "mode",
            text: "What is your preferred scan latency target?",
            options: ["Sub-second static signatures", "15–30s sandbox profiling", "1 min+ dynamic & AI jury validation"]
        ),
        QuizQuestion(
            id: "policy",
            text: "What is your target tracking policy?",
            options: ["Audit behavior and alert", "Block executing hosts in container", "Log execution trace only"]
        )
    ]
    
    var body: some View {
        VStack(spacing: 24) {
            // Header Progress
            VStack(spacing: 8) {
                HStack {
                    Text("Personalize TraceTree")
                        .font(.headline)
                        .foregroundColor(.summerOrange)
                    Spacer()
                    Text("Question \(currentQuestionIndex + 1) of \(questions.count)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                // Progress Bar
                ProgressView(value: Double(currentQuestionIndex + 1), total: Double(questions.count))
                    .accentColor(.summerOrange)
            }
            .padding(.top, 40)
            .padding(.horizontal, 24)
            
            // Question Card
            VStack(alignment: .leading, spacing: 20) {
                Text(questions[currentQuestionIndex].text)
                    .font(.system(size: 20, weight: .semibold, design: .rounded))
                    .foregroundColor(.primary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.bottom, 10)
                
                // Option Selection List
                ForEach(questions[currentQuestionIndex].options, id: \.self) { option in
                    Button(action: {
                        selectedAnswers[questions[currentQuestionIndex].id] = option
                        nextQuestion()
                    }) {
                        HStack {
                            Text(option)
                                .font(.body)
                                .foregroundColor(.primary)
                            Spacer()
                            if selectedAnswers[questions[currentQuestionIndex].id] == option {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.summerOrange)
                            } else {
                                Image(systemName: "circle")
                                    .foregroundColor(.secondary)
                            }
                        }
                        .padding()
                        .background(Color.secondary.opacity(0.08))
                        .cornerRadius(10)
                    }
                    .buttonStyle(PlainButtonStyle())
                }
            }
            .padding(24)
            .background(Color.white.opacity(0.05))
            .cornerRadius(16)
            .padding(.horizontal, 24)
            
            Spacer()
            
            // Footer Navigation
            HStack {
                if currentQuestionIndex > 0 {
                    Button("Back") {
                        currentQuestionIndex -= 1
                    }
                    .buttonStyle(.borderless)
                    .foregroundColor(.secondary)
                }
                Spacer()
            }
            .padding(.horizontal, 28)
            .padding(.bottom, 40)
        }
    }
    
    private func nextQuestion() {
        if currentQuestionIndex < questions.count - 1 {
            currentQuestionIndex += 1
        } else {
            // Save results to auth manager
            authManager.saveQuizAnswers(selectedAnswers)
        }
    }
}
