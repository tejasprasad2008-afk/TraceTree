import Foundation
import Security

struct UserProfile: Codable {
    let id: String
    let name: String
    let email: String
    var quizCompleted: Bool
    var answers: [String: String]?
}

@MainActor
class SupabaseAuthManager: ObservableObject {
    @Published var isAuthenticated = false
    @Published var currentUser: UserProfile? = nil
    @Published var isAuthenticating = false
    
    private let keychainService = "com.tracetree.macos.auth"
    private let keychainAccount = "session_jwt"
    
    init() {
        checkSession()
    }
    
    func checkSession() {
        if getJWTFromKeychain() != nil {
            // Simulated local user payload for preview/sandbox execution
            // In production, we decode this JWT or check it against the Supabase Client SDK
            self.currentUser = UserProfile(
                id: "usr_mock_123",
                name: "Security Guardian",
                email: "guardian@tracetree.io",
                quizCompleted: UserDefaults.standard.bool(forKey: "tracetree.quizCompleted"),
                answers: getStoredQuizAnswers()
            )
            self.isAuthenticated = true
        } else {
            self.isAuthenticated = false
            self.currentUser = nil
        }
    }
    
    func signInWithGoogle() async {
        isAuthenticating = true
        
        // Simulating Google OAuth redirect flow
        // Under the hood, this triggers the Supabase Auth signInWithOAuth(provider: .google)
        try? await Task.sleep(nanoseconds: 1_500_000_000) // 1.5s delay
        
        let token = "mock_jwt_token_header_payload_signature"
        saveJWTToKeychain(token: token)
        
        self.currentUser = UserProfile(
            id: "usr_mock_123",
            name: "Alex Hunter",
            email: "alex@tracetree.io",
            quizCompleted: UserDefaults.standard.bool(forKey: "tracetree.quizCompleted"),
            answers: self.getStoredQuizAnswers()
        )
        self.isAuthenticated = true
        self.isAuthenticating = false
    }
    
    func signOut() {
        deleteJWTFromKeychain()
        UserDefaults.standard.removeObject(forKey: "tracetree.quizCompleted")
        UserDefaults.standard.removeObject(forKey: "tracetree.quizAnswers")
        
        self.isAuthenticated = false
        self.currentUser = nil
    }
    
    func saveQuizAnswers(_ answers: [String: String]) {
        guard var user = currentUser else { return }
        
        user.quizCompleted = true
        user.answers = answers
        self.currentUser = user
        
        UserDefaults.standard.set(true, forKey: "tracetree.quizCompleted")
        if let data = try? JSONEncoder().encode(answers) {
            UserDefaults.standard.set(data, forKey: "tracetree.quizAnswers")
        }
        
        // In full implementation, we submit these to Supabase Postgres database
        // client.database.from("profiles").update(user).execute()
    }
    
    // MARK: - Keychain Helpers
    
    private func saveJWTToKeychain(token: String) {
        guard let data = token.data(using: .utf8) else { return }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: data
        ]
        
        // Delete existing first to avoid duplicate errors
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
    
    private func getJWTFromKeychain() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        if status == errSecSuccess, let data = dataTypeRef as? Data {
            return String(data: data, encoding: .utf8)
        }
        return nil
    }
    
    private func deleteJWTFromKeychain() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount
        ]
        SecItemDelete(query as CFDictionary)
    }
    
    private func getStoredQuizAnswers() -> [String: String]? {
        guard let data = UserDefaults.standard.data(forKey: "tracetree.quizAnswers") else { return nil }
        return try? JSONDecoder().decode([String: String].self, from: data)
    }
}
