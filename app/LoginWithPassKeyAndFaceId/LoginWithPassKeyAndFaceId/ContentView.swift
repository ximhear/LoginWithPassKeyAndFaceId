//
//  ContentView.swift
//  LoginWithPassKeyAndFaceId
//
//  Created by gzonelee on 6/27/24.
//

import SwiftUI
import AuthenticationServices
import LocalAuthentication
import Combine

struct ContentView: View {
    @StateObject private var viewModel = AuthViewModel()
    
    var body: some View {
        VStack {
            if viewModel.isAuthenticated {
                Text("Welcome!")
                VStack {
                    if let accessToken = viewModel.accessToken {
                        Text("Access Token: \(accessToken)")
                            .foregroundStyle(.red)
                    }
                    if let refreshToken = viewModel.refreshToken {
                        Text("Refresh Token: \(refreshToken)")
                            .foregroundStyle(.blue)
                    }
                }
            } else {
                Text("Please log in")
            }
            Button("Register PassKey") {
                viewModel.registerPassKey(userID: viewModel.userId)
            }
            .frame(width: 280, height: 45)
            .background(Color.blue)
            .foregroundColor(.white)
            .cornerRadius(10)
            .padding(.bottom, 20)
            
            Button("Authenticate with PassKey") {
                viewModel.authenticateWithPassKey(userID: viewModel.userId)
            }
            .frame(width: 280, height: 45)
            .background(Color.green)
            .foregroundColor(.white)
            .cornerRadius(10)
            .padding(.bottom, 20)
            
            Button("Authenticate with Face ID") {
                viewModel.authenticateWithFaceID()
            }
            .frame(width: 280, height: 45)
            .background(Color.red)
            .foregroundColor(.white)
            .cornerRadius(10)
        }
        .onAppear {
//            viewModel.checkAuthentication()
        }
    }
}

class AuthViewModel: NSObject, ObservableObject {
    @Published var isAuthenticated = false
    private var cancellables = Set<AnyCancellable>()
    private var baseApiUrl = "https://funky-largely-ewe.ngrok-free.app"
    let userId = "user3"
    
    var accessToken: String? {
        get { UserDefaults.standard.string(forKey: "accessToken") }
        set { UserDefaults.standard.setValue(newValue, forKey: "accessToken") }
    }
    
    var refreshToken: String? {
        get { UserDefaults.standard.string(forKey: "refreshToken") }
        set { UserDefaults.standard.setValue(newValue, forKey: "refreshToken") }
    }

    func registerPassKey(userID: String) {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "eng-rc-server.vercel.app")
        let challenge = "example_challenge".data(using: .utf8)!
        
        let registrationRequest = provider.createCredentialRegistrationRequest(challenge: challenge, name: userId, userID: userID.data(using: .utf8)!)
        let controller = ASAuthorizationController(authorizationRequests: [registrationRequest])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }

    func authenticateWithPassKey(userID: String) {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "eng-rc-server.vercel.app")
        let challenge = "example_challenge11".data(using: .utf8)!
        
        let authenticationRequest = provider.createCredentialAssertionRequest(challenge: challenge)
        let controller = ASAuthorizationController(authorizationRequests: [authenticationRequest])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }

    func authenticateWithFaceID() {
        let context = LAContext()
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Log in with Face ID") { success, error in
                DispatchQueue.main.async {
                    if success {
                        self.refreshTokenIfNeeded()
                    } else {
                        print("Authentication failed: \(error?.localizedDescription ?? "Unknown error")")
                    }
                }
            }
        } else {
            print("Biometrics not available: \(error?.localizedDescription ?? "Unknown error")")
        }
    }

    func refreshTokenIfNeeded() {
        GZLogFunc()
        guard let refreshToken = refreshToken else {
            self.isAuthenticated = false
            return
        }

        guard let url = URL(string: baseApiUrl + "/refresh") else { return }
        GZLogFunc()
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: Any] = [
            "refreshToken": refreshToken
        ]

        request.httpBody = try? JSONSerialization.data(withJSONObject: body, options: [])
        GZLogFunc()

        URLSession.shared.dataTaskPublisher(for: request)
            .tryMap { data, response -> AuthResponse in
                GZLogFunc()
                guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                    throw URLError(.badServerResponse)
                }
                let decodedResponse = try JSONDecoder().decode(AuthResponse.self, from: data)
                return decodedResponse
            }
            .receive(on: DispatchQueue.main)
            .sink(receiveCompletion: { completion in
                GZLogFunc()
                if case let .failure(error) = completion {
                    print("Error refreshing token: \(error.localizedDescription)")
                    self.isAuthenticated = false
                }
            }, receiveValue: { [weak self] response in
                GZLogFunc()
                self?.accessToken = response.accessToken
                self?.refreshToken = response.refreshToken
                self?.isAuthenticated = true
            })
            .store(in: &cancellables)
    }

    func checkAuthentication() {
        if accessToken != nil {
            authenticateWithFaceID()
        }
    }
}

extension AuthViewModel: ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let credentialRegistration = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            GZLogFunc("PassKey registration successful")
            
            // 서버로 PassKey 데이터 전송
            let userID = userId
            let rawID = credentialRegistration.credentialID
            let attestationObject = credentialRegistration.rawAttestationObject
            let clientDataJSON = credentialRegistration.rawClientDataJSON
            
            sendRegistrationDataToServer(userID: userID, rawID: rawID, attestationObject: attestationObject, clientDataJSON: clientDataJSON)
        } else if let credentialAssertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            GZLogFunc("PassKey authentication successful")
            
            // PassKey 인증 성공 시 서버로 데이터 전송
            let userID = userId
            let rawID = credentialAssertion.credentialID
            let authenticatorData = credentialAssertion.rawAuthenticatorData
            let clientDataJSON = credentialAssertion.rawClientDataJSON
            let signature = credentialAssertion.signature
            
            sendAuthenticationDataToServer(userID: userID, rawID: rawID, authenticatorData: authenticatorData, clientDataJSON: clientDataJSON, signature: signature)
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        print("Authorization failed: \(error.localizedDescription)")
    }
    
    private func sendRegistrationDataToServer(userID: String, rawID: Data, attestationObject: Data?, clientDataJSON: Data) {
        guard let url = URL(string: baseApiUrl + "/register-passkey") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        var body: [String: Any] = [
            "userID": userID,
            "rawID": rawID.base64EncodedString(),
            "clientDataJSON": clientDataJSON.base64EncodedString()
        ]
        if let attestationObject = attestationObject {
            body["attestationObject"] = attestationObject.base64EncodedString()
        }

        request.httpBody = try? JSONSerialization.data(withJSONObject: body, options: [])

        URLSession.shared.dataTask(with: request) { data, response, error in
            GZLogFunc(response)
            if let error = error {
                print("Error sending registration data to server: \(error)")
                return
            }

            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                print("Error: invalid response from server")
                return
            }

            print("Registration data successfully sent to server")
        }.resume()
    }
    
    private func sendAuthenticationDataToServer(userID: String, rawID: Data, authenticatorData: Data?, clientDataJSON: Data, signature: Data?) {
        GZLogFunc()
        guard let url = URL(string: baseApiUrl + "/authenticate-passkey") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        var body: [String: Any] = [
            "userID": userID,
            "rawID": rawID.base64EncodedString(),
            "clientDataJSON": clientDataJSON.base64EncodedString()
        ]
        
        if let signature = signature {
            body["signature"] = signature.base64EncodedString()
        }
        if let authenticatorData = authenticatorData {
            body["authenticatorData"] = authenticatorData.base64EncodedString()
        }

        request.httpBody = try? JSONSerialization.data(withJSONObject: body, options: [])

        URLSession.shared.dataTaskPublisher(for: request)
            .tryMap { data, response -> AuthResponse in
                guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                    throw URLError(.badServerResponse)
                }
                let decodedResponse = try JSONDecoder().decode(AuthResponse.self, from: data)
                return decodedResponse
            }
            .receive(on: DispatchQueue.main)
            .sink(receiveCompletion: { completion in
                if case let .failure(error) = completion {
                    print("Error refreshing token: \(error.localizedDescription)")
                    self.isAuthenticated = false
                }
            }, receiveValue: { [weak self] response in
                self?.accessToken = response.accessToken
                self?.refreshToken = response.refreshToken
                self?.isAuthenticated = true
            })
            .store(in: &cancellables)
    }
}

extension AuthViewModel: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return UIApplication.shared.connectedScenes
                    .compactMap { $0 as? UIWindowScene }
                    .flatMap { $0.windows }
                    .first { $0.isKeyWindow }!
    }
}

struct AuthResponse: Decodable {
    let accessToken: String
    let refreshToken: String
}
