import SwiftUI
import AuthenticationServices

class Fido2ViewModel: NSObject, ObservableObject {
    private let apiBaseUrl = "https://funky-largely-ewe.ngrok-free.app"
    
    func startRegistration() {
        let userId = "user123" // 실제 사용자 ID 사용
        guard let url = URL(string: apiBaseUrl + "/registerRequest") else { return }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["userId": userId], options: [])

        URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data else { return }
            guard let registrationOptions = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else { return }

            guard let challengeBase64 = registrationOptions["challenge"] as? String,
                  let challenge = Data(base64Encoded: challengeBase64),
                  let rpId = (registrationOptions["rp"] as? [String: String])?["id"] else {
                return
            }
            guard let userDic = registrationOptions["user"] as? [String: Any],
                    let idDic = userDic["id"] as? [String: Any],
                    let data = idDic["data"],
                    let bytes = data as? [UInt8] else {
                return
            }
            let userIdData = Data(bytes)
            GZLogFunc(challengeBase64)
            GZLogFunc(userIdData)

            let publicKeyCredentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
            let authRequest = publicKeyCredentialProvider.createCredentialRegistrationRequest(challenge: challenge, name: userId, userID: userIdData)

            let authController = ASAuthorizationController(authorizationRequests: [authRequest])
            authController.delegate = self
            authController.presentationContextProvider = self
            authController.performRequests()
        }.resume()
    }

    func startAuthentication() {
        let userId = "user123" // 실제 사용자 ID 사용
        guard let url = URL(string: apiBaseUrl + "/authRequest") else { return }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["userId": userId], options: [])

        URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data else { return }
            guard let assertionOptions = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else { return }

            let challenge = Data(base64Encoded: assertionOptions["challenge"] as! String)!
            let rpId = assertionOptions["rpId"] as! String

            let publicKeyCredentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
            let authRequest = publicKeyCredentialProvider.createCredentialAssertionRequest(challenge: challenge)

            let authController = ASAuthorizationController(authorizationRequests: [authRequest])
            authController.delegate = self
            authController.presentationContextProvider = self
            authController.performRequests()
        }.resume()
    }
}

extension Fido2ViewModel: ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let credentialRegistration = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            let attestationObject = credentialRegistration.rawAttestationObject
            let clientDataJSON = credentialRegistration.rawClientDataJSON
            let credentialID = credentialRegistration.credentialID
            GZLogFunc(attestationObject?.string)
            GZLogFunc(clientDataJSON.string)
            let c = clientDataJSON.decode(ClientJSON.self)
            GZLogFunc(c?.challenge.base64UrlToBase64)

            let userId = "user123" // 실제 사용자 ID 사용
            guard let url = URL(string: apiBaseUrl + "/registerResponse") else { return }

            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let body: [String: Any] = [
                "userId": userId,
                "response": [
                    "clientDataJSON": clientDataJSON.base64EncodedString(),
                    "attestationObject": attestationObject?.base64EncodedString() ?? ""
                ],
                "id": credentialID.base64EncodedString(),
                "rawId": credentialID.base64EncodedString()
            ]
            request.httpBody = try? JSONSerialization.data(withJSONObject: body, options: [])

            URLSession.shared.dataTask(with: request) { data, response, error in
                if let error = error {
                    print("Error: \(error)")
                    return
                }
                GZLogFunc("User successfully registered")
            }.resume()
        } else if let credentialAssertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            let authenticatorData = credentialAssertion.rawAuthenticatorData
            let clientDataJSON = credentialAssertion.rawClientDataJSON
            let signature = credentialAssertion.signature
            let credentialID = credentialAssertion.credentialID

            let userId = "user123" // 실제 사용자 ID 사용
            guard let url = URL(string: apiBaseUrl + "/authResponse") else { return }

            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let body: [String: Any] = [
                "userId": userId,
                "response": [
                    "authenticatorData": authenticatorData?.base64EncodedString() ?? "",
                    "clientDataJSON": clientDataJSON.base64EncodedString(),
                    "signature": signature?.base64EncodedString() ?? ""
                ],
                "id": credentialID.base64EncodedString(),
                "rawId": credentialID.base64EncodedString()
            ]
            request.httpBody = try? JSONSerialization.data(withJSONObject: body, options: [])

            URLSession.shared.dataTask(with: request) { data, response, error in
                GZLogFunc(response)
                if let error = error {
                    print("Error: \(error)")
                    return
                }
                GZLogFunc("User successfully authenticated")
            }.resume()
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        print("Error: \(error)")
    }
}

extension Fido2ViewModel: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return UIApplication.shared.windows.first!
    }
}


extension Data {
    var base64: String {
        return base64EncodedString()
    }
    var string: String? {
        return String(data: self, encoding: .utf8)
    }
    
    // data to codable
    func decode<T: Codable>(_ type: T.Type) -> T? {
        return try? JSONDecoder().decode(type, from: self)
    }
}

struct ClientJSON: Codable {
    let challenge: String
    let origin: String
    let type: String
}

extension String {
    // base64url to base64
    var base64UrlToBase64: String? {
        let padding = String(repeating: "=", count: (4 - count % 4) % 4)
        let base64 = replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + padding
        return base64
    }
}
