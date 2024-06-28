//
//  Fido2View.swift
//  LoginWithPassKeyAndFaceId
//
//  Created by gzonelee on 6/27/24.
//

import SwiftUI
import AuthenticationServices

struct Fido2View: View {
    @StateObject private var viewModel = Fido2ViewModel()

    var body: some View {
        VStack {
            Button(action: {
                viewModel.startRegistration()
            }) {
                Text("Register with FIDO2")
                    .frame(width: 280, height: 45)
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(10)
            }
            
            Button(action: {
                viewModel.startAuthentication()
            }) {
                Text("Authenticate with FIDO2")
                    .frame(width: 280, height: 45)
                    .background(Color.green)
                    .foregroundColor(.white)
                    .cornerRadius(10)
            }
        }
    }
}

#Preview {
    Fido2View()
}
