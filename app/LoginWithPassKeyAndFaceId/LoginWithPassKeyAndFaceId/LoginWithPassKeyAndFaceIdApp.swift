//
//  LoginWithPassKeyAndFaceIdApp.swift
//  LoginWithPassKeyAndFaceId
//
//  Created by gzonelee on 6/27/24.
//

import SwiftUI

@main
struct LoginWithPassKeyAndFaceIdApp: App {
    var body: some Scene {
        WindowGroup {
            Fido2View()
//            StartView()
        }
    }
}

struct StartView: View {
    var body: some View {
        NavigationView {
            VStack(spacing: 16) {
                NavigationLink(destination: ContentView()) {
                    Text("ContentView")
                        .foregroundStyle(.white)
                        .bold()
                        .padding()
                        .background(Color.green)
                        .cornerRadius(10)
                }
                NavigationLink(destination: Fido2View()) {
                    Text("Fido 2")
                        .foregroundStyle(.white)
                        .bold()
                        .padding()
                        .background(Color.red)
                        .cornerRadius(10)
                }
            }
        }
    }
}
