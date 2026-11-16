// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "keychain-api",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .executable(name: "keychain-api", targets: ["KeychainAPI"])
    ],
    targets: [
        .executableTarget(
            name: "KeychainAPI",
            path: "Sources/KeychainAPI",
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Network")
            ]
        )
    ]
)
