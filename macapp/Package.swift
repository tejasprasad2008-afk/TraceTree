// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "TraceTree",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "TraceTree",
            path: ".",
            sources: ["TraceTreeApp.swift", "Models", "Views"],
            swiftSettings: [.unsafeFlags(["-parse-as-library"])]
        )
    ]
)
