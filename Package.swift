// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "UtilvoEdgeShield",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .tvOS(.v13),
        .watchOS(.v6)
    ],
    products: [
        .library(
            name: "UtilvoEdgeShield",
            targets: ["UtilvoEdgeShield"]
        ),
    ],
    targets: [
        .target(
            name: "UtilvoEdgeShield",
            dependencies: [],
            path: "Sources/UtilvoEdgeShield"
        ),
    ]
)
