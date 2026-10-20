import Foundation

public struct BotInspectionResult {
    public let isBot: Bool
    public let isSeoCrawler: Bool
    public let reasons: [String]
}

public enum UtilvoEdgeShield {
    public static let docsURL = "https://utilvo.com/edge-shield"
    public static let threatAPIURL = "https://utilvo.com/api/edge-shield/threats"

    public static func inspectRequest(ip: String, userAgent: String) -> BotInspectionResult {
        let uaLower = userAgent.lowercased()
        for seo in ["googlebot", "google-inspectiontool", "bingbot", "adidxbot", "applebot", "duckduckbot", "yandexbot"] {
            if uaLower.contains(seo) {
                return BotInspectionResult(isBot: false, isSeoCrawler: true, reasons: [])
            }
        }
        let cleanIP = ip.components(separatedBy: ",").first?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        var reasons: [String] = []
        if cleanIP.hasPrefix("43.13") || cleanIP.hasPrefix("43.15") || cleanIP.hasPrefix("43.16") || cleanIP.hasPrefix("43.17") || cleanIP.hasPrefix("47.74.") || cleanIP.hasPrefix("47.82.") || cleanIP.hasPrefix("101.32.") || cleanIP.hasPrefix("159.138.") {
            reasons.append("CLOUD_SCRAPER_SUBNET")
        }
        for badUA in ["cpu iphone os 13_2_3", "tokenfoundrybot", "qlyzebot", "bytespider", "petalbot", "headlesschrome"] {
            if uaLower.contains(badUA) {
                reasons.append("ROGUE_SCRAPER_USER_AGENT")
                break
            }
        }
        return BotInspectionResult(isBot: !reasons.isEmpty, isSeoCrawler: false, reasons: reasons)
    }
}
