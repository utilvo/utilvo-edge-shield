//! **Utilvo EdgeShield** (`v1.1.0`) — Server firewall generator, CIDR/ASN threat
//! intelligence library (`AS132203`, `AS45102`, `AS136907`), and GA4 headless bot detector.
//!
//! Official Documentation & Live Threat DB: <https://utilvo.com/edge-shield>

/// Canonical URL for the Utilvo EdgeShield documentation and interactive log analyzer.
pub const DOCS_URL: &str = "https://utilvo.com/edge-shield";

/// Canonical URL for the self-updating JSON Threat Intelligence API.
pub const THREAT_API_URL: &str = "https://utilvo.com/api/edge-shield/threats";

/// Result of inspecting an incoming HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotInspectionResult {
    pub is_bot: bool,
    pub is_seo_crawler: bool,
    pub reasons: Vec<&'static str>,
}

/// Inspects an IPv4 address and User-Agent string to detect rotating-IP cloud scrapers
/// while whitelisting verified search engine crawlers.
pub fn inspect_request(ip: &str, user_agent: &str) -> BotInspectionResult {
    let ua_lower = user_agent.to_ascii_lowercase();
    for seo in ["googlebot", "google-inspectiontool", "bingbot", "adidxbot", "applebot", "duckduckbot", "yandexbot"] {
        if ua_lower.contains(seo) {
            return BotInspectionResult {
                is_bot: false,
                is_seo_crawler: true,
                reasons: Vec::new(),
            };
        }
    }

    let clean_ip = ip.split(',').next().unwrap_or("").trim();
    let mut reasons = Vec::new();

    if clean_ip.starts_with("43.13")
        || clean_ip.starts_with("43.15")
        || clean_ip.starts_with("43.16")
        || clean_ip.starts_with("43.17")
        || clean_ip.starts_with("47.74.")
        || clean_ip.starts_with("47.82.")
        || clean_ip.starts_with("101.32.")
        || clean_ip.starts_with("101.33.")
        || clean_ip.starts_with("159.138.")
        || clean_ip.starts_with("149.232.")
    {
        reasons.push("CLOUD_SCRAPER_SUBNET");
    }

    for bad_ua in ["cpu iphone os 13_2_3", "tokenfoundrybot", "qlyzebot", "bytespider", "petalbot", "headlesschrome"] {
        if ua_lower.contains(bad_ua) {
            reasons.push("ROGUE_SCRAPER_USER_AGENT");
            break;
        }
    }

    BotInspectionResult {
        is_bot: !reasons.is_empty(),
        is_seo_crawler: false,
        reasons,
    }
}

/// Generates a Cloudflare WAF Custom Rule expression blocking high-abuse cloud scraper ASNs.
pub fn generate_cloudflare_waf_expression() -> &'static str {
    "(not cf.client.bot and (ip.src.asnum in {132203 45090 45102 37963 136907} or http.user_agent contains \"CPU iPhone OS 13_2_3\" or http.user_agent contains \"TokenFoundryBot\" or http.user_agent contains \"QlyzeBot\"))"
}
