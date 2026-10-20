/**
 * @module
 * **Utilvo EdgeShield** (`@utilvo/edge-shield` v1.1.0) — Open-source server firewall generator,
 * self-updating CIDR/ASN threat intelligence feed, Safe-Harbor community reporting API client,
 * and browser WebGL headless bot detector.
 *
 * Designed to block rotating-IP cloud scrapers (`AS132203` Tencent Cloud, `AS45102` Alibaba Cloud,
 * `AS136907` Huawei Cloud) and prevent headless Chromium clusters from polluting Google Analytics 4
 * (`gtag.js`) with fake Singapore/Cloud sessions while preserving 100% SEO crawler compatibility.
 *
 * Canonical Documentation & Live Threat Feeds: https://utilvo.com/edge-shield
 */

/**
 * Metadata and canonical feed endpoints for Utilvo EdgeShield v1.1.0.
 */
export interface EdgeShieldFeedUrls {
  /** Official documentation and interactive access.log analyzer. */
  readonly docsUrl: string;
  /** Safe 1-line Linux Nginx installer with automatic nginx -t rollback & daily auto-sync. */
  readonly installerUrl: string;
  /** RFC 4632 CIDR blocklist feed for Fail2Ban, CrowdSec, UFW, and ipset. */
  readonly cidrFeedUrl: string;
  /** Live JSON Threat Intelligence API & Safe-Harbor Community Reporting endpoint. */
  readonly threatApiUrl: string;
  /** Dynamic plain-text CIDR feed synced from the Live Threat DB API. */
  readonly liveCidrApiUrl: string;
  /** Zero-conflict Nginx http {} map configuration file. */
  readonly nginxMapUrl: string;
  /** Client-side WebGL & OS-mismatch GA4 bot guard script. */
  readonly ga4GuardUrl: string;
}

/**
 * Canonical URLs for live Utilvo EdgeShield threat intelligence feeds.
 */
export const EDGE_SHIELD_FEEDS: EdgeShieldFeedUrls = {
  docsUrl: "https://utilvo.com/edge-shield",
  installerUrl: "https://utilvo.com/edge-shield/install.sh",
  cidrFeedUrl: "https://utilvo.com/edge-shield/ai-scrapers-cidr.txt",
  threatApiUrl: "https://utilvo.com/api/edge-shield/threats",
  liveCidrApiUrl: "https://utilvo.com/api/edge-shield/threats?format=cidr",
  nginxMapUrl: "https://utilvo.com/edge-shield/nginx-bot-shield.conf",
  ga4GuardUrl: "https://utilvo.com/edge-shield/ga4-bot-guard.min.js",
};

/**
 * Autonomous System Numbers (ASNs) operated by high-abuse rotating cloud scrapers.
 */
export const CLOUD_SCRAPER_ASNS: readonly number[] = [
  132203, // Tencent Cloud (SG / HK / Global)
  45090,  // Tencent Cloud China
  45102,  // Alibaba Cloud (US / SG / HK)
  37963,  // Alibaba Cloud China
  136907, // Huawei Cloud Service
];

/**
 * Verified CIDR subnets actively used by rotating-IP headless Chromium scrapers.
 */
export const CLOUD_SCRAPER_CIDRS: readonly string[] = [
  "43.128.0.0/10",
  "101.32.0.0/15",
  "119.28.0.0/16",
  "124.156.0.0/16",
  "129.226.0.0/16",
  "150.109.0.0/16",
  "170.106.0.0/16",
  "43.119.0.0/16",
  "47.74.0.0/16",
  "47.82.0.0/16",
  "47.88.0.0/15",
  "8.217.0.0/16",
  "8.219.0.0/16",
  "46.250.0.0/16",
  "149.232.0.0/16",
  "159.138.0.0/16",
];

/**
 * Result of evaluating an incoming HTTP request or browser environment.
 */
export interface BotInspectionResult {
  /** True if the request or runtime matches a cloud scraper or headless browser. */
  readonly isBot: boolean;
  /** Matched threat reason codes, or empty array if clean. */
  readonly reasons: readonly string[];
}

/**
 * Inspects an IPv4 address and User-Agent string on the server/edge to identify
 * rotating-IP cloud scrapers while whitelisting Googlebot, Bingbot, and Applebot.
 *
 * @param ip Client IPv4 address (from CF-Connecting-IP or X-Forwarded-For).
 * @param userAgent HTTP User-Agent header string.
 * @returns Inspection result indicating whether the request should be blocked.
 */
export function inspectServerRequest(ip: string, userAgent: string): BotInspectionResult {
  if (/(Googlebot|Google-InspectionTool|bingbot|adidxbot|MicrosoftPreview|Applebot|DuckDuckBot|YandexBot)/i.test(userAgent)) {
    return { isBot: false, reasons: [] };
  }

  const reasons: string[] = [];
  const cleanIp = ip.split(",")[0].trim();

  if (
    /^43\.(119|12[89]|1[3-6][0-9]|17[0-5])\./.test(cleanIp) ||
    /^(47\.(74|8[289])|8\.21[79]|101\.3[23]|119\.28|124\.156|129\.226|150\.109|170\.106|149\.232|159\.138|46\.250)\./.test(cleanIp)
  ) {
    reasons.push("CLOUD_SCRAPER_SUBNET");
  }

  if (/(CPU iPhone OS 13_2_3|TokenFoundryBot|QlyzeBot|Bytespider|PetalBot|ClaudeBot|CCBot|GPTBot|HeadlessChrome)/i.test(userAgent)) {
    reasons.push("ROGUE_SCRAPER_USER_AGENT");
  }

  return {
    isBot: reasons.length > 0,
    reasons,
  };
}

/**
 * Generates a ready-to-deploy Cloudflare WAF Custom Rule expression that blocks
 * cloud scraper ASNs and spoofed mobile emulator User-Agents without affecting verified bots.
 *
 * @returns Cloudflare WAF rule expression string.
 */
export function generateCloudflareWafExpression(): string {
  const asnList = CLOUD_SCRAPER_ASNS.join(" ");
  return `(not cf.client.bot and (ip.src.asnum in {${asnList}} or http.user_agent contains "CPU iPhone OS 13_2_3" or http.user_agent contains "TokenFoundryBot" or http.user_agent contains "QlyzeBot"))`;
}
