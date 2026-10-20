export const EDGE_SHIELD_FEEDS = {
  docsUrl: "https://utilvo.com/edge-shield",
  installerUrl: "https://utilvo.com/edge-shield/install.sh",
  cidrFeedUrl: "https://utilvo.com/edge-shield/ai-scrapers-cidr.txt",
  threatApiUrl: "https://utilvo.com/api/edge-shield/threats",
  liveCidrApiUrl: "https://utilvo.com/api/edge-shield/threats?format=cidr",
  nginxMapUrl: "https://utilvo.com/edge-shield/nginx-bot-shield.conf",
  ga4GuardUrl: "https://utilvo.com/edge-shield/ga4-bot-guard.min.js",
};

export const CLOUD_SCRAPER_ASNS = [132203, 45090, 45102, 37963, 136907];

export const CLOUD_SCRAPER_CIDRS = [
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

const SEO_BOT_RE = /(Googlebot|Google-InspectionTool|bingbot|adidxbot|MicrosoftPreview|Applebot|DuckDuckBot|YandexBot)/i;
const SUBNET_RE_1 = /^43\.(119|12[89]|1[3-6][0-9]|17[0-5])\./;
const SUBNET_RE_2 = /^(47\.(74|8[289])|8\.21[79]|101\.3[23]|119\.28|124\.156|129\.226|150\.109|170\.106|149\.232|159\.138|46\.250)\./;
const BAD_UA_RE = /(CPU iPhone OS 13_2_3|TokenFoundryBot|QlyzeBot|Bytespider|PetalBot|ClaudeBot|CCBot|GPTBot|HeadlessChrome)/i;

export function inspectServerRequest(ip, userAgent) {
  const ua = String(userAgent || "");
  if (SEO_BOT_RE.test(ua)) {
    return { isBot: false, isSeoCrawler: true, reasons: [] };
  }
  const cleanIp = String(ip || "").split(",")[0].trim();
  const reasons = [];
  if (SUBNET_RE_1.test(cleanIp) || SUBNET_RE_2.test(cleanIp)) {
    reasons.push("CLOUD_SCRAPER_SUBNET");
  }
  if (BAD_UA_RE.test(ua)) {
    reasons.push("ROGUE_SCRAPER_USER_AGENT");
  }
  return {
    isBot: reasons.length > 0,
    isSeoCrawler: false,
    reasons,
  };
}

export function generateCloudflareWafExpression() {
  return `(not cf.client.bot and (ip.src.asnum in {${CLOUD_SCRAPER_ASNS.join(" ")}} or http.user_agent contains "CPU iPhone OS 13_2_3" or http.user_agent contains "TokenFoundryBot" or http.user_agent contains "QlyzeBot"))`;
}
