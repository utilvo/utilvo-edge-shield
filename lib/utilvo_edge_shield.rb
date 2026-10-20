# frozen_string_literal: true

module UtilvoEdgeShield
  VERSION = "1.1.0"
  DOCS_URL = "https://utilvo.com/edge-shield"
  THREAT_API_URL = "https://utilvo.com/api/edge-shield/threats"
  CIDR_FEED_URL = "https://utilvo.com/edge-shield/ai-scrapers-cidr.txt"

  SEO_BOT_RE = /(Googlebot|Google-InspectionTool|bingbot|adidxbot|MicrosoftPreview|Applebot|DuckDuckBot|YandexBot)/i
  SUBNET_RE_1 = /^43\.(119|12[89]|1[3-6][0-9]|17[0-5])\./
  SUBNET_RE_2 = /^(47\.(74|8[289])|8\.21[79]|101\.3[23]|119\.28|124\.156|129\.226|150\.109|170\.106|149\.232|159\.138|46\.250)\./
  BAD_UA_RE = /(CPU iPhone OS 13_2_3|TokenFoundryBot|QlyzeBot|Bytespider|PetalBot|ClaudeBot|CCBot|GPTBot|HeadlessChrome)/i

  def self.inspect_request(ip, user_agent)
    ua = user_agent.to_s
    return { is_bot: false, is_seo_crawler: true, reasons: [] } if ua.match?(SEO_BOT_RE)

    clean_ip = ip.to_s.split(",").first.to_s.strip
    reasons = []
    reasons << "CLOUD_SCRAPER_SUBNET" if clean_ip.match?(SUBNET_RE_1) || clean_ip.match?(SUBNET_RE_2)
    reasons << "ROGUE_SCRAPER_USER_AGENT" if ua.match?(BAD_UA_RE)

    {
      is_bot: !reasons.empty?,
      is_seo_crawler: false,
      reasons: reasons
    }
  end

  def self.generate_cloudflare_waf_expression
    '(not cf.client.bot and (ip.src.asnum in {132203 45090 45102 37963 136907} or http.user_agent contains "CPU iPhone OS 13_2_3" or http.user_agent contains "TokenFoundryBot" or http.user_agent contains "QlyzeBot"))'
  end
end
