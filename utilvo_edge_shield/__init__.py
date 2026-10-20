"""Utilvo EdgeShield — Server firewall generator, CIDR/ASN threat feed, and GA4 bot detector."""

from __future__ import annotations
import re
from typing import Dict, List, Any

__version__ = "1.1.0"

EDGE_SHIELD_FEEDS: Dict[str, str] = {
    "docs_url": "https://utilvo.com/edge-shield",
    "installer_url": "https://utilvo.com/edge-shield/install.sh",
    "cidr_feed_url": "https://utilvo.com/edge-shield/ai-scrapers-cidr.txt",
    "threat_api_url": "https://utilvo.com/api/edge-shield/threats",
    "live_cidr_api_url": "https://utilvo.com/api/edge-shield/threats?format=cidr",
    "nginx_map_url": "https://utilvo.com/edge-shield/nginx-bot-shield.conf",
    "ga4_guard_url": "https://utilvo.com/edge-shield/ga4-bot-guard.min.js",
}

CLOUD_SCRAPER_ASNS: List[int] = [132203, 45090, 45102, 37963, 136907]

CLOUD_SCRAPER_CIDRS: List[str] = [
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
]

_SEO_BOT_RE = re.compile(
    r"(Googlebot|Google-InspectionTool|bingbot|adidxbot|MicrosoftPreview|Applebot|DuckDuckBot|YandexBot)",
    re.IGNORECASE,
)
_SUBNET_RE_1 = re.compile(r"^43\.(119|12[89]|1[3-6][0-9]|17[0-5])\.")
_SUBNET_RE_2 = re.compile(
    r"^(47\.(74|8[289])|8\.21[79]|101\.3[23]|119\.28|124\.156|129\.226|150\.109|170\.106|149\.232|159\.138|46\.250)\."
)
_BAD_UA_RE = re.compile(
    r"(CPU iPhone OS 13_2_3|TokenFoundryBot|QlyzeBot|Bytespider|PetalBot|ClaudeBot|CCBot|GPTBot|HeadlessChrome)",
    re.IGNORECASE,
)


def inspect_request(ip: str, user_agent: str) -> Dict[str, Any]:
    """Inspects an IPv4 address and User-Agent string with Safe-Harbor SEO crawler protection."""
    ua = user_agent or ""
    if _SEO_BOT_RE.search(ua):
        return {"is_bot": False, "is_seo_crawler": True, "reasons": []}

    clean_ip = (ip or "").split(",")[0].strip()
    reasons: List[str] = []
    if _SUBNET_RE_1.match(clean_ip) or _SUBNET_RE_2.match(clean_ip):
        reasons.append("CLOUD_SCRAPER_SUBNET")
    if _BAD_UA_RE.search(ua):
        reasons.append("ROGUE_SCRAPER_USER_AGENT")

    return {
        "is_bot": len(reasons) > 0,
        "is_seo_crawler": False,
        "reasons": reasons,
    }


def generate_cloudflare_waf_expression() -> str:
    """Returns a Cloudflare WAF Custom Rule expression for blocking high-abuse cloud scraper ASNs."""
    asn_list = " ".join(str(a) for a in CLOUD_SCRAPER_ASNS)
    return (
        "(not cf.client.bot and (ip.src.asnum in  + asn_list +  "
        'or http.user_agent contains "CPU iPhone OS 13_2_3" '
        'or http.user_agent contains "TokenFoundryBot" '
        'or http.user_agent contains "QlyzeBot"))'
    )
