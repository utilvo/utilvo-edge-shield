# Changelog

## 1.1.0 - 2026-10-20

- Added live Threat Intelligence Database API (`https://utilvo.com/api/edge-shield/threats`) with RFC 4632 CIDR and Nginx map feed formats.
- Added Safe-Harbor Community Bot Reporting verification rules protecting Googlebot (`66.249.64.0/19`), Bingbot, Applebot, DuckDuckBot, and Cloudflare Edge proxies (`172.64.0.0/13`, `104.16.0.0/12`).
- Added automated daily cron sync support (`/etc/cron.daily/utilvo-edge-shield-sync`) with `nginx -t` validation and rollback.

## 1.0.0 - 2026-10-20

- Initial release of `utilvo-edge-shield` across server WAF generators, ASN/CIDR blocklists (`AS132203`, `AS45102`, `AS136907`), and WebGL headless GA4 bot detection.
