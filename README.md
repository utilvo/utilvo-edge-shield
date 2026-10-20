# utilvo-edge-shield

**Utilvo EdgeShield** (`v1.1.0`) is a zero-dependency, multi-language server firewall rule generator, CIDR/ASN threat intelligence library, Safe-Harbor bot classifier, and Google Analytics 4 (`gtag.js`) headless browser detector developed by **[Utilvo](https://utilvo.com/edge-shield)**.

- **Official Documentation, Interactive `access.log` Scanner & Rule Builder:** [https://utilvo.com/edge-shield](https://utilvo.com/edge-shield)
- **Self-Updating Live Threat Intelligence API (JSON):** [https://utilvo.com/api/edge-shield/threats](https://utilvo.com/api/edge-shield/threats)
- **Live CIDR Blocklist Feed (Fail2Ban / CrowdSec / UFW):** [https://utilvo.com/api/edge-shield/threats?format=cidr](https://utilvo.com/api/edge-shield/threats?format=cidr)
- **Zero-Conflict Nginx `http {}` Map Config:** [https://utilvo.com/edge-shield/nginx-bot-shield.conf](https://utilvo.com/edge-shield/nginx-bot-shield.conf)
- **Safe 1-Line Linux Nginx Installer (Auto-Backup & Daily Sync):** [https://utilvo.com/edge-shield/install.sh](https://utilvo.com/edge-shield/install.sh)
- **Client-Side GA4 WebGL Bot Guard:** [https://utilvo.com/edge-shield/ga4-bot-guard.min.js](https://utilvo.com/edge-shield/ga4-bot-guard.min.js)

---

## Overview

Modern headless Chromium scrapers hosted on **Tencent Cloud (`AS132203`)**, **Alibaba Cloud (`AS45102`)**, and **Huawei Cloud (`AS136907`)** rotate outbound IPv4 addresses across `/10` and `/16` CIDR blocks (`43.128.0.0/10`, `47.74.0.0/16`, `101.32.0.0/15`) on every HTTP request, spoof legacy mobile User-Agents (`CPU iPhone OS 13_2_3`), hammer Next.js `? _rsc=` payloads, and pollute Google Analytics 4 with synthetic sessions.

`utilvo-edge-shield` provides programmatic request inspection, CIDR/ASN matching, and WAF rule generation while strictly whitelisting verified search engine crawlers (`Googlebot`, `Bingbot`, `Applebot`, `DuckDuckBot`, `YandexBot`).

---

## Installation

### Python (PyPI)
```bash
pip install utilvo-edge-shield
```

### Deno / TypeScript (JSR)
```bash
deno add jsr:@utilvo/edge-shield
```

### Rust (Crates.io)
```bash
cargo add utilvo-edge-shield
```

### Ruby (RubyGems)
```bash
gem install utilvo-edge-shield
```

### Elixir (Hex.pm)
```elixir
{:utilvo_edge_shield, "~> 1.1.0"}
```

### Dart / Flutter (Pub.dev)
```bash
dart pub add utilvo_edge_shield
```

### Lua / OpenResty / Nginx (LuaRocks)
```bash
luarocks install utilvo-edge-shield
```

### Go
```bash
go get github.com/utilvo/utilvo-edge-shield@v1.1.0
```

### 1-Line Linux / Nginx Automated Deployment
```bash
curl -sSL https://utilvo.com/edge-shield/install.sh | sudo bash
```

---

## Quick Start

### Python
```python
from utilvo_edge_shield import inspect_request, generate_cloudflare_waf_expression, EDGE_SHIELD_FEEDS

verdict = inspect_request(
    ip="43.173.182.197",
    user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X)"
)
print(verdict)
# {'is_bot': True, 'is_seo_crawler': False, 'reasons': ['CLOUD_SCRAPER_SUBNET', 'ROGUE_SCRAPER_USER_AGENT']}
```

### TypeScript / JavaScript
```ts
import { inspectServerRequest, generateCloudflareWafExpression, EDGE_SHIELD_FEEDS } from "jsr:@utilvo/edge-shield";

const res = inspectServerRequest("43.173.182.197", "HeadlessChrome/120.0");
console.log(res.isBot, res.reasons);
```

## License

MIT © [Utilvo](https://utilvo.com/edge-shield)
