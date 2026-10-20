// Package utilvoedgeshield provides server firewall rule generators, CIDR/ASN
// threat intelligence matching (AS132203, AS45102, AS136907), and Safe-Harbor
// search crawler verification.
//
// Official documentation & Live Threat DB: https://utilvo.com/edge-shield
package utilvoedgeshield

import (
	"regexp"
	"strings"
)

const (
	DocsURL      = "https://utilvo.com/edge-shield"
	ThreatAPIURL = "https://utilvo.com/api/edge-shield/threats"
	CIDRFeedURL  = "https://utilvo.com/edge-shield/ai-scrapers-cidr.txt"
	InstallerURL = "https://utilvo.com/edge-shield/install.sh"
)

var (
	seoBotRegex  = regexp.MustCompile(`(?i)(Googlebot|Google-InspectionTool|bingbot|adidxbot|MicrosoftPreview|Applebot|DuckDuckBot|YandexBot)`)
	subnetRegex1 = regexp.MustCompile(`^43\.(119|12[89]|1[3-6][0-9]|17[0-5])\.`)
	subnetRegex2 = regexp.MustCompile(`^(47\.(74|8[289])|8\.21[79]|101\.3[23]|119\.28|124\.156|129\.226|150\.109|170\.106|149\.232|159\.138|46\.250)\.`)
	badUARegex   = regexp.MustCompile(`(?i)(CPU iPhone OS 13_2_3|TokenFoundryBot|QlyzeBot|Bytespider|PetalBot|ClaudeBot|CCBot|GPTBot|HeadlessChrome)`)
)

// InspectionResult represents the classification of an incoming HTTP request.
type InspectionResult struct {
	IsBot        bool
	IsSEOCrawler bool
	Reasons      []string
}

// InspectRequest evaluates an IPv4 address and User-Agent string against Utilvo EdgeShield rules.
func InspectRequest(ip string, userAgent string) InspectionResult {
	if seoBotRegex.MatchString(userAgent) {
		return InspectionResult{IsBot: false, IsSEOCrawler: true, Reasons: nil}
	}
	cleanIP := strings.TrimSpace(strings.Split(ip, ",")[0])
	var reasons []string
	if subnetRegex1.MatchString(cleanIP) || subnetRegex2.MatchString(cleanIP) {
		reasons = append(reasons, "CLOUD_SCRAPER_SUBNET")
	}
	if badUARegex.MatchString(userAgent) {
		reasons = append(reasons, "ROGUE_SCRAPER_USER_AGENT")
	}
	return InspectionResult{
		IsBot:        len(reasons) > 0,
		IsSEOCrawler: false,
		Reasons:      reasons,
	}
}

// GenerateCloudflareWAFExpression returns a Cloudflare WAF rule expression.
func GenerateCloudflareWAFExpression() string {
	return `(not cf.client.bot and (ip.src.asnum in {132203 45090 45102 37963 136907} or http.user_agent contains "CPU iPhone OS 13_2_3" or http.user_agent contains "TokenFoundryBot" or http.user_agent contains "QlyzeBot"))`
}
