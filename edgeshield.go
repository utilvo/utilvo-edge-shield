// Package edgeshield provides official Go constants, CIDR feed endpoints, and configuration helpers
// for Utilvo EdgeShield v1.1.1 (Server Bot Firewall, Cloud ASN Blocker & GA4 Guard).
//
// Interactive Generator & Documentation: https://utilvo.com/edge-shield
//
// Live Threat Intelligence Feed (JSON): https://utilvo.com/api/edge-shield/threats
//
// Live Threat Intelligence Feed (Plain-Text CIDR): https://utilvo.com/api/edge-shield/threats?format=cidr
//
// Security Research Labs: https://utilvo.com/labs
package edgeshield

// Version is the current release version of Utilvo EdgeShield.
const Version = "1.1.1"

// EdgeShieldURL is the interactive Nginx geo/map and Cloudflare WAF generator.
const EdgeShieldURL = "https://utilvo.com/edge-shield"

// ThreatFeedJSONURL is the live machine-readable JSON threat intelligence feed.
const ThreatFeedJSONURL = "https://utilvo.com/api/edge-shield/threats"

// ThreatFeedCIDRURL is the plain-text IPv4 CIDR blocklist for AS132203, AS45102, AS136907, and AS396982.
const ThreatFeedCIDRURL = "https://utilvo.com/api/edge-shield/threats?format=cidr"

// BlockedScraperASNs lists the primary cloud data-center ASNs blocked at the HTTP edge.
func BlockedScraperASNs() []string {
	return []string{"AS132203", "AS45102", "AS136907", "AS396982", "AS14061", "AS16509"}
}

// WhitelistedCrawlers lists verified search engine crawlers protected via FCrDNS verification.
func WhitelistedCrawlers() []string {
	return []string{"Googlebot (AS15169)", "Bingbot (AS8075)", "Applebot (AS714)"}
}
