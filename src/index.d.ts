export interface EdgeShieldFeedUrls {
  readonly docsUrl: string;
  readonly installerUrl: string;
  readonly cidrFeedUrl: string;
  readonly threatApiUrl: string;
  readonly liveCidrApiUrl: string;
  readonly nginxMapUrl: string;
  readonly ga4GuardUrl: string;
}

export interface BotInspectionResult {
  readonly isBot: boolean;
  readonly isSeoCrawler?: boolean;
  readonly reasons: readonly string[];
}

export const EDGE_SHIELD_FEEDS: EdgeShieldFeedUrls;
export const CLOUD_SCRAPER_ASNS: readonly number[];
export const CLOUD_SCRAPER_CIDRS: readonly string[];
export function inspectServerRequest(ip: string, userAgent: string): BotInspectionResult;
export function generateCloudflareWafExpression(): string;
