<?php

declare(strict_types=1);

namespace Utilvo\EdgeShield;

final class EdgeShield
{
    public const DOCS_URL = 'https://utilvo.com/edge-shield';
    public const THREAT_API_URL = 'https://utilvo.com/api/edge-shield/threats';
    public const CIDR_FEED_URL = 'https://utilvo.com/edge-shield/ai-scrapers-cidr.txt';

    public static function inspectRequest(string $ip, string $userAgent): array
    {
        if (preg_match('/(Googlebot|Google-InspectionTool|bingbot|adidxbot|MicrosoftPreview|Applebot|DuckDuckBot|YandexBot)/i', $userAgent)) {
            return ['is_bot' => false, 'is_seo_crawler' => true, 'reasons' => []];
        }
        $cleanIp = trim(explode(',', $ip)[0]);
        $reasons = [];
        if (
            preg_match('/^43\.(119|12[89]|1[3-6][0-9]|17[0-5])\./', $cleanIp) ||
            preg_match('/^(47\.(74|8[289])|8\.21[79]|101\.3[23]|119\.28|124\.156|129\.226|150\.109|170\.106|149\.232|159\.138|46\.250)\./', $cleanIp)
        ) {
            $reasons[] = 'CLOUD_SCRAPER_SUBNET';
        }
        if (preg_match('/(CPU iPhone OS 13_2_3|TokenFoundryBot|QlyzeBot|Bytespider|PetalBot|ClaudeBot|CCBot|GPTBot|HeadlessChrome)/i', $userAgent)) {
            $reasons[] = 'ROGUE_SCRAPER_USER_AGENT';
        }
        return [
            'is_bot' => !empty($reasons),
            'is_seo_crawler' => false,
            'reasons' => $reasons,
        ];
    }
}
