library utilvo_edge_shield;

class BotInspectionResult {
  final bool isBot;
  final bool isSeoCrawler;
  final List<String> reasons;

  const BotInspectionResult({
    required this.isBot,
    required this.isSeoCrawler,
    required this.reasons,
  });
}

class UtilvoEdgeShield {
  static const String docsUrl = 'https://utilvo.com/edge-shield';
  static const String threatApiUrl = 'https://utilvo.com/api/edge-shield/threats';
  static const String cidrFeedUrl = 'https://utilvo.com/edge-shield/ai-scrapers-cidr.txt';

  static final RegExp _seoBotRe = RegExp(
    r'(Googlebot|Google-InspectionTool|bingbot|adidxbot|MicrosoftPreview|Applebot|DuckDuckBot|YandexBot)',
    caseSensitive: false,
  );
  static final RegExp _subnetRe1 = RegExp(r'^43\.(119|12[89]|1[3-6][0-9]|17[0-5])\.');
  static final RegExp _subnetRe2 = RegExp(
    r'^(47\.(74|8[289])|8\.21[79]|101\.3[23]|119\.28|124\.156|129\.226|150\.109|170\.106|149\.232|159\.138|46\.250)\.',
  );
  static final RegExp _badUaRe = RegExp(
    r'(CPU iPhone OS 13_2_3|TokenFoundryBot|QlyzeBot|Bytespider|PetalBot|ClaudeBot|CCBot|GPTBot|HeadlessChrome)',
    caseSensitive: false,
  );

  static BotInspectionResult inspectRequest(String ip, String userAgent) {
    if (_seoBotRe.hasMatch(userAgent)) {
      return const BotInspectionResult(
        isBot: false,
        isSeoCrawler: true,
        reasons: <String>[],
      );
    }
    final cleanIp = ip.split(',').first.trim();
    final reasons = <String>[];
    if (_subnetRe1.hasMatch(cleanIp) || _subnetRe2.hasMatch(cleanIp)) {
      reasons.add('CLOUD_SCRAPER_SUBNET');
    }
    if (_badUaRe.hasMatch(userAgent)) {
      reasons.add('ROGUE_SCRAPER_USER_AGENT');
    }
    return BotInspectionResult(
      isBot: reasons.isNotEmpty,
      isSeoCrawler: false,
      reasons: reasons,
    );
  }
}
