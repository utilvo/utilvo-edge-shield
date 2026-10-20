defmodule UtilvoEdgeShield do
  @moduledoc """
  Utilvo EdgeShield (`v1.1.0`) — Open-source server firewall rule generator,
  CIDR/ASN threat intelligence feed (`AS132203`, `AS45102`, `AS136907`), and GA4 headless bot detector.

  Official documentation: https://utilvo.com/edge-shield
  """

  @seo_re ~r/(Googlebot|Google-InspectionTool|bingbot|adidxbot|MicrosoftPreview|Applebot|DuckDuckBot|YandexBot)/i
  @subnet_re1 ~r/^43\.(119|12[89]|1[3-6][0-9]|17[0-5])\./
  @subnet_re2 ~r/^(47\.(74|8[289])|8\.21[79]|101\.3[23]|119\.28|124\.156|129\.226|150\.109|170\.106|149\.232|159\.138|46\.250)\./
  @bad_ua_re ~r/(CPU iPhone OS 13_2_3|TokenFoundryBot|QlyzeBot|Bytespider|PetalBot|ClaudeBot|CCBot|GPTBot|HeadlessChrome)/i

  @doc """
  Inspects an IPv4 address and User-Agent string with Safe-Harbor search crawler verification.
  """
  def inspect_request(ip, user_agent) when is_binary(ip) and is_binary(user_agent) do
    if Regex.match?(@seo_re, user_agent) do
      %{is_bot: false, is_seo_crawler: true, reasons: []}
    else
      clean_ip = ip |> String.split(",") |> List.first() |> String.trim()
      reasons = []
      reasons =
        if Regex.match?(@subnet_re1, clean_ip) or Regex.match?(@subnet_re2, clean_ip),
          do: ["CLOUD_SCRAPER_SUBNET" | reasons],
          else: reasons

      reasons =
        if Regex.match?(@bad_ua_re, user_agent),
          do: ["ROGUE_SCRAPER_USER_AGENT" | reasons],
          else: reasons

      %{
        is_bot: length(reasons) > 0,
        is_seo_crawler: false,
        reasons: Enum.reverse(reasons)
      }
    end
  end
end
