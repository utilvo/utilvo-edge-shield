defmodule UtilvoEdgeShield.MixProject do
  use Mix.Project

  def project do
    [
      app: :utilvo_edge_shield,
      version: "1.1.0",
      elixir: "~> 1.12",
      description: "Open-source server firewall generator, CIDR/ASN threat intelligence feed (AS132203, AS45102, AS136907), and GA4 headless bot detector.",
      package: package(),
      deps: []
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{
        "Homepage" => "https://utilvo.com/edge-shield",
        "Live Threat API" => "https://utilvo.com/api/edge-shield/threats",
        "GitHub" => "https://github.com/utilvo/utilvo-edge-shield"
      }
    ]
  end
end
