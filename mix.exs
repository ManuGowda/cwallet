defmodule Cwallet.MixProject do
  use Mix.Project

  def project do
    [
      app: :cwallet,
      version: "0.1.0",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:base58check, github: "quanterall/base58check"},
      {:seed_generator, github: "quanterall/seed_generator"},
      {:libsecp256k1, [github: "mbrix/libsecp256k1", manager: :rebar]},
      {:enacl, github: "aeternity/enacl", ref: "2f50ba6", override: true}
    ]
  end
end
