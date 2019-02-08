defmodule Cwallet.Structs.Bip32PrivKey do
  @moduledoc """
  Module for Bip32PrivKey struct
  """

  @typedoc """
  Network types
  """
  @type network :: :mainnet | :testnet

  @typedoc """
  Wallet type
  """
  @type currency :: :lsk | :btc

  @typedoc """
  structure of the key, ref(https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format)
  """
  @type t :: %__MODULE__{
    currency: atom(),
    network: atom(),
    version: integer(),
    depth: integer(),
    finger_print: binary(),
    child_number: integer(),
    chain_code: binary(),
    key: binary()
  }

  defstruct [
    :currency,
    :network,
    :version,
    :depth,
    :finger_print,
    :child_number,
    :chain_code,
    :key
  ]

  ## Network versions

  # bitcoin
  @mainnet_xprv_btc_prefix 0x0488ADE4
  @testnet_tprv_btc_prefix 0x04358394

  # Lisk
  @mainnet_LMPR_lsk_prefix 0x019257d2
  @testnet_LTPR_lsk_prefix 0x01947e6e

  def create(:mainnet, :btc) do
    default(@mainnet_xpriv_btc_prefix, :mainnet, :btc)
  end
  def create(:testnet, :btc) do
    default(@testnet_tprv_btc_prefix, :testnet, :btc)
  end
  def create(:mainnet, :lsk) do
    default(@mainnet_LMPR_lsk_prefix, :mainnet, :lsk)
  end
  def create(:testnet, :lsk) do
    default(@testnet_LTPR_lsk_prefix, :testnet, :lsk)
  end
  def create(network, _currency) do
    throw("The given network #{network} is not supported! Please use either :mainnet or :testnet")
  end

  defp default(version, network, currency) do
    %Cwallet.Structs.Bip32PrivKey{
      currency: currency,
      network: network,
      version: version,
      depth: 0,
      finger_print: <<0::32>>,
      child_number: 0,
      chain_code: <<0>>,
      key: <<0>>
    }
  end
end
