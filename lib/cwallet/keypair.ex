defmodule Cwallet.Keypair do
  @moduledoc """
  Module for generating master public and privatekey
  """

  alias Cwallet.Structs.Bip32PubKey, as: PubKey
  alias Cwallet.Structs.Bip32PrivKey, as: PrivKey

  @typedoc "Wallet option value"
  @type wallet_type :: :lsk | :btc

  @typedoc "Type of network"
  @type network :: :mainnet | :testnet

  @typedoc "Type of key"
  @type key_type :: :public | :private

  @typedoc "Keyword options list"
  @type opts :: [{key, wallet_type}]

  @typedoc "Pivate extended key struct"
  @type privkey :: %PrivKey{}

  @typedoc "Public extended key struct"
  @type pubkey :: %PubKey{}

  @typedoc "Bip32 extended key"
  @type key :: %PubKey{} | %PrivKey{}

  @typedoc "Public key type"
  @type pubkey_type :: :compressed

  @typedoc "Serialized data"
  @type serialized_data :: %{
    depth: binary,
    fingerprint: binary,
    child_number: binary ,
    chain_code: binary,
    ser_key: binary
  }

  @typedoc "Structure of extended key"
  @type t :: %{
    version: binary,
    serialized_data: serialized_data()
  }

  # Constant for generating the private_key / chain_code
  @bitcoin_key "Bitcoin seed"
  @lisk_key "Lisk seed"

  # Integers modulo the order of the curve (referred to as n)
  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  # Used as guard for the key derivation type: normal / hardned
  @mersenne_prime 2_147_483_647

  @doc """
  Generates a seed from the given mnemonic and pass_phrase
  """
  def generate_seed(mnemonic, pass_phrase \\ "") do
    SeedGenerator.generate(mnemonic, pass_phrase, [])
  end

  @doc """
  Generates keypair using the curve :curve25519
  """
  @spec generate_keypair() :: map()
  def generate_keypair, do: :enacl.sign_keypair()

  @doc """
  Generates master private extended key. Where you can state the network
  the key should be working on and select a type of key. The default network
  is `:mainnet` and the default key type is `:lsk`
  ## Networks
    * `:mainnet` - Creates key for the Mainnet
    * `:testnet` - Creates key for the Testnet
  ## Options
  The accepted options are:
    * `:type` - specifies the type of wallet
  The values for `:type` are:
    * `:lsk` - creates an Lisk wallet
    * `:btc` - creates a Bitcoin wallet
  ## Examples
      iex> generate_master_key(seed_bin, :mainnet, :lsk)
      master_extended_btc_key
      iex> generate_master_key(seed_bin, :testnet, :lsk)
      master_extended_lsk_key
  """
  @spec generate_master_key(binary(), network(), opts()) :: privkey()
  def generate_master_key(seed_bin, network \\ :mainnet, opts \\ []) do
    type = Keyword.get(opts, :type, :lsk)
    priv_and_chain = case type do
      :lsk -> :crypto.hmac(:sha512, @lisk_key, seed_bin)
      :btc -> :crypto.hmac(:sha512, @bitcoin_key, seed_bin)
      _ -> throw("This wallet does not support #{type} wallet type")
    end
    build_master_key(priv_and_chain, network, type)
  end

  for {type, wallet_type} <- [lsk: :lsk, btc: :btc] do
    defp build_master_key(<<priv_key::binary-32, c_code::binary>>, network, unquote(type)) do
      key = PrivKey.create(network, unquote(wallet_type))

      %{key | key: priv_key, chain_code: c_code}
    end
  end

  @doc """
  Generates the corresponding Public key to the given Private key
  ## Example
      iex> KeyPair.to_public_key(%Privkey{})
      %PubKey{}
  """
  @spec to_public_key(privkey()) :: pubkey()
  def to_public_key(%PrivKey{} = priv_key) do
    pub_key = generate_pub_key(priv_key.key)
    key = PubKey.create(priv_key.network, priv_key.currency)

    %{key |
      depth: priv_key.depth,
      finger_print: priv_key.finger_print,
      child_number: priv_key.child_number,
      chain_code: priv_key.chain_code,
      key: pub_key}
  end

  @spec generate_pub_key(binary()) :: binary()
  def generate_pub_key(priv_key) do
    {pub_key, _rest} = :crypto.generate_key(:ecdh, :secp256k1, priv_key)
    pub_key
  end

  @spec generate_pub_key(binary(), pubkey_type()) :: binary()
  def generate_pub_key(priv_key, :compressed) do
    priv_key
    |> generate_pub_key()
    |> compress()
  end

  @spec fingerprint(privkey()) :: binary()
  defp fingerprint(%PrivKey{key: priv_key}) do
    priv_key
    |> generate_pub_key(:compressed)
    |> fingerprint()
  end

  @spec fingerprint(pubkey()) :: binary()
  defp fingerprint(%PubKey{key: pub_key}) do
    pub_key
    |> compress()
    |> fingerprint()
  end

  @spec fingerprint(binary()) :: binary()
  defp fingerprint(pub_key) do
    <<finger_print::binary-4, _rest::binary>> =
      :crypto.hash(:ripemd160, :crypto.hash(:sha256, pub_key))
    finger_print
  end

  @spec serialize(privkey()) :: t()
  defp serialize(%PrivKey{} = key) do
    serialized_key = <<0::size(8), key.key::binary>>
    serialize(key, serialized_key)
  end

  @spec serialize(pubkey()) :: t()
  defp serialize(%PubKey{} = key) do
    serialized_key = compress(key.key)
    serialize(key, serialized_key)
  end

  @spec serialize(key(), binary()) :: t()
  defp serialize(key_data, serialized_key) do
    {
      <<key_data.version::size(32)>>,
      <<key_data.depth::size(8),
      key_data.finger_print::binary-4,
      key_data.child_number::size(32),
      key_data.chain_code::binary,
      serialized_key::binary>>
    }
  end

  @doc """
  Formats the key into Base58
  ## Example
      iex> KeyPair.format_key(key)
      "xprv9ykQk99RM1ihJkrSMmfn28SEZiF79geaDvMHGJz6b2zmSvzdmWmru2ScVujbbkJ9kVUrVNNhER5373sZSUcfJYhNSGyg64VB9jm5aP9oAga"
  """
  @spec format_key(key()) :: String.t()
  def format_key(key) when is_map(key) do
    {prefix, bip32_serialization} = serialize(key)
    Base58Check.encode58check(prefix, bip32_serialization)
  end

  # Deriving private keys.
  @spec derive(key(), String.t()) :: map()
  def derive(key, <<"m/", path::binary>>) do
    derive(key, path, :private)
  end

  # Deriving public keys.
  def derive(key, <<"M/", path::binary>>) do
    derive(key, path, :public)
  end

  @spec derive(key(), String.t(), key_type()) :: map()
  defp derive(key, path, key_type) do
    derive_pathlist(
      key,
      :lists.map(fn(elem) ->
        case String.reverse(elem) do
          <<"'", hardened::binary>> ->
            {num, _rest} =
              hardened
              |> String.reverse()
              |> Integer.parse()
            num + @mersenne_prime + 1
          _ ->
            {num, _rest} = Integer.parse(elem)
            num
        end
      end, :binary.split(path, <<"/">>, [:global])),
      key_type)
  end

  @spec derive_pathlist(key(), list(), key_type()) :: key()
  def derive_pathlist(%PrivKey{} = key, [], :private), do: key
  def derive_pathlist(%PrivKey{} = key, [], :public), do: to_public_key(key)
  def derive_pathlist(%PubKey{} = key, [], :public), do: key
  def derive_pathlist(key, pathlist, key_type) do
    [index | rest] = pathlist
    key
    |> derive_key(index)
    |> derive_pathlist(rest, key_type)
  end

  @spec derive_key(privkey(), integer()) :: privkey()
  defp derive_key(%PrivKey{} = key, index) when index > -1 and index <= @mersenne_prime do
    # Normal derivation
    compressed_pub_key = generate_pub_key(key.key, :compressed)

    <<derived_key::size(256), child_chain::binary>> =
      :crypto.hmac(:sha512, key.chain_code, <<compressed_pub_key::binary, index::size(32)>>)

    <<parent_key_int::size(256)>> = key.key

    child_key =
      derived_key
      |> Kernel.+(parent_key_int)
      |> rem(@n)
      |> :binary.encode_unsigned()

    derive_key(key, child_key, child_chain, index)
  end

  defp derive_key(%PrivKey{} = key, index) when index > @mersenne_prime do
    # Hardned derivation
    <<derived_key::size(256), child_chain::binary>> =
      :crypto.hmac(:sha512, key.chain_code, <<0::size(8), key.key::binary, index::size(32)>>)

    <<key_int::size(256)>> = key.key

    child_key =
      derived_key
      |> Kernel.+(key_int)
      |> rem(@n)
      |> :binary.encode_unsigned()

    derive_key(key, child_key, child_chain, index)
  end

  @spec derive_key(pubkey(), integer()) :: pubkey()
  defp derive_key(%PubKey{} = key, index) when index > -1 and index <= @mersenne_prime do
    # Normal derivation
    serialized_pub_key = compress(key.key)

    <<derived_key::binary-32, child_chain::binary>> =
      :crypto.hmac(:sha512, key.chain_code,
        <<serialized_pub_key::binary, index::size(32)>>)

    # Elliptic curve point addition
    {:ok, child_key} = :libsecp256k1.ec_pubkey_tweak_add(key.key, derived_key)

    derive_key(key, child_key, child_chain, index)
  end

  defp derive_key(%PubKey{}, index) when index > @mersenne_prime do
    # Hardned derivation
    raise(RuntimeError, "Cannot derive Public Hardened child")
  end

  @spec derive_key(key(), binary(), binary(), integer()) :: key()
  defp derive_key(key, child_key, child_chain, index) when is_map(key) do
    %{key |
      key: child_key,
      chain_code: child_chain,
      depth: key.depth + 1,
      finger_print: fingerprint(key),
      child_number: index}
  end

  @doc """
  Generates wallet address from a given public key
  Network ID `Bitcoin` bytes:
    * :mainnet = `0x00`
    * :testnet = `0x6F`
  Network ID `Lisk` bytes:
    * :mainnet = `0x18`
    * :testnet = `0x42`
  """
  for {wallet_type, net_bytes} <- [lsk: 0x18, btc: 0x00] do
    def generate_wallet_address(public_key, :mainnet, unquote(wallet_type)) do
      generate_address(public_key, unquote(net_bytes))
    end
  end

  for {wallet_type, net_bytes} <- [lsk: 0x42, btc: 0x6F] do
    def generate_wallet_address(public_key, :testnet, unquote(wallet_type)) do
      generate_address(public_key, unquote(net_bytes))
    end
  end

  @spec generate_wallet_address(binary(), network(), wallet_type()) :: String.t()
  def generate_wallet_address(_public_key, network, _wallet_type) do
    throw("The #{network} network is not supported! Please use :mainnet or :testnet")
  end

  @spec generate_address(binary(), integer()) :: String.t()
  defp generate_address(public_key, net_bytes) do
    pub_ripemd160 =
      :crypto.hash(:ripemd160, :crypto.hash(:sha256, public_key))

    pub_with_netbytes = <<net_bytes::size(8), pub_ripemd160::binary>>

    <<checksum::binary-4, _rest::binary>> = :crypto.hash(:sha256,
      :crypto.hash(:sha256, pub_with_netbytes))

    Base58Check.encode58(pub_with_netbytes <> checksum)
  end

  @spec compress(binary()) :: binary()
  def compress(<<_prefix::size(8), x_coordinate::size(256), y_coordinate::size(256)>>) do
    prefix = case rem(y_coordinate, 2) do
      0 -> 0x02
      _ -> 0x03
    end
    <<prefix::size(8), x_coordinate::size(256)>>
  end
end
