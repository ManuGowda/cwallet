defmodule Cwallet.Bits do
  @moduledoc """
  Module for converting binary to a list of integer numbers
  used as rows for the mnemonic code words
  """

  @doc """
  Loops through the bitstring and converts it to binary list
  ## Examples
      iex> Bits.to_binary_list(<<1>>)
      [0, 0, 0, 0, 0, 0, 0, 1]
      iex> Bits.to_binary_list(<<45, 234>>)
      [0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0]
  """
  @spec to_binary_list(Bitstring.t()) :: []
  def to_binary_list(binary) when is_binary(binary) do
    to_binary_list(binary, [])
  end

  defp to_binary_list(<<bit::size(1), bits::bitstring>>, acc) do
    to_binary_list(bits, [bit | acc])
  end

  defp to_binary_list(<<>>, acc), do: Enum.reverse(acc)

  @doc """
  Converts binary list (consisting of groups of 11 bits)
  to byte list (consisting of number from 0 to 2047)
  ## Examples
      iex> Bits.parse_binary_list(["10100110110", "10111000110"])
      [1478, 1334]
  """
  @spec parse_binary_list(List.t()) :: List.t()
  def parse_binary_list(list) do
    Enum.map(list, fn(binary) -> binary_to_int(binary) end)
  end

  @spec binary_to_int(binary()) :: List.t()
  defp binary_to_int(binary), do: binary |> Integer.parse(2) |> elem(0)

  @doc """
  Splits the given string into groups of 11 bits each encoding
  a number from 0-2047, serving as an index into a wordlist.
  The result is a list of grups.
  ## Examples
      iex> Bits.split_into_groups("1011100011010100110110")
      ["10100110110", "10111000110"]
      iex> Bits.split_into_groups("1011100011010100110110" <> "1011001011")
      ["10100110110", "10111000110"]
  """
  @spec split_into_groups(String.t()) :: List.t()
  def split_into_groups(string_bits) do
    split_into_groups(string_bits, [])
  end
  def split_into_groups(<<part::binary-11, rest::binary>>, acc) do
    split_into_groups(rest, [part | acc])
  end
  def split_into_groups("", acc), do: Enum.reverse(acc)
end
