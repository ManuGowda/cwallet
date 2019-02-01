defmodule MnemonicTest do
  use ExUnit.Case
  doctest Cwallet

  test "mnemonic.generate_phrase" do
    assert Cwallet.Mnemonic.generate_phrase([2047, 33, 47]) == "zoo aerobic album"
  end

  test "mnemonic.get_wordlist" do
    assert elem(Cwallet.Mnemonic.get_wordlist(), 0) == "abandon"
  end
end
