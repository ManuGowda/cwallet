defmodule Cwallet.BitsTest do
  use ExUnit.Case
  doctest Cwallet

  test "to_binary_list" do
    assert Cwallet.Bits.to_binary_list(<<1>>) == [0, 0, 0, 0, 0, 0, 0, 1]
    assert Cwallet.Bits.to_binary_list(<<2>>) == [0, 0, 0, 0, 0, 0, 1, 0]
    assert Cwallet.Bits.to_binary_list(<<11>>) == [0, 0, 0, 0, 1, 0, 1, 1]
  end
end
