defmodule CwalletTest do
  use ExUnit.Case
  doctest Cwallet

  test "greets the world" do
    assert Cwallet.hello() == :world
  end
end
