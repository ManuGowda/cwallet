defmodule Cwallet.IndexesTest do
  use ExUnit.Case
  doctest Cwallet

  test "generate_indexes" do
    Cwallet.Indexes.generate_indexes()
    |> Enum.each(fn item -> assert item >=0 && item <= 2047 end)
  end
end
