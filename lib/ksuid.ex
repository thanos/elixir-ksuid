defmodule Ksuid do
  @moduledoc """
  KSuid stands for K-Sortable Unique Identifier. It's a way to generate globally unique
  IDs which are partially chronologically sortable.
  """


  @epoch 1400000000
  @payload_length  16
  @ksuid_raw_length 20
  @ksuid_encoded_length 27
  @parse_error "the value given is more than the max Ksuid value possible"

  defp get_ts(fun, time_resolution) do
    ts = fun.(time_resolution) - @epoch
    <<ts::integer-size(32)>>  # length of the time stamp is 32 bits
  end

  defp get_bytes() do
    :crypto.strong_rand_bytes(@payload_length)
  end

  @doc """
  This method returns a 20 byte Ksuid which has 4 bytes as timestamp
  and 16 bytes of crypto string bytes.
  It uses System.system_time/1 which is not gauranteed to be monotonic, i.e. it is sensitive to summer time changes.

  ## Examples

      iex> Ksuid.generate()
      "0KZi94b2fnVzpGi60FoZgXIvUtYy"

  """
  def generate() do
    generate(:second)
  end



  @doc """
  This method returns a 20 byte Ksuid which has 4 bytes as timestamp
  and 16 bytes of crypto string bytes.
  time_resolution can be one of the following time_units: :second, :millisecond, :microsecond, :nanosecond, or a positive integer.
  It uses System.system_time/1 which is not gauranteed to be monotonic, i.e. it is sensitive to summer time changes.

  ## Examples

      iex> Ksuid.generate(:nanosecond)
      "0KZi94b2fnVzpGi60FoZgXIvUtYy"

  """
  def generate(time_resolution) do
    generate(fn x -> System.system_time(x) end, time_resolution)
  end


   @doc """
  This method returns a 20 byte Ksuid which has 4 bytes as timestamp
  and 16 bytes of crypto string bytes.
  fun can be any function fun(time_unit) :: integer
  time_resolution can be one of the following time_units: :second, :millisecond, :microsecond, :nanosecond, or a positive integer.


  ## Examples

      iex> Ksuid.generate(fn x -> System.monotonic_time(x) end, :nanosecond)
      "0KZi94b2fnVzpGi60FoZgXIvUtYy"

  """
  def generate(fun, time_resolution) do
    kuid_as_bytes = get_ts(fun, time_resolution) <> get_bytes()

    kuid_as_bytes
    |> Base62.encode()
    |> apply_padding(<<48>>,@ksuid_encoded_length) # <<48>> is zero on decoding
  end


  defp apply_padding(bytes,pad_char,expected_length) do
    pad = expected_length - byte_size(bytes)
    gen_padding(pad,pad_char) <> bytes
  end

  defp gen_padding(length,pad_char) when length>0 do
    pad_char <> gen_padding(length-1,pad_char)
  end
  defp gen_padding(0,_) do
    <<>>
  end

  def parse(ksuid) when is_binary(ksuid) and byte_size(ksuid) === @ksuid_encoded_length do

    decoded = Base62.decode!(ksuid)
    cond do
      byte_size(decoded) > 20 ->
        {:error, @parse_error}
      true -> # for any other case we are adding padding to make the string of 20 length.
        decoded
        |> apply_padding(<<0>>,@ksuid_raw_length)
        |> normalize
    end
  end

  defp normalize(<<ts::32,rand_bytes::bits>>) do
    case DateTime.from_unix(ts + @epoch)  do
       {:ok , time } -> {:ok ,time , rand_bytes}
        {:error, reason } -> {:error, reason }
    end
  end

end
