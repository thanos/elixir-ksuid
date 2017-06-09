# Ksuid

ksuid is a Elixir library that can generate KSUIDs.

## How To

```elixir
iex> Ksuid.generate()
"KZi94b2fnVzpGi60FoZgXIvUtYy"
```


## TODO

- [x] Generate KSUID
- [ ] Parsing KSUIDS
- [ ] Decode BASE62 method
- [ ] Write tests
- [ ] Write Documentation

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `ksuid` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:ksuid, "~> 0.1.0"}]
end
```