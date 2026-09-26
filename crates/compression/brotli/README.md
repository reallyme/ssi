# reallyme-compression-brotli

`reallyme-compression-brotli` provides bounded Brotli compression helpers for
arbitrary byte payloads.

The crate is a small, protocol-independent compression boundary. ReallyMe's
identity repositories use it for bounded protobuf transport, but the API does
not depend on SSI models or protobuf contracts. Decompression is capped by
default to avoid decompression-bomb memory exhaustion on untrusted payloads.

## Install

```toml
[dependencies]
reallyme-compression-brotli = "0.2.0"
```

## Security contract

- `brotli_decompress` uses `DEFAULT_MAX_DECOMPRESSED_BYTES`.
- `brotli_decompress_with_limit` lets callers enforce tighter schema-specific
  limits.
- Malformed or oversized streams return a typed error. Plaintext acceptance, if
  a protocol defines it, must be selected explicitly before this boundary.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
