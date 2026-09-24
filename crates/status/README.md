# reallyme-credential-status

**Bounded credential status-list models, issuance, and verification**

`reallyme-credential-status` implements local Status List and Token Status List
processing for ReallyMe credential infrastructure. It provides typed models,
canonical signing payloads, compact status-value packing, resource limits, and
signature-verification boundaries.

> Building an issuer, verifier, or wallet? Start with
> [`reallyme-identity`](https://crates.io/crates/reallyme-identity). Use this
> crate directly when implementing the credential status layer.

## Scope

| This crate provides | The host application provides |
| --- | --- |
| Status List and Token Status List models | Status resource retrieval and caching |
| JWT and CWT issuance and verification boundaries | DID and trust resolution |
| Bounded decoding and index validation | OpenID/OAuth transport |
| Optional protobuf conversion | Persistence and service policy |

## Install

```toml
[dependencies]
reallyme-credential-status = "0.1"
```

The default `native` feature enables the native cryptographic provider. Use
`default-features = false` with `wasm` for WebAssembly, or enable `proto` for
protobuf conversions.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
