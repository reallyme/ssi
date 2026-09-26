# reallyme-sd-jwt

**RFC 9901 SD-JWT issuance, presentation, and verification**

`reallyme-sd-jwt` implements the protocol-neutral SD-JWT format layer. It
supports compact and JWS JSON serialization, disclosure creation and
selection, recursive disclosure processing, issuer-signature verification,
and key-binding JWT validation.

> Building an issuer, verifier, or wallet? Start with
> [`reallyme-identity`](https://crates.io/crates/reallyme-identity). Use this
> crate directly when integrating RFC 9901 at the format layer.

## Scope

| This crate provides | The protocol or wallet layer provides |
| --- | --- |
| SD-JWT issuance and disclosure construction | OpenID4VCI issuance flows |
| Compact and JWS JSON serialization | OpenID4VP request and response handling |
| Disclosure selection and recursive processing | Wallet inventory and consent |
| Issuer and key-binding verification | Transport and platform SDK bindings |

## Install

```toml
[dependencies]
reallyme-sd-jwt = "0.2.0"
```

The default `native` feature enables the native cryptographic provider. Use
`default-features = false` with `wasm` for WebAssembly builds.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
