# reallyme-openid-oauth

**OAuth primitives for ReallyMe's OpenID protocol implementations**

`reallyme-openid-oauth` provides RFC 9126 pushed authorization requests, RFC
9449 DPoP, RFC 7636 PKCE, RFC 8414 authorization-server metadata, and
attestation-based client authentication. OpenID4VCI and OpenID4VP use these
components without duplicating OAuth validation logic.

> Building an issuer, verifier, or wallet? Start with
> [`reallyme-identity`](https://crates.io/crates/reallyme-identity). Use this
> crate directly when implementing the OAuth boundary beneath an OpenID flow.

## Scope

| This crate provides | The protocol or service layer provides |
| --- | --- |
| PAR request and response models | OpenID4VCI and OpenID4VP sequencing |
| DPoP proof construction and validation | HTTP server and client adapters |
| PKCE challenge and verifier handling | Durable replay state and persistence |
| Authorization-server metadata retrieval boundary | Application authorization policy |
| Attestation-based client authentication | Wallet and issuer lifecycle management |

## Install

```toml
[dependencies]
reallyme-openid-oauth = "0.1"
```

The default `native` feature selects native trust dependencies. Disable
default features and enable `wasm` for WebAssembly builds.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
