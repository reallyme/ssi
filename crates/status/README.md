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
reallyme-credential-status = "0.3.3"
```

The default `native` feature enables the native cryptographic provider. Use
`default-features = false` with `wasm` for WebAssembly, or enable `proto` for
protobuf conversions.

## Certificate-bound Token Status Lists

Use `verify_token_status_list_jwt_with_x5c` when the Token Status List signing
key is authenticated through the JWT's protected `x5c` path. The caller
supplies an X.509 resolver that validates the exact leaf-first DER chain at the
provided verification time and returns the authenticated leaf P-256 key. The
presented chain is never used as a trust source.

Use `verify_token_status_list_jwt` for an issuer key already authenticated by a
different trust mechanism. That raw-key API continues to reject embedded key
material.

## Signing payload version

The proprietary `StatusList` signing payload uses the `reallyme.status-list.v2`
domain and authenticates the signature algorithm alongside the list fields.
Issuers must re-sign lists produced with the previous payload encoding. Verifiers
do not accept the old encoding as a fallback. The JWT and CWT Token Status List
wire formats are unchanged.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
