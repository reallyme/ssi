# reallyme-mdoc

**ISO/IEC 18013-5 mdoc issuance, presentation, and verification**

`reallyme-mdoc` implements the protocol-neutral mdoc format layer: typed
issuer-signed documents, bounded CBOR processing, Mobile Security Object
validation, COSE issuer authentication, device authentication, selective
presentation, and DeviceResponse verification.

> Building an issuer, verifier, or wallet? Start with
> [`reallyme-identity`](https://crates.io/crates/reallyme-identity). Use this
> crate directly when integrating the ISO mdoc format layer.

## Scope

| This crate provides | The protocol or wallet layer provides |
| --- | --- |
| IssuerSigned and DeviceResponse models | OpenID4VP handover construction |
| Bounded ISO CBOR encoding and decoding | Digital Credentials API transport |
| COSE issuer and device authentication | Wallet consent and storage |
| Issuance, presentation, and verification entry points | Platform SDK bindings |

## Install

```toml
[dependencies]
reallyme-mdoc = "0.1"
```

The default `native` feature enables the native cryptographic provider. Use
`default-features = false` with `wasm` for WebAssembly. The lower-level model
and CBOR surface remains available without `mdoc-crypto`.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
