# reallyme-trust-x509

**Portable X.509 parsing and policy for identity trust decisions**

`reallyme-trust-x509` parses certificates, verifies bounded chain signatures,
and evaluates data-driven certificate policy. It includes eIDAS and EUDI
profiles, qualified-certificate statement parsing, and typed trusted-list
service projections.

> Building an issuer, verifier, or wallet? Start with
> [`reallyme-identity`](https://crates.io/crates/reallyme-identity). Use this
> crate directly when implementing the X.509 parsing and policy boundary.

## Scope

| This crate provides | The host application provides |
| --- | --- |
| Bounded DER and PEM parsing | Certificate and trusted-list retrieval |
| Certificate metadata and QCStatements | Path discovery and trust-store management |
| eIDAS/EUDI policy presets | Application trust policy |
| Portable chain-signature verification | Final trust decisions |

## Install

```toml
[dependencies]
reallyme-trust-x509 = "0.2.0"
```

The default `native` feature enables native verification. Disable default
features and enable `wasm` for WebAssembly builds.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
