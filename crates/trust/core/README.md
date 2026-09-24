# reallyme-trust-core

**Deterministic trust evaluation over parsed X.509 evidence**

`reallyme-trust-core` evaluates certificate chains against explicit trust,
status, and chain-link policy. Signature and status verification are injected,
keeping the decision engine deterministic and portable across native and
WebAssembly environments.

> Building an issuer, verifier, or wallet? Start with
> [`reallyme-identity`](https://crates.io/crates/reallyme-identity). Use this
> crate directly when supplying a trust engine or policy adapter.

## Scope

| This crate provides | The host application provides |
| --- | --- |
| Bounded candidate-chain evaluation | DER parsing and path discovery |
| eIDAS/ETSI chain-link policy | Trusted-list and intermediate retrieval |
| Typed trust decisions and failure reasons | Trust-store lifecycle |
| Signature and status verifier interfaces | Cryptographic and revocation providers |

## Install

```toml
[dependencies]
reallyme-trust-core = "0.1"
```

The default `native` feature selects native dependencies. Disable default
features and enable `wasm` for WebAssembly builds.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
