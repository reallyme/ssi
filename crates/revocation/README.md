# reallyme-revocation

**Credential revocation and suspension policy over resolved status evidence**

`reallyme-revocation` combines OCSP, CRL, and Status List evidence into a
protocol-neutral credential status decision. It includes bounded evidence
caching, composite evaluation, explicit soft-fail policy, and presets for
common trust profiles.

> Building an issuer, verifier, or wallet? Start with
> [`reallyme-identity`](https://crates.io/crates/reallyme-identity). Use this
> crate directly when the surrounding system already resolves status evidence.

## Scope

| This crate provides | The host application provides |
| --- | --- |
| Composite status evaluation | OCSP, CRL, and Status List retrieval |
| Bounded in-memory evidence caching | Transport, retry, and freshness scheduling |
| Explicit soft-fail behavior | Trust-store and network policy |
| Typed revocation decisions and errors | OpenID protocol sequencing |

Network access is never ambient. Callers supply resolved evidence through
explicit interfaces.

## Install

```toml
[dependencies]
reallyme-revocation = "0.2.0"
```

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
