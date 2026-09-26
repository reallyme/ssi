# reallyme-credential-audit

**Deterministic QEAA compliance and verification-provenance validation**

`reallyme-credential-audit` validates the evidence attached to qualified
electronic attestations of attributes. It provides typed models and bounded
validation for identity proofing, QTSP roles, key protection, status methods,
standards versions, and verification resolvers.

> Building an issuer, verifier, or wallet? Start with
> [`reallyme-identity`](https://crates.io/crates/reallyme-identity). Use this
> crate directly when implementing or reviewing the QEAA evidence layer.

## Scope

| This crate provides | The host application provides |
| --- | --- |
| QEAA compliance metadata | Trusted-list retrieval |
| Verification provenance | Certificate-chain verification |
| Resource limits and typed validation errors | Trust decisions and policy selection |
| Deterministic local validation | Operational audit logging and retention |

The name refers to credential audit evidence. This crate does not implement a
server audit trail or a compliance automation service.

## Install

```toml
[dependencies]
reallyme-credential-audit = "0.2.0"
```

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
