# reallyme-credential-audit

**Deterministic QEAA metadata screening and verification-provenance models**

`reallyme-credential-audit` provides typed models and bounded structural
screening for metadata attached to qualified electronic attestations of
attributes: identity proofing, QTSP roles, key protection, status methods,
standards versions, and verification resolvers.

Metadata screening is not cryptographic verification. A successful screen does
not establish a certificate path, qualified trust-list authorization, issuer
binding, envelope signature, or current credential status. Those guarantees
must come from the owning trust, envelope, and status layers.

> Building an issuer, verifier, or wallet? Start with
> [`reallyme-identity`](https://crates.io/crates/reallyme-identity). Use this
> crate directly when implementing or reviewing the QEAA evidence layer.

## Scope

| This crate provides | The host application provides |
| --- | --- |
| QEAA compliance metadata | Trusted-list retrieval |
| Verification provenance | Certificate-chain verification |
| Resource limits and typed validation errors | Trust decisions and policy selection |
| Deterministic local metadata screening | Operational audit logging and retention |

The name refers to credential audit evidence. This crate does not implement a
server audit trail or a compliance automation service.

## Install

```toml
[dependencies]
reallyme-credential-audit = "0.3.3"
```

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
