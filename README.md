<div align="center">

# ReallyMe SSI

**Identity primitives for digital credentials, presentations, trust, and selective disclosure**

[![Rust CI](https://github.com/reallyme/ssi/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/reallyme/ssi/actions/workflows/rust-ci.yml)
[![Fuzz](https://github.com/reallyme/ssi/actions/workflows/fuzz.yml/badge.svg)](https://github.com/reallyme/ssi/actions/workflows/fuzz.yml)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE-MIT)

</div>

`reallyme-ssi` provides the shared identity foundation for digital credentials
across the ReallyMe stack. It defines protocol-neutral models and operations
for credentials, presentations, claims, DIDs, trust, status, and selective
disclosure.

Credential formats including SD-JWT, mdoc, JWT-VC, and W3C Data Integrity are
implemented here independently of issuance and presentation protocols.
OpenID4VCI and OpenID4VP build on these capabilities without duplicating
credential, trust, or disclosure logic.

The core is independent of HTTP frameworks, persistence, network access, key
management, and platform SDKs. External evidence and capabilities are supplied
through explicit interfaces, keeping identity processing portable across
server, native, and WebAssembly environments.

> **Looking for the ReallyMe SDK?** Start with
> [ReallyMe Identity](https://github.com/reallyme/identity), the
> application-facing SDK for building issuers, verifiers, wallets, and
> identity-enabled applications. This repository provides the underlying
> credential, presentation, trust, and identity primitives.

This repository is in active pre-1.0 development. Its public contracts are
standards-level Rust and protobuf surfaces; application operations and platform
packages remain in ReallyMe Identity.

## Capabilities

| Area | Support |
| --- | --- |
| Identity data | Typed DID documents, verification methods, credentials, presentations, normalized claims, and canonical paths |
| Credential formats | RFC 9901 SD-JWT, issuer-signed mdoc issuance and verification, JWT-VC, and W3C Data Integrity |
| Presentations | Protocol-neutral presentation construction, validation, and disclosure requirements |
| Trust | X.509 helpers, trust policy, trusted-list processing, registration evidence, and Wasm-safe trust boundaries |
| Status and revocation | Status-list validation and composition of resolved OCSP, CRL, and StatusList evidence |
| Selective disclosure | Claim matching, disclosure planning, derivation requirements, and credential commitments |
| DIDs | Method-neutral DID models, resolution boundaries, and pluggable DID methods |
| OAuth | Shared OAuth primitives consumed by higher-level protocol implementations |
| EUDI | ETSI EAA metadata, EU PID profiles, relying-party registration, and normative requirement indexes |
| Integration | Rust APIs, canonical protobuf schemas, ProtoJSON, bounded codecs, and typed errors |
| Verification | Standards vectors, negative cases, conformance evidence, and fuzz testing |

## Architecture

```text
                    Credential semantics
                           SSI
                            │
                 canonical credential model
                            │
           ┌────────────────┼────────────────┐
           ▼                ▼                ▼
       SD-JWT VC          mdoc        ReallyMe ZK proof
           └────────────────┼────────────────┘
                            ▼
                       OpenID4VP
                            │
                         Verifier
```

SSI owns credential meaning, canonical commitments, and format-independent
disclosure requirements. SD-JWT VC, mdoc, and ReallyMe ZK proofs are different
ways to represent or prove those semantics. The relationship is semantic: SSI
does not depend on the ZK repository or select concrete circuits.

```text
                 reallyme/crypto
                  /           \
                 ▼             ▼
                SSI            ZK
                 \             /
                  └─────┬─────┘
                        ▼
                    OpenID4VP
                        │
                      Wallet
                        │
                     Identity
```

SSI and ZK are independently buildable sibling foundations. OpenID4VP composes
their public contracts, Wallet manages presentation state and consent, and
ReallyMe Identity provides the application-facing SDK layer.

SSI provides the protocol-neutral identity capabilities shared by ReallyMe's
issuance, presentation, wallet, and application layers.

Cryptographic operations and generic JOSE and COSE structures are provided by
[`reallyme/crypto`](https://github.com/reallyme/crypto),
[`reallyme/jose`](https://github.com/reallyme/jose), and
[`reallyme/cose`](https://github.com/reallyme/cose). SSI builds credential
formats, identity models, trust evaluation, status validation, DIDs, and
disclosure policy on those foundations.

Protocol sequencing is implemented by
[`reallyme/openid4vci`](https://github.com/reallyme/openid4vci) and
[`reallyme/openid4vp`](https://github.com/reallyme/openid4vp). Wallet inventory,
consent, storage, lifecycle, and audit state are provided by
[`reallyme/wallet`](https://github.com/reallyme/wallet).

The DID framework is method-neutral. Individual DID methods integrate through
explicit method interfaces rather than being coupled to credential or protocol
implementations.

Platform packaging is provided by ReallyMe Identity. Swift, Kotlin, TypeScript,
native, and WebAssembly distributions compose the lower-level Rust components
into application-facing artifacts rather than loading independent runtimes.

## Standards

| Standard or profile | SSI responsibility |
| --- | --- |
| RFC 9901 — Selective Disclosure for JWTs (SD-JWT) | Disclosure construction, parsing, key binding, presentation, and validation policy |
| ISO/IEC 18013-5 mdoc and mDL | Issuer-signed documents, DeviceResponse construction, issuer authentication, and DeviceAuth verification |
| W3C Verifiable Credentials Data Model 2.0 | Protocol-neutral credential and presentation semantics plus Data Integrity dispatch |
| W3C Decentralized Identifiers (DIDs) v1.0 | Method-neutral DID document types, resolution boundaries, and pluggable DID methods |
| IETF Token Status List draft-21 | JWT and CWT status-evidence validation with bounded inputs |
| ETSI EAA and EU PID profiles | Typed conformance policy and requirement evidence used by eIDAS-aligned applications |

Generic JWS, JWT, JWE, COSE Sign1, and COSE Key mechanics remain in their
foundational repositories rather than being reimplemented here.

## Workspace

| Path | Purpose |
| --- | --- |
| `crates/ssi` | Composed Rust facade consumed by protocols and services. |
| `crates/proto`, `crates/proto-codec` | Canonical SSI protobuf schemas, generated messages, bounded codecs, and validated mappings. |
| `crates/credential`, `crates/claims` | Credential semantics, issuance APIs, normalized claims, and disclosure validation. |
| `crates/envelopes/*` | SD-JWT, mdoc, JWT-VC, Data Integrity, and envelope-profile implementations. |
| `crates/did/*` | DID primitives, resolution engine, APIs, and method adapters. |
| `crates/presentation/*` | Protocol-neutral presentation policy, validation, and SD-JWT support. |
| `crates/trust/*` | Trust policy, X.509, trusted lists, JAdES, and Wasm boundaries. |
| `crates/status`, `crates/revocation` | Local status validation and resolved revocation-evidence composition. |
| `crates/delivery/*`, `crates/oauth` | Delivery artifacts and shared OAuth primitives. |
| `crates/eudi/*`, `crates/audit` | EUDI registration, ETSI EAA, QEAA metadata, and audit-evidence policy. |
| `conformance`, `vectors`, `fuzz` | Requirement inventory, standards vectors, negative cases, and adversarial testing. |

The facade exposes identity-owned capabilities through stable paths including
`reallyme_ssi::credential::api`, `reallyme_ssi::delivery`,
`reallyme_ssi::trust`, `reallyme_ssi::claims`, `reallyme_ssi::did`,
`reallyme_ssi::presentation`, `reallyme_ssi::oauth`, and
`reallyme_ssi::single_use`.

## Getting Started

| Goal | Start here |
| --- | --- |
| Build an application with ReallyMe | Use [ReallyMe Identity](https://github.com/reallyme/identity), the application-facing SDK. |
| Integrate a credential protocol | Consume the `reallyme-ssi` facade from the corresponding ReallyMe source workspace. |
| Use bounded Brotli independently | Use the published `reallyme-compression-brotli` crate. |
| Develop SSI | Clone this repository and run the repository gate; no sibling checkout is required. |

Published foundational crates—`reallyme-crypto`, `reallyme-codec`,
`reallyme-jose`, and `reallyme-cose`—are consumed at reviewed versions. The SSI
facade remains a source-workspace composition crate until its private internal
dependencies are approved for publication.

## Architecture Boundaries

Credential models define credential kind, profile, assurance, issuer, validity,
status, subject binding, claim commitments, optional compliance evidence, and
issuer signatures. OpenID exchanges, wallet persistence, and envelope-specific
parsing remain outside those models.

Status components validate supplied evidence; hosts are responsible for
fetching, caching, and native OCSP or CRL provider selection. Trust components
evaluate supplied evidence without acquiring ambient network access.

Disclosure policy determines which claims may be disclosed and which verifier
requirements need derivation. Concrete ZK circuit selection, witness building,
proving, verification, and protocol-specific proof formats remain outside SSI
and are composed by OpenID4VP.

Generated protobuf types and bounded codecs form the durable integration
contract. JSON remains an interoperability format where required by a standard
rather than a second in-process operation protocol.

## Development

Contributor-facing repository boundaries are documented in
[Architecture](docs/ARCHITECTURE.md). Standards requirements and generated
verification evidence are documented alongside the executable
[conformance inventory](conformance/README.md).

Run the repository gate and core workspace checks before submitting changes:

```sh
cargo fmt --check
scripts/lint-protos.sh
node scripts/check_release_readiness.mjs
cargo clippy --workspace --all-targets --all-features -- -D warnings
node scripts/run_bounded_nextest.mjs native
cargo check --workspace --no-default-features --features wasm --target wasm32-unknown-unknown
cargo deny check
```

## Security

SSI processes credentials, identity attributes, trust evidence, and
cryptographic bindings. Production paths use typed errors, reject malformed
signatures and proofs, and keep secret material behind explicit ownership
boundaries.

Follow the [security policy](SECURITY.md) when reporting a vulnerability. Do
not include credentials, identity attributes, private keys, trust evidence, or
production identity data in reports.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

Third-party components retain their own licenses and notices.

## Copyright and Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe® is a registered trademark of ReallyMe LLC.
