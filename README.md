<div align="center">

# ReallyMe SSI

**Identity primitives for digital credentials, presentations, trust, and selective disclosure**

[![Rust CI](https://github.com/reallyme/ssi/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/reallyme/ssi/actions/workflows/rust-ci.yml)
[![Fuzz](https://github.com/reallyme/ssi/actions/workflows/fuzz.yml/badge.svg)](https://github.com/reallyme/ssi/actions/workflows/fuzz.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.96-475569)](Cargo.toml)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

[Identity](https://github.com/reallyme/identity) · **SSI** · [OpenID4VCI](https://github.com/reallyme/openid4vci) · [OpenID4VP](https://github.com/reallyme/openid4vp) · [Wallet](https://github.com/reallyme/wallet) · [ZK](https://github.com/reallyme/zk)

</div>

ReallyMe SSI is the protocol-neutral identity and credential semantics layer of
the ReallyMe stack. It defines shared models and policy for credentials,
presentations, claims, canonical claim paths and commitments, selective
disclosure, DIDs, trust, status and revocation evidence, credential formats,
identity-oriented OAuth primitives, EUDI profiles, and stable protobuf/domain
integration contracts.

Credential and presentation envelopes such as SD-JWT and mdoc are implemented
independently of issuance and presentation sequencing. ReallyMe OpenID4VCI and
OpenID4VP build on these capabilities without duplicating credential, trust,
status, or disclosure logic.

SSI does not own HTTP orchestration, persistence, wallet lifecycle, key
management, generic cryptography, concrete ZK circuits, or platform SDK
packaging. External evidence and capabilities enter through explicit
interfaces, keeping the semantic core portable across server, native, and
WebAssembly environments.

> **Looking for the ReallyMe SDK?** Start with
> [ReallyMe Identity](https://github.com/reallyme/identity), the
> application-facing SDK for building issuers, verifiers, wallets, and
> identity-enabled applications. This repository supplies the shared identity
> and credential foundation beneath those SDKs.

## Capabilities

| Area | Responsibility |
| --- | --- |
| Identity data | Typed credentials, presentations, normalized claims, canonical paths, and DID documents |
| Credential and presentation envelopes | RFC 9901 SD-JWT, construction and verification of issuer-signed mdoc documents, DeviceResponse processing, the ReallyMe canonical-envelope JWT profile, and the `did:me` proof profile |
| Presentations | Protocol-neutral construction, validation, requested paths, and disclosure requirements |
| Claims and commitments | Claim registries, canonical commitments, matching, disclosure planning, and derivation requirements |
| Trust | X.509 policy, trusted-list processing, registration evidence, and native/Wasm trust boundaries |
| Status and revocation | Status-list validation and composition of supplied OCSP, CRL, and StatusList evidence |
| DIDs | Method-neutral DID models, validation, resolution boundaries, and pluggable method implementations |
| OAuth | Shared, transport-injected OAuth primitives consumed by higher-level protocol implementations |
| EUDI | ETSI EAA policy, EU PID profiles, relying-party registration, and requirement evidence |
| Integration | Rust APIs, canonical protobuf schemas, ProtoJSON, bounded codecs, and typed errors |
| Assurance evidence | Standards vectors, negative cases, requirement mappings, fuzzing, and release gates |

## Architecture

This diagram describes conceptual ownership and composition, not Cargo
dependency edges.

```text
                           Applications
                                │
                                ▼
                       ReallyMe Identity
                 application SDKs and composition
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
       OpenID4VCI          OpenID4VP              Wallet
         issuance       presentation/session   state · consent
            │               /       \          lifecycle · audit
            │              /         \
            └─────────────▼           ▼
                          SSI      ReallyMe ZK
                identity and credential   circuits and proof
                      semantics           infrastructure
                       /      \               /
                    JOSE      COSE            /
                       \       │             /
                        └──────┴────────────┘
                               ▼
                        reallyme/crypto
```

SSI defines what credentials, claims, commitments, trust evidence, status
evidence, and disclosure requirements mean. SD-JWT and mdoc implement
credential and presentation envelopes over those semantics. ReallyMe ZK is a
sibling foundation: it defines circuits, proof contracts, artifacts, and proof
providers for statements about SSI-owned semantics and commitments; it does
not become the owner of credential semantics.

OpenID4VCI sequences issuance. OpenID4VP sequences presentation and composes
credential and proof capabilities into verifier-bound sessions. Wallet owns
durable inventory, lifecycle, consent, persistence policy, and audit state.
ReallyMe Identity packages the complete stack for applications.

Generic cryptographic operations and JOSE and COSE mechanics remain in
[`reallyme/crypto`](https://github.com/reallyme/crypto),
[`reallyme/jose`](https://github.com/reallyme/jose), and
[`reallyme/cose`](https://github.com/reallyme/cose). SSI builds identity and
credential semantics on those foundations rather than reimplementing them.

### Repository boundaries

| Layer | Responsibility |
| --- | --- |
| [ReallyMe Identity](https://github.com/reallyme/identity) | Application SDKs, platform facades, and final composition |
| [ReallyMe OpenID4VCI](https://github.com/reallyme/openid4vci) | Issuance protocol mechanics and sequencing |
| [ReallyMe OpenID4VP](https://github.com/reallyme/openid4vp) | Presentation protocol mechanics, session binding, and credential/proof composition |
| ReallyMe SSI | Credential and identity semantics, envelopes, commitments, trust, status, DIDs, and disclosure policy |
| [ReallyMe Wallet](https://github.com/reallyme/wallet) | Inventory, lifecycle, consent, persistence policy, and audit state |
| [ReallyMe ZK](https://github.com/reallyme/zk) | Circuits, proof contracts, artifacts, and provider infrastructure |
| [crypto](https://github.com/reallyme/crypto) / [JOSE](https://github.com/reallyme/jose) / [COSE](https://github.com/reallyme/cose) | Lower-level cryptographic, signing, encryption, and encoding mechanics |

## Standards

The table describes the implemented SSI surface. It does not claim complete
implementation of every feature in a cited specification or external
certification.

| Standard or profile | Implemented SSI responsibility |
| --- | --- |
| RFC 9901 — Selective Disclosure for JWTs | SD-JWT issuance, disclosures, parsing, key binding, presentation, and validation policy |
| ISO/IEC 18013-5:2021 mdoc and mDL | Issuer-signed documents, DeviceResponse construction, issuer authentication, and DeviceAuth verification |
| W3C Verifiable Credentials Data Model 2.0 | Protocol-neutral credential and presentation models used by the supported envelope profiles |
| ReallyMe `did:me` proof | Dispatch and validation for the ReallyMe-defined `es256-jws-cid-2025` suite; this is not a general W3C Data Integrity cryptosuite implementation |
| W3C Decentralized Identifiers 1.0 | Method-neutral DID document types, validation and resolution boundaries, and pluggable DID methods |
| IETF Token Status List draft-21 | Bounded JWT and CWT status-evidence parsing and validation |
| ETSI EAA and EU PID profiles | Typed metadata and policy checks plus executable requirement evidence for the supported eIDAS-aligned surface |

Generic JWS, JWT, JWE, COSE Sign1, and COSE Key mechanics remain in their
foundational repositories rather than being reimplemented here.

## Which layer should I use?

| Goal | Start here |
| --- | --- |
| Build an issuer, verifier, wallet, or identity-enabled application | Use [ReallyMe Identity](https://github.com/reallyme/identity) |
| Implement issuance or presentation protocol behavior | Use [ReallyMe OpenID4VCI](https://github.com/reallyme/openid4vci) or [ReallyMe OpenID4VP](https://github.com/reallyme/openid4vp) |
| Integrate protocol-neutral credential, trust, status, DID, or disclosure behavior | Compose the `reallyme-ssi` facade in the ReallyMe source workspace |
| Use one independently published primitive | Select the corresponding component crate from its manifest and documentation |
| Develop or audit SSI | Use this repository and the complete gate described under Development |

## Repository structure

| Path | Purpose |
| --- | --- |
| `crates/ssi` | Source-composition facade consumed by ReallyMe protocols and services |
| `crates/proto`, `crates/proto-codec` | Canonical SSI protobuf schemas, generated messages, bounded codecs, and validated mappings |
| `crates/credential`, `crates/claims` | Credential semantics, issuance APIs, normalized claims, commitments, and disclosure validation |
| `crates/envelopes/*` | SD-JWT, mdoc, canonical-envelope JWT, supported Data Integrity proof, and envelope-profile implementations |
| `crates/did/*` | DID primitives, validation and resolution engines, APIs, and method implementations |
| `crates/presentation/*` | Protocol-neutral presentation models, policy, validation, and SD-JWT support |
| `crates/trust/*` | Trust policy, X.509, trusted lists, JAdES, and Wasm trust boundaries |
| `crates/status`, `crates/revocation` | Local status validation and supplied revocation-evidence composition |
| `crates/delivery/*`, `crates/oauth` | Delivery artifacts and shared, transport-injected OAuth primitives |
| `crates/eudi/*`, `crates/audit` | EUDI registration, ETSI EAA, QEAA metadata, and audit-evidence policy |
| `conformance`, `vectors`, `fuzz` | Requirement inventory, standards vectors, negative cases, and adversarial testing |

The facade exposes identity-owned capabilities through stable paths including
`reallyme_ssi::credential::api`, `reallyme_ssi::delivery`,
`reallyme_ssi::trust`, `reallyme_ssi::claims`, `reallyme_ssi::did`,
`reallyme_ssi::presentation`, `reallyme_ssi::oauth`, and
`reallyme_ssi::single_use`.

## Architecture boundaries

Credential models own credential kind, profile, assurance, issuer, validity,
status, subject binding, claim commitments, optional compliance evidence, and
issuer signatures. OpenID exchange state, wallet persistence, and
envelope-specific parsing remain outside those generic models.

Status components validate supplied evidence. Hosts are responsible for
fetching, caching, and native OCSP or CRL provider selection. Trust components
evaluate supplied evidence without acquiring ambient network authority.

Disclosure policy determines which claims may be disclosed and which verifier
requirements need derivation. Concrete ZK circuit selection, witness building,
proving, verification, and protocol-specific proof formats remain outside SSI
and are composed by OpenID4VP.

The DID framework is method-neutral. Individual DID methods integrate through
explicit method interfaces rather than coupling credential or protocol models
to a specific DID implementation.

Generated protobuf types and bounded codecs form the durable integration
contract. JSON is used where standards require interoperability; it is not a
second in-process operation protocol.

Platform packaging is provided by ReallyMe Identity. Swift, Kotlin,
TypeScript, native, and WebAssembly artifacts are composed there rather than
shipped as independent SSI runtimes.

## Development

SSI is developed alongside the JOSE, COSE, and shared protobuf repositories.
Use the checkout layout required by CI:

```text
<workspace>/reallyme/ssi
<workspace>/reallyme/jose
<workspace>/reallyme/cose
<workspace>/me-id/protos
```

`me-id/protos` supplies imported protobuf contracts for linting, generation,
freshness, and wire-compatibility checks. The JOSE and COSE checkouts supply the
pinned upstream conformance suites exercised by the complete repository gate.
Published foundational crates—`reallyme-crypto`, `reallyme-codec`,
`reallyme-jose`, and `reallyme-cose`—remain version-pinned dependencies.

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

Contributor-facing crate boundaries are documented in
[Architecture](docs/ARCHITECTURE.md). Standards requirements and generated
evidence are documented in the executable
[conformance inventory](conformance/README.md). Cargo metadata and release
preflight are the authoritative package inventory.

## Security

SSI processes credentials, identity attributes, trust evidence, and
cryptographic bindings. Parsers and codecs apply explicit input bounds;
verification receives trust, status, time, and network-derived evidence through
typed boundaries rather than ambient access. Production paths use typed errors,
reject malformed or invalid credential signatures and SSI-owned proofs, and
keep secret-bearing material behind explicit ownership and redacted diagnostic
boundaries.

Report vulnerabilities through the [security policy](SECURITY.md). Do not
include credentials, identity attributes, private keys, trust evidence, access
tokens, or production identity data in reports.

## Versioning

SSI is in active pre-1.0 development. Workspace crates advance in lockstep, but
only component crates whose manifests opt into publication are released to
crates.io; the `reallyme-ssi` facade remains a source-workspace composition
crate. Public Rust API changes follow Cargo's pre-1.0 compatibility rules.
Protobuf schemas additionally pass freshness and wire-compatibility gates
because they form cross-language integration contracts. Public crates declare
Rust 1.96 as their minimum supported Rust version.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

Third-party components retain their own licenses and notices.

## Copyright and Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe® is a registered trademark of ReallyMe LLC.
