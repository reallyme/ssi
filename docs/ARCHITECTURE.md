# Repository Architecture

This repository owns protocol-neutral self-sovereign identity core behavior.
Its consumers include the OpenID protocol repositories, wallet, the public
identity SDK, services, conformance tooling, and other internal identity
infrastructure.

## Ownership Boundaries

- `crates/ssi` owns the composed Rust facade with Cargo package name
  `reallyme-ssi`. It remains source-only until its support graph is
  deliberately publishable. The workspace root is virtual.
- `crates/credential` owns canonical credential semantics. Representation and
  transport envelopes such as SD-JWT, mdoc, JWT-VC, and Data Integrity remain
  under `crates/envelopes`.
- `crates/presentation` owns validation, policy, APIs, and implementations.
  `crates/proto` owns presentation wire and data-model messages, while
  `crates/proto-codec` owns their authored validation and conversion; these
  layers are deliberately separate.
  Existing Cargo package names retain the established `vp` vocabulary because
  they describe verifiable-presentation APIs and are already dependency
  identities. Directory names follow the broader `presentation` ownership
  taxonomy; renaming published or consumed package identities is a separate
  compatibility change, not part of this repository move.
- `crates/trust` owns trust implementations. `crates/trust/wasm` is an
  internal implementation adapter, not a public SDK binding.
- `crates/trust/jades` owns reusable ETSI TS 119 182-1 JAdES Baseline policy
  over an already authenticated compact-JWS result. JOSE implementations own
  envelope parsing and cryptographic verification; consuming applications
  retain document-profile rules such as TS 119 602 signer-subject matching.
- `crates/oauth` owns reusable OAuth substrate only. OpenID4VCI and OpenID4VP
  endpoint flows, sessions, and state machines stay in their protocol
  repositories.
- Services consume this repository; service and product business logic do not
  live here.

## Dependency and Protocol Boundaries

SSI owns protocol-neutral identity semantics. Focused lower-level ReallyMe
packages own cryptographic and serialization mechanics:

| Capability | Owner |
| --- | --- |
| Cryptographic algorithms, keys, randomness, and primitive verification | [`reallyme/crypto`](https://github.com/reallyme/crypto) |
| JSON Web Signature, Encryption, Key, and Token mechanics | [`reallyme/jose`](https://github.com/reallyme/jose) |
| COSE structures and COSE key mechanics | [`reallyme/cose`](https://github.com/reallyme/cose) |
| Bounded binary and text codecs | [`reallyme/codec`](https://github.com/reallyme/codec) |

SSI consumes these capabilities through their public facades. Domain crates do
not select primitive cryptographic or encoding backends directly. Narrow parser
or adapter dependencies remain confined to their owning crate and are enforced
by `scripts/check-shared-dependency-boundaries.mjs`.

`crates/oauth` owns reusable OAuth substrate such as PAR, DPoP, PKCE,
authorization-server metadata, and attestation client authentication.
OpenID4VCI and OpenID4VP repositories own endpoint orchestration, HTTP
transport, session state, nonce persistence, and protocol conformance.

Disclosure policy may determine that a derived claim is required, but SSI does
not select a zero-knowledge proof system, build witnesses, prove statements, or
verify protocol-specific proofs. Those capabilities are composed above this
repository, so SSI has no dependency on `reallyme/zk`.

## Public Rust Surface

`reallyme-ssi` is the composed Rust facade. It exposes stable modules including
`reallyme_ssi::credential::api`, `reallyme_ssi::delivery`,
`reallyme_ssi::trust`, and generated-protobuf surfaces under the SSI facade.
The facade remains source-only until its full dependency graph is deliberately
accepted as public API. The smaller package set required by ReallyMe Identity
is published independently.

## Runtime and Provider Policy

Rust identity crates expose only `native` and `wasm` backend lanes. They must
not expose cargo features named `swift` or `kotlin`; platform provider selection
belongs to `reallyme/identity`.

Unsupported providers fail closed with a typed error. There is no silent
provider fallback. The `crates/envelopes/mdoc` implementation owns
issuer-signed mdoc issuance and verification plus ISO/IEC 18013-5
DeviceResponse and DeviceAuth verification. OpenID handover and transport state
remain in the protocol repositories.

A composed application embeds one ReallyMe Rust binary or Wasm module. Handles
and state do not cross independent Wasm instances. Final FFI, JNI, Swift,
Kotlin, TypeScript, native, and composed Wasm packaging belongs to
`reallyme/identity`.

## Protobuf Ownership

```yaml
repository: ssi
proto_layout: canonical
proto_root: crates/proto
canonical_proto_crate: crates/proto
codec_crate: crates/proto-codec
```

Every SSI-owned schema lives below `crates/proto/proto`. The canonical
`crates/proto` package owns all standards-level generated modules. The product
operation contract is owned by `reallyme/identity` and imports these neutral
messages without creating a reverse dependency. Compatibility packages named
`crates/proto-*` are forbidden except for the authored `crates/proto-codec`
validation and conversion boundary. The repository has no root `protos/`
mirror.

This shape gives the multi-domain repository one auditable schema root and one
generated-code owner. `crates/proto-codec` remains the sole authored validation
and conversion boundary for SSI-owned domain messages.

External schemas are imported from exact upstream sources during generation.
They are not copied into this repository. The shared module inventory in
`scripts/proto-workspace.sh` resolves the external `me-id` schema alongside the
SSI-owned modules.

## Downstream SDK Ownership

The `reallyme/identity` repository owns public FFI, JNI, Swift, Kotlin,
Android, TypeScript, and composed Wasm bindings and packages, along with
application-developer examples and cross-language generated sources. Those
surfaces must not be added under root `bindings/`, `gen/`, `packages/`, or
`examples/` directories here.

## Verification Data

- `vectors/` owns reusable cross-crate and cross-language vectors.
- `conformance/fixtures/` owns inputs that exist only for conformance runs.
- `reallyme/identity-conformance` retains generated release evidence; SSI owns
  the requirement mappings and the generator that produces the clean bundle.
- OIDF certification orchestration remains outside this repository in
  `reallyme/identity-conformance`.

## Static Resources

`contexts/` owns repository-wide JSON-LD contexts. These are data resources,
not Rust crates, and therefore do not live beneath `crates/`.
