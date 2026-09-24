# ReallyMe Credential Claims

`reallyme-credential-claims` is the identity core crate for credential
claim semantics. It is intentionally below OpenID, wallet, SDK, FFI, and
service layers.

The crate owns:

- normalized claim values for identity data;
- canonical `/claims/...` paths and path resolution;
- claim registries and claim definitions;
- credential claim payload validation;
- local disclosure permission checks.

It does not own:

- credential envelope parsing;
- OpenID4VCI or OpenID4VP protocol behavior;
- DCQL syntax;
- Connect or HTTP services;
- FFI, wasm-bindgen, Swift, Kotlin, or TypeScript package facades;
- wallet storage, consent, or trust decisions.

## Proto And JSON Boundary

Protobuf and Buffa are first-class boundaries in the identity workspace. Native
protobuf/Buffa adapters should map directly into `ClaimValue`, `ClaimPath`,
`ClaimPathEntry`, and `ClaimsRegistry` rather than inventing parallel claim
semantics. Path-entry streams can be normalized with
`claim_value_from_path_entries`, which is the intended bridge for generated
messages that carry a canonical claim path plus a typed value oneof.

Canonical paths use JSON Pointer-style `~0` and `~1` escaping for object fields,
plus `~2` for numeric object member names. The extra escape is required because
unescaped decimal path segments are array selectors, while external credential
profiles such as ARF PID use numeric object keys for age-over claims.

JSON is still mandatory at external credential, DID, and OpenID boundaries, but
JSON must enter this crate through explicit normalization such as
`claim_value_from_json_slice`. That parser detects duplicate object members and
rejects non-ASCII claim names before data can be treated as trusted identity
claims.

## Layering Rules

`crates/claims` is safe for lower-layer identity consumers such as envelope,
presentation, and disclosure-policy crates. Higher layers may adapt protocol
selectors into claim paths, but this crate must remain protocol-neutral.

Compression, when needed for large claim-bearing protobuf or JSON payloads,
belongs at the transport or envelope boundary through
`reallyme-compression-brotli`, not inside this crate.

## Built-In Profiles

The crate ships registry-backed claim catalogs for predefined credential shapes
that are already stable enough to validate concrete claim payloads:

- `eu.pid.v1` for EU PID natural-person attributes.
- `eu.eaa.v1` for common electronic attestation metadata.
- `eu.age.v1` for age and age-over credentials derived from PID attributes.
- `eu.address.v1` for residence address, contact, and PID issuing metadata.
- `eu.diploma.v1` for diploma and learning credentials.
- `eu.driving_license.v1` for mobile driving licence attributes.
- `eu.professional_license.v1` for professional licence and certification
  attributes.
- `eu.health.v1` for European Health Insurance Card entitlement attributes.
- `eu.company.v1` for EU legal-person PID identity and business identifiers.
- `eu.tax.v1` for a narrow tax-residency and tax-identifier baseline.
- `eu.eidas-vid.v1` for the eIDAS verified-identity view over EU PID.
- `eu.passport.v1` for EU-facing passport policy selection backed by the ICAO
  passport catalog.
- `icao.passport.v1` for ICAO 9303 passport and LDS-oriented attributes.

These registries are intentionally conservative and limited to their stated
scope. EU PID, address, company, and tax fields are aligned to the
PID natural-person and legal-person attribute tables in Commission Implementing
Regulation (EU) 2024/2977 where the regulation names those attributes.
Regulation (EU) 2024/1183 Annex VI provides category-level authority for
address, age, education, professional, permit/licence, and legal-person
financial/company data; Commission Implementing Regulation (EU) 2025/1569
establishes the attribute and scheme catalogue process, but no populated
official sector field catalogue is pinned here yet. Passport fields are aligned
to ICAO travel-document semantics. National extensions, sector-specific field
catalogues, and scheme-specific identifier rules require a profile-specific
source before being added to these built-in claim definitions.

Disclosure policy also recognizes `eu.kyc.v1`, which remains policy-only
because KYC is a relying-party verification use case, not one authoritative EU
credential catalog. See `PREDEFINED_CREDENTIALS.md` for the release matrix,
source authority, supported formats, and vector coverage for each predefined
credential.
