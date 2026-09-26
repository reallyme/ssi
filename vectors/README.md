# Conformance Vectors

This directory contains reusable cross-crate and cross-language vector
manifests generated from portable JSON and text fixtures. The files are
intentionally language-neutral: no Rust
serialization formats, no test-only structs, and no platform-specific paths
beyond repository-relative fixture references.

Inputs that exist only to drive a conformance run belong in
`conformance/fixtures/`; generated execution evidence belongs in
the generated release bundle retained by `reallyme/identity-conformance`.

Regenerate with:

```sh
node scripts/generate_conformance_vectors.mjs
```

Current suites:

- `jwe-compact.json`: compact JWE direct and ECDH-ES JSON payload vectors for
  `A128GCM`, `A192GCM`, and `A256GCM` over P-256, native P-384, and native
  P-521, plus a tampered-tag failure case.
- `jwk-thumbprint.json`: RFC 7638 JWK thumbprint vectors for EC, OKP, RSA, and
  missing-required-member failure.
- `sd-jwt-compact.json`: compact SD-JWT presentation vectors from pinned
  upstream and ReallyMe fixtures.
- `sd-jwt-json-serialization.json`: JSON-serialization SD-JWT presentation
  vectors from pinned upstream fixtures.
- `mdoc-issuer-signed.json`: portable mdoc issuer-signed item and MSO
  `valueDigests` vectors for deterministic ISO 18013-5 digest binding.
- `status-list.json`: portable status-list vectors for deterministic signing
  payloads, little-endian bit semantics, signature failure, stale/not-yet-valid
  evidence, revocation, suspension, and index bounds.
- `x509-trust-policy.json`: portable projected X.509/QWAC and TSL trust-service
  policy vectors for certificate policy/QCStatement screening, territory,
  status freshness, and certificate binding behavior. These are structured
  policy vectors, not raw certification-chain fixtures.
- `resource-limits.json`: shared resource-limit constants used by SDK
  lanes and conformance reports.
- `did-methods.json`: language-neutral DID method syntax and generation
  vectors for `did:me`, `did:key`, `did:jwk`, `did:web`, `did:ebsi`,
  `did:cheqd`, and `did:ion`.
- `claims/normalization.json`: cross-format claim normalization vectors for
  SD-JWT, mdoc, JWT-VC, W3C VC, presentation proto, and credential proto.
- `claims/predefined-credentials.json`: predefined credential claim vectors for
  EU PID, age, address, EAA, company, tax, passport, driving licence, diploma,
  health, professional licence, and eIDAS VID profiles.
- `claims/catalog-sources.json`: source-to-registry coverage map for every
  predefined registry-backed claims catalog, with third-party references limited
  to pinned official sources and ReallyMe extensions marked as internal
  baselines, aliases, projections, or preserve-only catalogs. It also records
  that EU law establishes an attribute/scheme catalogue process, but no
  populated official sector field catalogue is pinned by this repository yet.
- `credential/canonical.json`: canonical credential payload, hash, signature,
  status, and revocation composition vector.
