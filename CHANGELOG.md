# Changelog

## 0.3.0

This release hardens authentication and verification boundaries while preserving
the existing EUDI and OpenID protocol profiles. The `did:me` core wire format
changes to authenticate its externally visible projection commitment.

### Security

- Every evaluated credential and presentation failure is terminal and remains
  visible in the verification report. Requested checks are mandatory, while an
  absent optional check remains explicitly skipped rather than fabricated.
- OAuth client-attestation trust receipts are bound to the exact compact JWT,
  and DPoP access-token verification requires the confirmed key thumbprint.
- OCSP processing rejects ambiguous duplicate certificate responses, accepts
  interoperable SHA-256 and SHA-1 CertIDs, derives issuer identifiers from the
  authenticated issuer key, rejects unsupported critical response extensions
  and oversized nonces, and treats response certificates as untrusted
  chain-building material. Parsed responses are sealed verification receipts;
  the WebAssembly lane fails closed when no Rust verifier is available.
- CRL parsing validates the issuer CA profile, authority-key identifiers, and
  revocation reasons before issuing an opaque parsed-CRL capability. Checking a
  CRL also verifies that its issuer key authenticates the target certificate.
- `did:me` signs every externally visible projection field, binds the genesis
  identifier inside the core engine, and exposes trusted-head and observed-
  successor validation for rollback and equivocation resistance.
- TSL pointer verification derives signer authorization from an authenticated
  parent list and applies the correct QWAC and QSeal certificate profiles.
  Qualified-type determination evaluates ASi and Sie restrictions before leaf
  claims, and semantically projects a list only after XML signature validation.
- Presentation verification requires configured nonce and audience bindings,
  validates ZK expiry, and removes the stateless SIOP response entry point.
- Committed-credential proofs verify against a caller-trusted issuer key and
  reject raw P-256 keys whose bytes do not match their declared SEC1 encoding.
- Legacy status lists receive a 24-hour maximum-age ceiling through the default
  `verify_status` policy, and token-list `exp` deadlines are exclusive.
  Replay storage uses store-owned wall time to validate
  exclusive absolute expiries, monotonic deadlines, protocol namespaces, a
  global capacity limit, and bounded per-protocol quotas. WebAssembly callers
  inject a clock because the platform has no portable process-monotonic clock.
- Brotli decoding rejects trailing data and non-RFC large-window streams, caps
  its window and output storage, and returns zeroizing, right-sized plaintext
  storage.
- SIOP request state values require at least 22 encoded characters, sufficient
  to carry 16 random bytes in unpadded base64url. Device-signed mdoc
  elements require matching MSO key authorizations, and empty authorization
  objects cannot be issued. SIOP callers remain responsible for generating the
  state value with at least 128 bits of cryptographic entropy.
- OAuth discovery rejects non-public issuer and endpoint URLs, including
  alternate IPv4-in-IPv6 encodings and local host aliases. Attestation client
  authentication applies the same restriction to JWT `aud` and configured
  expected-audience URLs.
- `did:web` rejects path-normalization aliases and percent-encoded unreserved
  characters. `did:key` accepts only its canonical base58btc representation;
  `did:cheqd` UUIDs are canonical lowercase; and EBSI verification methods are
  restricted to P-256 with absent `alg` or `ES256`, and secp256k1 with absent
  `alg` or `ES256K`, for the current legal-entity profile. Active EBSI registry
  documents must identify at least one controller.
- `did:jwk` rejects RSA public keys below 2,048 bits or above 16,384 bits,
  even moduli, and public exponents longer than eight bytes.
- Authenticated TSL pointer-parent failures map to the dedicated protobuf
  reason `TSL_POINTER_INVALID_PARENT` (1071), preserving the failure on the wire.
- mdoc issuance bounds authorization identifiers and implementation-defined
  key information. Committed proofs validate uncompressed P-256 points before
  binding them to the trusted issuer key.

### Privacy and robustness

- mdoc digest identifiers are randomized, and projected mdoc JSON values are
  zeroized on drop.
- Numeric claims normalize equivalent signed and unsigned values before
  commitment, and committed-credential salts are zeroized on all paths.
- Generated conformance evidence records every configured fuzz target and
  fails if an expected target is missing. Local evidence references are checked
  against real test functions and both positive and negative evidence.
- Published crate preflight builds and runs tests from each extracted crate
  archive, preventing tests from relying on files outside the package.

### Breaking API changes

- Public security error enums are marked `#[non_exhaustive]` where downstream
  exhaustive matching would prevent compatible typed-state additions.
- `TrustDecision`, `VerifiedTokenStatusList`, and parsed CRL values can only be
  created by their verification or parsing pipelines. Callers use read-only
  accessors instead of constructing these security capabilities directly.
- The standalone CRL core crate has been removed. Use the OpenSSL CRL parser
  and checker from `identity-revocation-crl-openssl`.
- SIOP authentication response verification takes the expected state in its
  only public protocol entry point.
- Committed-credential proof binding requires the trusted issuer public key.
- `SingleUseStore` operations require a `SingleUseNamespace`, no longer accept
  caller-supplied current time, and use the store's `SingleUseClock`. That clock
  now returns paired wall and monotonic readings through `SingleUseTime`.
  `SingleUseError::ClockRollback` is removed; rollback and forward-correction
  behavior is handled by bounded clock readings and both absolute and monotonic
  expiry deadlines instead. Constructors backed by the system clock are not
  available on `wasm32-unknown-unknown`; WebAssembly callers inject a clock.
- `DidCore` includes its signed projection commitment, and `BrotliError`
  includes a distinct trailing-data variant. Brotli decompression now returns
  `Zeroizing<Vec<u8>>`.
- The OpenSSL OCSP parser accepts certificate DER instead of OpenSSL handles;
  nonce-aware verification is available through
  `parse_ocsp_response_der_with_nonce`, and sealed `ParsedOcspResponse`
  receipts expose the authenticated response nonce through accessors.
- `AuthorizationServerMetadata` is non-exhaustive, includes `jwks_uri`, and is
  constructed with `AuthorizationServerMetadata::new`.
- `DidApiError` carries did:web failures through the typed
  `DidWeb(DidWebErrorReason)` variant. The corresponding protobuf reasons now
  preserve individual did:web transport and document-validation failures.
- Trust evaluation reports `PurposePolicyMismatch` when a receipt purpose is
  paired with a policy that does not enforce that purpose's requirements.
- Trusted-list ingestion requires the last accepted sequence number and rejects
  authenticated rollback before returning a verified list.
- The X.509 trusted-list helper is now explicitly a policy-only projection,
  binds CA/QC service identities to a CA certificate rather than an end-entity
  leaf, and requires a concrete validation time.
- VC validation exposes typed errors for required expiration, SD-JWT digest
  algorithm, presentation binding, and trusted issuer-key mismatches.

All workspace crates, including source-only internal crates, use version 0.3.0.
