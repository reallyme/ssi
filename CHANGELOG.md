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
- OCSP response and delegated-responder certificate signatures using SHA-1 or
  MD5 are rejected. Embedded delegated-responder certificates must carry an
  appropriate digital-signature key usage. JAdES validation rejects the
  unsupported `sigD` signature-detached mechanism instead of ignoring it.
- CRL parsing validates the issuer CA profile, authority-key identifiers, and
  revocation reasons before issuing an opaque parsed-CRL capability. Checking a
  CRL also verifies that its issuer key authenticates the target certificate.
  The default freshness policy honors the authenticated `nextUpdate`; a maximum
  age remains available as an explicit relying-party policy.
- `did:me` signs every externally visible projection field, binds the genesis
  identifier inside the core engine, and exposes trusted-head and observed-
  successor validation for rollback and equivocation resistance.
- TSL pointer verification derives signer authorization from an authenticated
  parent list and applies the correct QWAC and QSeal certificate profiles.
  Qualified-type determination evaluates ASi and Sie restrictions before leaf
  claims, combines every purpose-scoped row for one service key, and cannot
  mask a withdrawal with a sibling grant. Structurally ambiguous service rows
  become non-authorizing without discarding unrelated providers, and semantic
  projection occurs only after XML signature validation.
- Trusted-list projection accepts bounded deployed SKI representations, exact
  duplicate service rows, and repeated current-state history rows without
  weakening authorization. Noncanonical SKIs remain non-binding, while a
  conflicting duplicate or malformed policy qualifier makes only that service
  key indeterminate. A fixed 30-document EU snapshot corpus guards this boundary.
- Presentation verification requires configured nonce and audience bindings,
  validates ZK expiry, and removes the stateless SIOP response entry point.
- Committed-credential proofs verify against a caller-trusted issuer key and
  reject raw P-256 keys whose bytes do not match their declared SEC1 encoding.
- Legacy status lists receive a 24-hour maximum-age ceiling through the default
  `verify_status` policy, and token-list `exp` deadlines are exclusive.
  Composite credential revocation verification always checks the credential's
  own status-list entry as well as the issuer certificate.
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
  characters, including percent-encoded port separators such as `%3A443`.
  Standard JWK verification-method pairs and extensible Multikey codecs remain
  accepted. `did:key` accepts only its canonical base58btc representation;
  `did:cheqd` UUIDs are canonical lowercase; and EBSI verification methods are
  restricted to P-256 with absent `alg` or `ES256`, and secp256k1 with absent
  `alg` or `ES256K`, for the current legal-entity profile. Active EBSI registry
  documents must identify at least one controller.
- `did:jwk` rejects RSA public keys below 2,048 bits or above 16,384 bits,
  even moduli, public exponents longer than eight bytes, and fully specified
  algorithm names such as `Ed25519` and `ESP256` where JOSE identifiers are
  required.
- Authenticated TSL pointer-parent failures map to the dedicated protobuf
  reason `TSL_POINTER_INVALID_PARENT` (1071), preserving the failure on the wire.
- mdoc issuance bounds authorization identifiers and implementation-defined
  key information. Committed proofs validate uncompressed P-256 points before
  binding them to the trusted issuer key.

### Privacy and robustness

- mdoc digest identifiers are randomized, and projected mdoc JSON values are
  zeroized on drop.
- SD-JWT top-level disclosure classifies dotted and URI claim names by
  structure rather than path-string syntax. Presentation selection indexes
  reconstructed arrays, ignores decoys, and rejects absent requested paths.
- Numeric claims normalize equivalent signed and unsigned values before
  commitment while preserving the 0.2.x `RM-CV-JCS-V1` integer tags, and
  committed-credential salts are zeroized on all paths.
- Generated conformance evidence records every configured fuzz target and
  fails if an expected target is missing. Local evidence references are checked
  against real test functions and both positive and negative evidence.
- Published crate preflight builds and runs tests from each extracted crate
  archive, preventing tests from relying on files outside the package. Preflight
  also attests the exact reviewed archives, and publication compares both new
  and resumed crates.io uploads with those archives.

### Breaking API changes

- Public security error enums are marked `#[non_exhaustive]` where downstream
  exhaustive matching would prevent compatible typed-state additions.
- Public enums across the credential, claims, status, mdoc, OAuth, SD-JWT,
  revocation, trust, X.509, and presentation crates are now non-exhaustive.
  Callers must use wildcard match arms and must not rely on implicit numeric
  discriminants, which changed where typed failure variants were added.
- Typed additions include `KeySetError` reasons,
  `OcspError::Unsupported`, `TslStructureFailure::ServiceHistoryOrder`,
  `DidValidationCode::TransitionEquivocation`, and
  `CertificateStatus::NotChecked`. The `KeySetError` protobuf mapping changes
  the stable reason transmitted to Swift, Kotlin, and TypeScript callers.
- `TrustDecision`, `VerifiedTokenStatusList`, and parsed CRL values can only be
  created by their verification or parsing pipelines. Callers use read-only
  accessors instead of constructing these security capabilities directly.
- `VerifiedSdJwt`, `VerifiedMdoc`, and `VerifiedMdocDeviceResponse` likewise
  expose authenticated state through accessors instead of public fields.
  Verified mdoc values and several presentation-domain models no longer
  implement `Clone` so sensitive authenticated projections are not duplicated
  implicitly.
- The standalone CRL core crate has been removed. The published
  `reallyme-revocation` crate accepts CRL decisions through the portable
  `StatusChecker` boundary; its OpenSSL parser and checker remain a
  source-workspace implementation and are not published in 0.3.0.
- SIOP authentication response verification takes the expected state in its
  only public protocol entry point.
- Committed-credential proof binding requires the trusted issuer public key.
  The unauthenticated `verify_merkle_only` entry point has been removed.
- QEAA validation is represented by the typed verification-provenance and
  compliance pipeline; the former `QeaaValidationPolicy`,
  `validate_qeaa_compliance`, and `validate_qeaa_compliance_with_policy` APIs
  have been removed.
- `SingleUseStore` operations require a `SingleUseNamespace`, no longer accept
  caller-supplied current time, and use the store's `SingleUseClock`. That clock
  now returns paired wall and monotonic readings through `SingleUseTime`.
  `SingleUseError::ClockRollback` is removed; rollback and forward-correction
  behavior is handled by bounded clock readings and both absolute and monotonic
  expiry deadlines instead. Constructors backed by the system clock are not
  available on `wasm32-unknown-unknown`; WebAssembly callers inject a clock.
- `DidCore` includes its signed projection commitment, and `BrotliError`
  includes distinct trailing-data and oversized-window variants. Both
  `brotli_compress` and Brotli decompression now return
  `Zeroizing<Vec<u8>>`.
- `CredentialRevocationVerificationInput` and
  `verify_credential_revocation_status` require authenticated credential
  status-list evidence in addition to certificate-revocation evidence.
- The OpenSSL OCSP parser accepts certificate DER instead of OpenSSL handles;
  nonce-aware verification is available through
  `parse_ocsp_response_der_with_nonce`, and sealed `ParsedOcspResponse`
  receipts expose the authenticated response nonce through accessors.
- `AuthorizationServerMetadata` is non-exhaustive, includes `jwks_uri`, and is
  constructed with `AuthorizationServerMetadata::new`. Attestation validation
  contexts add the expected client identity, trust-evidence construction now
  requires the authenticated compact attestation and verification time, and
  verified attestation PoP claims are exposed through accessors.
- SD-JWT verification policies add required-expiration controls, and verified
  SD-JWT payloads, disclosures, and key-binding data are exposed through
  accessors rather than public fields.
- mdoc validity carries optional `expectedUpdate`; issue configuration carries
  device-key authorizations and bounded key information; x5chain verification
  returns the authenticated signer-certificate interval. The former
  `MdocEnvelopeStatus` enum is replaced by typed envelope errors.
- Status-list verification seals `VerifiedTokenStatusList`; use its accessors
  instead of the removed `status_bit` and `token_status_value` helpers.
  Revocation composition no longer exposes mutable `statuslist` or
  `require_verified` policy fields.
- `DidApiError` carries did:web failures through the typed
  `DidWeb(DidWebErrorReason)` variant. The corresponding protobuf reasons now
  preserve individual did:web transport and document-validation failures.
- Trust evaluation reports `PurposePolicyMismatch` when a receipt purpose is
  paired with a policy that does not enforce that purpose's requirements.
- Trusted-list ingestion requires the last accepted sequence number and rejects
  authenticated rollback before returning a verified list.
- The X.509 trusted-list helper is now explicitly a policy-only projection,
  binds CA/QC service identities to a CA certificate rather than an end-entity
  leaf, and requires a concrete validation time. `TslTrustService`,
  `validate_tsl_trust_service_for_leaf`, and the `require_leaf_binding` policy
  field are replaced by CA-bound `TslCertificateBinding`,
  `evaluate_tsl_service_policy_for_ca`, and `require_ca_binding`.
  `CertificateIdentityFacts` also adds the canonical `subject_name_der` field.
- X.509 policy evaluation no longer accepts `PublicKeyProfile::Other`, including
  unclassified RSA-PSS and ML-DSA keys, under the default policy. Callers must
  select a policy with an explicitly supported public-key profile.
- The permissive disclosure-policy constructors `VpPolicy::dev_default` and
  `VpPolicy::unsafe_permissive_for_tests` have been removed; callers construct
  an explicit policy.
- VC validation exposes typed errors for required expiration, SD-JWT digest
  algorithm, presentation binding, and trusted issuer-key mismatches.

All workspace crates, including source-only internal crates, use version 0.3.0.
