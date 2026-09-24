# reallyme-credential

`reallyme-credential` is the authoritative protocol-neutral credential crate
owned by `reallyme/ssi`.

It defines the semantic shape that issuance, wallet, presentation, and SDK
layers build on: credential kind, profile identity, assurance level, issuer
identity, validity window, status pointer, subject key binding, claim
commitment, optional QEAA compliance evidence, and issuer signature. It is not
an OpenID4VCI issuer, an OpenID4VP response assembler, a wallet inventory, or an
envelope parser.

The `committed` module owns canonical credential issuance and verification. It
binds the public credential envelope to holder-private claims, proof-binding
metadata, issuer signatures, and signed-envelope transport without taking a
dependency on OpenID protocol flows or wallet state.

## Model

The public credential envelope is `CredentialEnvelope`.

It contains:

- `CredentialKind` for PID, EAA, and QEAA credentials.
- `profile_id` for the canonical profile or claimset identifier.
- `AssuranceLevel` for substantial or high assurance.
- issuer identity and issuer country.
- validity timestamps.
- `CredentialStatus` for StatusList-based revocation or suspension checks.
- `CredentialSubject` for pairwise subject identity and subject public key.
- `ClaimsCommitment` for the normalized claim set.
- optional `QeaaCompliance` evidence for QEAA credentials.
- issuer `Signature` over the canonical public envelope.

Holder-private claim values remain outside the public envelope in
`SubjectPrivateBundle`. Validation binds the private bundle back to the public
credential through the envelope hash, holder key, issuer signature, and
commitment opening verification.

The public `profile_id` must match the `ClaimsCommitment.claimset_id`. This
keeps a credential from presenting one profile identity while committing to a
different claims registry; any aliasing, such as eIDAS VID or EU passport
selection, must be resolved before constructing the credential envelope.

## Boundaries

This crate owns shared credential semantics:

- canonical credential signing payloads and credential envelope hashes;
- injected issuer signing and verification traits;
- local status-list verification;
- composition with already-resolved revocation evidence;
- credential protobuf/Buffa mapping when the `proto` feature is enabled.

This crate deliberately does not own:

- OpenID4VCI offers, token exchange, deferred issuance, notifications, or HTTP;
- OpenID4VP request/response assembly, DCQL, handover, or session binding;
- wallet storage, inventory, consent UX, or provider selection;
- network fetching for status lists, OCSP, CRLs, trusted lists, or metadata;
- envelope-specific parsing for SD-JWT, mdoc, JWT-VC, or W3C VC.

Those behaviors belong in protocol, wallet, or SDK layers. Envelope crates map
their format-specific bytes into this credential model when a credential needs
to be signed, committed, checked, or transported.

## Conformance

Credential conformance records live in
`conformance/requirements/credential.json`.

Portable credential vectors live in
`vectors/credential/canonical.json` and cover canonical payload
bytes, envelope hash, vector signature, and status-list verification behavior.
