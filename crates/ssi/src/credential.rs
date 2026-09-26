// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// High-level credential issuance and public encoding API.
pub use identity_credential_vc_api as api;

/// Protocol-neutral credential envelope model and validation crate.
pub use reallyme_credential as core;

/// VC issuance model primitives used by the high-level credential API.
pub use reallyme_credential::committed;

pub use reallyme_credential::{
    credential_envelope_hash, credential_signing_payload, sign_credential_envelope,
    validate_credential_envelope, validate_credential_unsigned_envelope,
    validate_credential_with_bundle, verify_credential, verify_credential_issuer_signature,
    verify_credential_revocation_status, verify_credential_status,
    verify_credential_status_with_policy, verify_credential_with_revocation,
    verify_credential_with_statuslist_policy, AssuranceLevel, CredentialCanonicalReason,
    CredentialEnvelope, CredentialError, CredentialInvalidReason, CredentialIssuerSigner,
    CredentialIssuerVerifier, CredentialKind, CredentialProtoField, CredentialProtoReason,
    CredentialRevocationVerificationInput, CredentialSignatureReason, CredentialStatus,
    CredentialStatusListPolicyInput, CredentialStatusListPolicyStatusInput, CredentialStatusReason,
    CredentialSubject, CredentialValidityReason, CredentialVerificationInput,
    DispatchCredentialIssuerSigner, DispatchCredentialIssuerVerifier, UnixSeconds,
    MAX_CREDENTIAL_COUNTRY_BYTES, MAX_CREDENTIAL_TEXT_BYTES, MAX_PUBLIC_KEY_BYTES,
    MAX_STATUS_LIST_URL_BYTES,
};

#[cfg(feature = "credential-proto")]
pub use reallyme_credential::{credential_envelope_from_proto, credential_envelope_to_proto};
