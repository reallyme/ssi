// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol-neutral credential model, committed issuance, and validation.
//!
//! This crate owns the shared shape and cryptographic credential boundary for a
//! ReallyMe credential. Signing and verification operate through injected
//! interfaces. OpenID flows, VP response assembly, network fetching, wallet
//! state, and application orchestration remain outside this crate.
//!
//! `committed` preserves the established credential-envelope Merkle
//! construction for existing issued credentials. Its roots and openings are
//! not interchangeable with `reallyme-credential-claims` commitments. A
//! verifier must select the construction from authenticated profile/version
//! metadata and must never retry an opening under the other construction.

mod canonical;
mod commands;
/// Committed-claim issuance, proof binding, and cryptographic verification.
pub mod committed;
mod error;
mod issue_provider;
mod model;
#[cfg(feature = "proto")]
mod proto;
mod signature;
mod validate;
mod verify;

pub use canonical::{credential_envelope_hash, credential_signing_payload};
pub use commands::{
    check_credential_envelope_status_command, check_credential_status_command,
    validate_credential_command, validate_credential_envelope_command,
    validate_credential_with_evidence, CredentialCheckCode, CredentialCheckName,
    CredentialCheckOutcome, CredentialCheckResult, CredentialCheckSeverity,
    CredentialCheckStatusRequest, CredentialDecision, CredentialEvidenceValidationInput,
    CredentialStatusResult, CredentialStatusValue, CredentialValidateRequest,
    CredentialValidationPolicy, CredentialValidationResult, CredentialVerificationContext,
};
pub use error::{
    CredentialCanonicalReason, CredentialError, CredentialInvalidReason, CredentialProtoField,
    CredentialProtoReason, CredentialSignatureReason, CredentialStatusReason,
    CredentialValidityReason,
};
pub use issue_provider::{
    CredentialIssueProvider, CredentialIssueProviderError, CredentialLifecycleAction,
    CredentialLifecycleChange, CredentialLifecycleReason, CredentialLifecycleReceipt,
    CredentialLifecycleStatus,
};
pub use model::{
    AssuranceLevel, CredentialEnvelope, CredentialKind, CredentialStatus, CredentialSubject,
    HolderBinding, PartyReference, PublicKeyIdentity, UnixSeconds, X509SubjectReference,
    MAX_CREDENTIAL_COUNTRY_BYTES, MAX_CREDENTIAL_TEXT_BYTES, MAX_PUBLIC_KEY_BYTES,
    MAX_STATUS_LIST_URL_BYTES,
};
#[cfg(feature = "proto")]
pub use proto::{
    credential_envelope_from_proto, credential_envelope_to_proto, credential_status_from_proto,
    credential_status_to_proto, holder_binding_from_proto, holder_binding_to_proto,
    party_reference_from_proto, party_reference_to_proto, qeaa_compliance_from_proto,
};
pub use signature::{
    sign_credential_envelope, verify_credential_issuer_signature, CredentialIssuerSigner,
    CredentialIssuerVerifier, DispatchCredentialIssuerSigner, DispatchCredentialIssuerVerifier,
};
pub use validate::{
    validate_credential_envelope, validate_credential_unsigned_envelope,
    validate_credential_with_bundle,
};
pub use verify::{
    verify_credential, verify_credential_revocation_status, verify_credential_status,
    verify_credential_status_with_policy, verify_credential_with_revocation,
    verify_credential_with_statuslist_policy, CredentialRevocationVerificationInput,
    CredentialStatusListPolicyInput, CredentialStatusListPolicyStatusInput,
    CredentialVerificationInput,
};
