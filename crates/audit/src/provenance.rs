// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic validation provenance shared by identity verification results.

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum UTF-8 length of one provenance identifier or version value.
pub const MAX_PROVENANCE_TEXT_BYTES: usize = 2_048;

/// Standards versions captured at the instant a verification decision is made.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct StandardsVersions {
    /// ReallyMe DID method profile version.
    pub did_me: String,
    /// did:web method profile version.
    pub did_web: String,
    /// EBSI DID method profile version.
    pub did_ebsi: String,
    /// W3C DID Core version.
    pub w3c_did_core: String,
    /// OpenID for Verifiable Presentations version.
    pub openid4vp: String,
    /// OpenID for Verifiable Credential Issuance version.
    pub openid4vci: String,
    /// SD-JWT VC version.
    pub sd_jwt_vc: String,
    /// ISO/IEC 18013-5 edition.
    pub iso_18013_5: String,
    /// EUDI Wallet Architecture and Reference Framework version.
    pub eudi_wallet_arf: String,
}

/// Resolver implementations whose verified outputs informed the decision.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct VerificationResolvers {
    /// DID resolver implementation or configuration identifier.
    pub did_resolver: String,
    /// Trust resolver implementation or configuration identifier.
    pub trust_resolver: String,
    /// Status resolver implementation or configuration identifier.
    pub status_resolver: String,
}

/// Complete, privacy-safe provenance for one verification decision.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct VerificationProvenance {
    /// Unix timestamp when verification completed.
    pub evaluated_at_unix: u64,
    /// Unix timestamp at which the subject material was evaluated.
    pub valid_at_unix: u64,
    /// Stable identifier of the applied policy.
    pub policy_id: String,
    /// Version of the applied policy.
    pub policy_version: String,
    /// Exact standards versions used during verification.
    pub standards_versions: StandardsVersions,
    /// Trust-state snapshot identifier.
    pub trust_snapshot_id: String,
    /// Revocation and suspension status snapshot identifier.
    pub status_snapshot_id: String,
    /// Schema snapshot identifier.
    pub schema_snapshot_id: String,
    /// Resolver implementations used to collect external evidence.
    pub resolvers: VerificationResolvers,
    /// Digest identifier binding the collected verification evidence.
    pub evidence_digest: String,
    /// Privacy-safe trace identifier for correlating the decision.
    pub trace_id: String,
}

/// Stable field identifiers for provenance validation failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VerificationProvenanceField {
    /// Completion time.
    #[error("evaluation time")]
    EvaluatedAt,
    /// Subject-material evaluation time.
    #[error("validity time")]
    ValidAt,
    /// Applied policy identifier.
    #[error("policy identifier")]
    PolicyId,
    /// Applied policy version.
    #[error("policy version")]
    PolicyVersion,
    /// ReallyMe DID method standard version.
    #[error("did:me standard version")]
    DidMeVersion,
    /// did:web method standard version.
    #[error("did:web standard version")]
    DidWebVersion,
    /// EBSI DID method standard version.
    #[error("did:ebsi standard version")]
    DidEbsiVersion,
    /// W3C DID Core standard version.
    #[error("DID Core standard version")]
    DidCoreVersion,
    /// OpenID for Verifiable Presentations standard version.
    #[error("OpenID4VP standard version")]
    OpenId4VpVersion,
    /// OpenID for Verifiable Credential Issuance standard version.
    #[error("OpenID4VCI standard version")]
    OpenId4VciVersion,
    /// SD-JWT VC standard version.
    #[error("SD-JWT VC standard version")]
    SdJwtVcVersion,
    /// ISO/IEC 18013-5 edition.
    #[error("ISO 18013-5 standard version")]
    Iso18013_5Version,
    /// EUDI Wallet ARF version.
    #[error("EUDI Wallet ARF version")]
    EudiWalletArfVersion,
    /// Trust snapshot identifier.
    #[error("trust snapshot identifier")]
    TrustSnapshotId,
    /// Status snapshot identifier.
    #[error("status snapshot identifier")]
    StatusSnapshotId,
    /// Schema snapshot identifier.
    #[error("schema snapshot identifier")]
    SchemaSnapshotId,
    /// DID resolver identifier.
    #[error("DID resolver identifier")]
    DidResolver,
    /// Trust resolver identifier.
    #[error("trust resolver identifier")]
    TrustResolver,
    /// Status resolver identifier.
    #[error("status resolver identifier")]
    StatusResolver,
    /// Evidence digest identifier.
    #[error("evidence digest")]
    EvidenceDigest,
    /// Trace identifier.
    #[error("trace identifier")]
    TraceId,
}

/// Typed, allocation-free reason for rejecting provenance at a boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VerificationProvenanceError {
    /// A required field is empty or a required timestamp is zero.
    #[error("verification provenance field is missing")]
    Missing(VerificationProvenanceField),
    /// A text field exceeds the deterministic boundary limit.
    #[error("verification provenance field exceeds its bound")]
    TooLarge(VerificationProvenanceField),
    /// The subject evaluation time is later than completion time.
    #[error("verification provenance time ordering is invalid")]
    InvalidTimeOrder,
}

impl core::fmt::Debug for StandardsVersions {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("StandardsVersions(<redacted>)")
    }
}

impl core::fmt::Debug for VerificationResolvers {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerificationResolvers(<redacted>)")
    }
}

impl core::fmt::Debug for VerificationProvenance {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerificationProvenance(<redacted>)")
    }
}

/// Validate all required provenance fields without I/O or global state.
pub fn validate_verification_provenance(
    provenance: &VerificationProvenance,
) -> Result<(), VerificationProvenanceError> {
    validate_time(
        provenance.evaluated_at_unix,
        VerificationProvenanceField::EvaluatedAt,
    )?;
    validate_time(
        provenance.valid_at_unix,
        VerificationProvenanceField::ValidAt,
    )?;
    if provenance.valid_at_unix > provenance.evaluated_at_unix {
        return Err(VerificationProvenanceError::InvalidTimeOrder);
    }
    validate_text(&provenance.policy_id, VerificationProvenanceField::PolicyId)?;
    validate_text(
        &provenance.policy_version,
        VerificationProvenanceField::PolicyVersion,
    )?;
    validate_standard_versions(&provenance.standards_versions)?;
    validate_text(
        &provenance.trust_snapshot_id,
        VerificationProvenanceField::TrustSnapshotId,
    )?;
    validate_text(
        &provenance.status_snapshot_id,
        VerificationProvenanceField::StatusSnapshotId,
    )?;
    validate_text(
        &provenance.schema_snapshot_id,
        VerificationProvenanceField::SchemaSnapshotId,
    )?;
    validate_text(
        &provenance.resolvers.did_resolver,
        VerificationProvenanceField::DidResolver,
    )?;
    validate_text(
        &provenance.resolvers.trust_resolver,
        VerificationProvenanceField::TrustResolver,
    )?;
    validate_text(
        &provenance.resolvers.status_resolver,
        VerificationProvenanceField::StatusResolver,
    )?;
    validate_text(
        &provenance.evidence_digest,
        VerificationProvenanceField::EvidenceDigest,
    )?;
    validate_text(&provenance.trace_id, VerificationProvenanceField::TraceId)
}

fn validate_standard_versions(
    versions: &StandardsVersions,
) -> Result<(), VerificationProvenanceError> {
    for (value, field) in [
        (&versions.did_me, VerificationProvenanceField::DidMeVersion),
        (
            &versions.did_web,
            VerificationProvenanceField::DidWebVersion,
        ),
        (
            &versions.did_ebsi,
            VerificationProvenanceField::DidEbsiVersion,
        ),
        (
            &versions.w3c_did_core,
            VerificationProvenanceField::DidCoreVersion,
        ),
        (
            &versions.openid4vp,
            VerificationProvenanceField::OpenId4VpVersion,
        ),
        (
            &versions.openid4vci,
            VerificationProvenanceField::OpenId4VciVersion,
        ),
        (
            &versions.sd_jwt_vc,
            VerificationProvenanceField::SdJwtVcVersion,
        ),
        (
            &versions.iso_18013_5,
            VerificationProvenanceField::Iso18013_5Version,
        ),
        (
            &versions.eudi_wallet_arf,
            VerificationProvenanceField::EudiWalletArfVersion,
        ),
    ] {
        validate_text(value, field)?;
    }
    Ok(())
}

fn validate_time(
    value: u64,
    field: VerificationProvenanceField,
) -> Result<(), VerificationProvenanceError> {
    if value == 0 {
        return Err(VerificationProvenanceError::Missing(field));
    }
    Ok(())
}

fn validate_text(
    value: &str,
    field: VerificationProvenanceField,
) -> Result<(), VerificationProvenanceError> {
    if value.trim().is_empty() {
        return Err(VerificationProvenanceError::Missing(field));
    }
    if value.len() > MAX_PROVENANCE_TEXT_BYTES {
        return Err(VerificationProvenanceError::TooLarge(field));
    }
    Ok(())
}
