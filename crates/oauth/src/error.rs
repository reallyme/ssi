// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed OAuth substrate errors.

use core::fmt::{Display, Formatter};

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use thiserror::Error;

/// OAuth substrate result.
pub type OauthResult<T> = Result<T, OauthError>;

/// Deterministic non-PII OAuth error reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// A required value is absent.
    MissingRequiredValue,
    /// A string contains invalid characters or is empty.
    InvalidString,
    /// A URL is malformed or violates HTTPS requirements.
    InvalidUrl,
    /// JSON parsing or serialization failed.
    InvalidJson,
    /// Form data is malformed.
    InvalidForm,
    /// RFC 7636 S256 PKCE validation failed.
    InvalidPkce,
    /// RFC 9126 PAR validation failed.
    InvalidParRequest,
    /// RFC 9449 DPoP proof validation failed.
    InvalidDpopProof,
    /// DPoP proof replay was detected.
    DpopReplay,
    /// Authorization Server metadata validation failed.
    InvalidMetadata,
    /// Authorization Server metadata did not name the issuer that was requested.
    AuthorizationServerIssuerMismatch,
    /// Attestation-based client authentication validation failed.
    InvalidClientAttestation,
    /// Request client identifier did not match the authenticated attestation subject.
    AttestationClientIdMismatch,
    /// The PoP did not verify with the Client Instance Key in the attestation.
    AttestationKeyBindingFailed,
    /// A verifier returned a malformed or mismatched attestation receipt.
    InvalidAttestationReceipt,
    /// Wallet-attestation signer trust was conclusively rejected.
    AttestationTrustRejected,
    /// Wallet-attestation signer trust could not be established.
    AttestationTrustIndeterminate,
    /// Wallet-attestation trust evidence expired before the request time.
    AttestationTrustEvidenceStale,
    /// Wallet-attestation trust evidence was evaluated after the request time.
    AttestationTrustEvidenceFutureIssued,
    /// Replay protection rejected the attestation-bound PoP event.
    AttestationReplay,
    /// Cryptographic signing failed.
    SigningFailed,
    /// Cryptographic verification failed.
    VerificationFailed,
    /// The adapter cannot satisfy the hardened metadata transport contract.
    MetadataTransportPolicyUnsupported,
    /// The reported metadata connection did not match the validated authority.
    MetadataConnectionBindingFailed,
    /// Metadata retrieval encountered a TLS certificate or hostname failure.
    MetadataTlsFailure,
    /// A metadata redirect or changed effective URL was observed.
    MetadataRedirectRejected,
    /// The metadata endpoint returned a non-success HTTP status.
    MetadataHttpStatusRejected,
    /// The metadata response did not use the required JSON media type.
    MetadataMediaTypeRejected,
    /// The metadata response exceeded its byte bound or declared a bad length.
    MetadataResponseTooLarge,
}

impl Display for Reason {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::MissingRequiredValue => "missing_required_value",
            Self::InvalidString => "invalid_string",
            Self::InvalidUrl => "invalid_url",
            Self::InvalidJson => "invalid_json",
            Self::InvalidForm => "invalid_form",
            Self::InvalidPkce => "invalid_pkce",
            Self::InvalidParRequest => "invalid_par_request",
            Self::InvalidDpopProof => "invalid_dpop_proof",
            Self::DpopReplay => "dpop_replay",
            Self::InvalidMetadata => "invalid_metadata",
            Self::AuthorizationServerIssuerMismatch => "authorization_server_issuer_mismatch",
            Self::MetadataTransportPolicyUnsupported => "metadata_transport_policy_unsupported",
            Self::MetadataConnectionBindingFailed => "metadata_connection_binding_failed",
            Self::MetadataTlsFailure => "metadata_tls_failure",
            Self::MetadataRedirectRejected => "metadata_redirect_rejected",
            Self::MetadataHttpStatusRejected => "metadata_http_status_rejected",
            Self::MetadataMediaTypeRejected => "metadata_media_type_rejected",
            Self::MetadataResponseTooLarge => "metadata_response_too_large",
            Self::InvalidClientAttestation => "invalid_client_attestation",
            Self::AttestationClientIdMismatch => "attestation_client_id_mismatch",
            Self::AttestationKeyBindingFailed => "attestation_key_binding_failed",
            Self::InvalidAttestationReceipt => "invalid_attestation_receipt",
            Self::AttestationTrustRejected => "attestation_trust_rejected",
            Self::AttestationTrustIndeterminate => "attestation_trust_indeterminate",
            Self::AttestationTrustEvidenceStale => "attestation_trust_evidence_stale",
            Self::AttestationTrustEvidenceFutureIssued => {
                "attestation_trust_evidence_future_issued"
            }
            Self::AttestationReplay => "attestation_replay",
            Self::SigningFailed => "signing_failed",
            Self::VerificationFailed => "verification_failed",
        })
    }
}

/// OAuth substrate error value.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("{reason}")]
#[non_exhaustive]
pub struct OauthError {
    reason: Reason,
}

impl OauthError {
    /// Creates an error from a typed reason.
    #[must_use]
    pub const fn new(reason: Reason) -> Self {
        Self { reason }
    }

    /// Returns the deterministic reason.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }
}

impl From<Reason> for IdentityCoreErrorReason {
    fn from(reason: Reason) -> Self {
        match reason {
            Reason::SigningFailed | Reason::VerificationFailed => {
                Self::IDENTITY_CORE_ERROR_REASON_INVALID_SIGNATURE
            }
            Reason::InvalidJson | Reason::InvalidForm => {
                Self::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING
            }
            Reason::InvalidAttestationReceipt => {
                Self::IDENTITY_CORE_ERROR_REASON_OAUTH_INVALID_ATTESTATION_RECEIPT
            }
            Reason::AttestationTrustRejected => {
                Self::IDENTITY_CORE_ERROR_REASON_OAUTH_ATTESTATION_TRUST_REJECTED
            }
            Reason::AttestationTrustIndeterminate => {
                Self::IDENTITY_CORE_ERROR_REASON_OAUTH_ATTESTATION_TRUST_INDETERMINATE
            }
            Reason::AttestationTrustEvidenceStale => {
                Self::IDENTITY_CORE_ERROR_REASON_OAUTH_ATTESTATION_TRUST_EVIDENCE_STALE
            }
            Reason::AttestationTrustEvidenceFutureIssued => {
                Self::IDENTITY_CORE_ERROR_REASON_OAUTH_ATTESTATION_TRUST_EVIDENCE_FUTURE_ISSUED
            }
            Reason::AttestationKeyBindingFailed => {
                Self::IDENTITY_CORE_ERROR_REASON_OAUTH_ATTESTATION_KEY_BINDING_FAILED
            }
            Reason::AttestationReplay => Self::IDENTITY_CORE_ERROR_REASON_OAUTH_ATTESTATION_REPLAY,
            Reason::AuthorizationServerIssuerMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_OAUTH_AUTHORIZATION_SERVER_ISSUER_MISMATCH
            }
            _ => Self::IDENTITY_CORE_ERROR_REASON_OAUTH_INVALID_SUBSTRATE,
        }
    }
}

impl From<OauthError> for IdentityCoreErrorReason {
    fn from(error: OauthError) -> Self {
        error.reason.into()
    }
}
