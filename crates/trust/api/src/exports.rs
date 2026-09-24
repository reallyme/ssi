// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// -----------------------------------------------------------------------------
// Public error + result
// -----------------------------------------------------------------------------

pub use crate::error::{
    TrustApiError, TrustApiResourceLimitReason, TrustPolicyErrorReason,
    TrustedListPolicyErrorReason, TrustedListSignatureProfileErrorReason,
};

/// Standard API result alias
pub type TrustApiResult<T> = Result<T, TrustApiError>;

// -----------------------------------------------------------------------------
// Public domain and boundary-owner types
// -----------------------------------------------------------------------------

pub use crate::dto::{
    AuthorizationPurpose, CertificatePosition, CertificateStatus, CertificateStatusEvidence,
    TrustAnchorEvidence, TrustAnchorKind, TrustAnchorsDer, TrustDecision, TrustDecisionEvidence,
    TrustDecisionFailure, TrustDecisionOutcome, TrustPolicyId, TrustProtoError, TrustPurpose,
    TrustSourceEvidence, X509CertificateDer, X509ChainDer,
};

// -----------------------------------------------------------------------------
// Public API functions (typed, deterministic)
// -----------------------------------------------------------------------------

/// Evaluate trust (X.509 path + policy + optional revocation).
///
/// Does NOT perform issuer authorization.
pub use crate::evaluate::evaluate_trust_api;
pub use crate::evaluate::evaluate_trust_configured_api;

pub use crate::chain::{validate_certificate_chain_der, validate_trust_anchor_der};

/// Evaluate trust and optionally authorize issuer against a Trusted List (TSL).
///
/// This is the **primary entrypoint** adapters should use.
pub use crate::evaluate::verify_credential_trust_api;

// -----------------------------------------------------------------------------
// Advanced / manual flows
// -----------------------------------------------------------------------------

/// Explicit issuer authorization against a Trusted List (TSL).
///
/// Exposed for advanced workflows and testing.
pub use crate::authorize::authorize_issuer;
pub use crate::qualification::{matching_service_qualifiers, qualification_criteria_matches};

// -----------------------------------------------------------------------------
// Backends (feature-gated)
// -----------------------------------------------------------------------------

pub use crate::backend::default_signature_verifier;

#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
pub use crate::backend::OpenSslSignatureVerifier;

#[cfg(feature = "wasm")]
pub use crate::backend::WasmSignatureVerifier;

// -----------------------------------------------------------------------------
// Trust List
// -----------------------------------------------------------------------------
pub use crate::tsl::parse_trust_list_xml;

#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
pub use crate::tsl::{
    ingest_eu_trusted_list, ingest_trusted_list_xml,
    verify_trust_list_xml_native_with_external_signer, TrustedListAnchors, VerifiedTrustedList,
};

#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
pub use crate::tsl::verify_trust_list_xml_native;

// -----------------------------------------------------------------------------
// x509
// -----------------------------------------------------------------------------
pub use crate::x509::{
    extract_certificate_metadata, extract_certificate_metadata_der, parse_x509_chain_der,
    CertificateMetadata, KeyUsageMetadata,
};

// -----------------------------------------------------------------------------
// Policy mapping
// -----------------------------------------------------------------------------
pub use crate::policy::{map_trust_policy_to_profile, TrustPolicyRequirements};
