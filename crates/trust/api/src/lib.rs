// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! High-level Trust API (credential layer).
//!
//! Overview: typed orchestration over:
//! - trust path evaluation
//! - revocation decisions
//! - TSL-based authorization
//!
//! Non-goals:
//! - DER parsing.
//! - Fetching TSL/OCSP/CRLs.
//! - Cryptographic verification.
//!
//! Intended consumers:
//! - credential adapters
//! - identity

/// TSL-based issuer authorization.
pub mod authorize;
pub mod backend;
/// Typed DER trust-chain validation helpers.
pub mod chain;
/// Trust API domain and generated-contract conversion types.
pub mod dto;
/// Typed trust API errors.
pub mod error;
/// Trust evaluation entry points.
pub mod evaluate;
/// Trust policy mapping helpers.
pub mod policy;
/// TS 119 612 qualification evaluation.
pub mod qualification;
/// Trusted List ingestion and verification helpers.
pub mod tsl;
/// X.509 parsing and metadata helpers.
pub mod x509;

mod exports;

pub use exports::{
    authorize_issuer, default_signature_verifier, evaluate_trust_api,
    evaluate_trust_configured_api, extract_certificate_metadata, extract_certificate_metadata_der,
    map_trust_policy_to_profile, matching_service_qualifiers, parse_trust_list_xml,
    parse_x509_chain_der, qualification_criteria_matches, validate_certificate_chain_der,
    validate_trust_anchor_der, verify_credential_trust_api, AuthenticatedTrustedList,
    AuthorizationPurpose, CertificateMetadata, CertificatePosition, CertificateStatus,
    CertificateStatusEvidence, KeyUsageMetadata, TrustAnchorEvidence, TrustAnchorKind,
    TrustAnchorsDer, TrustApiError, TrustApiResourceLimitReason, TrustApiResult, TrustDecision,
    TrustDecisionEvidence, TrustDecisionFailure, TrustDecisionOutcome, TrustPolicyErrorReason,
    TrustPolicyId, TrustPolicyRequirements, TrustProtoError, TrustPurpose, TrustSourceEvidence,
    TrustedListPolicyErrorReason, TrustedListSignatureProfileErrorReason, X509CertificateDer,
    X509ChainDer,
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
pub use exports::{
    ingest_eu_trusted_list, ingest_trusted_list_xml, verify_trust_list_xml_native,
    verify_trust_list_xml_native_with_external_signer, OpenSslSignatureVerifier,
    TrustedListAnchors, VerifiedTrustedList,
};

#[cfg(feature = "wasm")]
pub use exports::WasmSignatureVerifier;
