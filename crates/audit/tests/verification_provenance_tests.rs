// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verification provenance boundary and memory-hygiene coverage.

#![allow(clippy::unwrap_used)]

use reallyme_credential_audit::{
    validate_verification_provenance, StandardsVersions, VerificationProvenance,
    VerificationProvenanceError, VerificationProvenanceField, VerificationResolvers,
    MAX_PROVENANCE_TEXT_BYTES,
};

fn provenance() -> VerificationProvenance {
    VerificationProvenance {
        evaluated_at_unix: 1_800_000_000,
        valid_at_unix: 1_799_999_900,
        policy_id: String::from("wallet-verification"),
        policy_version: String::from("2026-09"),
        standards_versions: StandardsVersions {
            did_me: String::from("1.0"),
            did_web: String::from("community-draft"),
            did_ebsi: String::from("v2"),
            w3c_did_core: String::from("1.0"),
            openid4vp: String::from("1.0"),
            openid4vci: String::from("1.0"),
            sd_jwt_vc: String::from("draft-22"),
            iso_18013_5: String::from("2021"),
            eudi_wallet_arf: String::from("2.3.0"),
        },
        trust_snapshot_id: String::from("trust-17"),
        status_snapshot_id: String::from("status-41"),
        schema_snapshot_id: String::from("schema-9"),
        resolvers: VerificationResolvers {
            did_resolver: String::from("did-resolver-3"),
            trust_resolver: String::from("trust-resolver-2"),
            status_resolver: String::from("status-resolver-5"),
        },
        evidence_digest: String::from("sha256:0123456789abcdef"),
        trace_id: String::from("trace-24"),
    }
}

#[test]
fn did_web_standard_version_is_required_at_the_provenance_boundary() {
    validate_verification_provenance(&provenance()).unwrap();

    let mut missing = provenance();
    missing.standards_versions.did_web.clear();
    assert_eq!(
        validate_verification_provenance(&missing),
        Err(VerificationProvenanceError::Missing(
            VerificationProvenanceField::DidWebVersion,
        ))
    );
}

#[test]
fn did_web_standard_version_rejects_oversized_untrusted_input() {
    let mut oversized = provenance();
    oversized.standards_versions.did_web = "x".repeat(MAX_PROVENANCE_TEXT_BYTES + 1);
    assert_eq!(
        validate_verification_provenance(&oversized),
        Err(VerificationProvenanceError::TooLarge(
            VerificationProvenanceField::DidWebVersion,
        ))
    );
}

#[test]
fn did_ebsi_standard_version_is_required_at_the_provenance_boundary() {
    validate_verification_provenance(&provenance()).unwrap();

    let mut missing = provenance();
    missing.standards_versions.did_ebsi.clear();
    assert_eq!(
        validate_verification_provenance(&missing),
        Err(VerificationProvenanceError::Missing(
            VerificationProvenanceField::DidEbsiVersion,
        ))
    );
}

#[test]
fn did_ebsi_standard_version_rejects_oversized_untrusted_input() {
    let mut oversized = provenance();
    oversized.standards_versions.did_ebsi = "x".repeat(MAX_PROVENANCE_TEXT_BYTES + 1);
    assert_eq!(
        validate_verification_provenance(&oversized),
        Err(VerificationProvenanceError::TooLarge(
            VerificationProvenanceField::DidEbsiVersion,
        ))
    );
}

#[test]
fn provenance_debug_output_is_redacted_and_owned_values_zeroize() {
    use zeroize::Zeroize;

    let mut value = provenance();
    assert_eq!(format!("{value:?}"), "VerificationProvenance(<redacted>)");
    value.zeroize();
    assert!(value.standards_versions.did_web.is_empty());
}
