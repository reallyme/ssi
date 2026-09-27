// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
//! Test coverage for this crate.

use reallyme_trust_x509::{
    presets::{eu_policy, EuPreset},
    CertificatePolicyId, QcStatementId, QcType, TrustAnchorRequirement,
};

#[test]
fn qwac_preset_contains_expected_oids() {
    let p = eu_policy(EuPreset::Qwac);

    assert!(p
        .required_policy_any_of
        .contains(&CertificatePolicyId::QevcpWeb));
    assert!(p
        .required_policy_any_of
        .contains(&CertificatePolicyId::QncpWeb));

    assert!(p
        .required_qc_statement_ids
        .contains(&QcStatementId::Compliance));
    assert!(p.required_qc_statement_ids.contains(&QcStatementId::Type));
    assert!(p
        .required_qc_type_any_of
        .contains(&QcType::WebAuthentication));
    assert_eq!(
        p.trust_anchor_requirement,
        TrustAnchorRequirement::Rfc5280Ca
    );
}

#[test]
fn qsealc_preset_contains_expected_oids() {
    let p = eu_policy(EuPreset::Qsealc);

    assert!(p
        .required_policy_any_of
        .contains(&CertificatePolicyId::QcpLegalPerson));
    assert!(p.required_qc_type_any_of.contains(&QcType::ElectronicSeal));
    assert_eq!(
        p.trust_anchor_requirement,
        TrustAnchorRequirement::Rfc5280Ca
    );
}

#[test]
fn qsigc_preset_contains_expected_oids() {
    let p = eu_policy(EuPreset::Qsigc);

    assert!(p
        .required_policy_any_of
        .contains(&CertificatePolicyId::QcpNaturalPerson));
    assert!(p
        .required_qc_type_any_of
        .contains(&QcType::ElectronicSignature));
}
