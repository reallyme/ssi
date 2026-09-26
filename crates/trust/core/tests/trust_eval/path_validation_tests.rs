// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{config, mock_cert, AllowAllSignatures};
use envelopes_x509::{
    CertificateExtension, CertificateExtensionKind, ObjectIdentifier, X509Certificate,
};
use reallyme_trust_core::{evaluate_trust_decision, TrustConfig, TrustFailureReason, TrustOutcome};
use time::OffsetDateTime;

fn assert_policy_rejection(presented: &[X509Certificate], cfg: &TrustConfig) {
    let decision = evaluate_trust_decision(presented, cfg, &AllowAllSignatures, None)
        .expect("policy rejection remains a typed trust decision");
    assert_eq!(decision.outcome, TrustOutcome::Rejected);
    assert!(decision.failures.contains(&TrustFailureReason::Policy));
    assert!(decision.chain.is_none());
    assert!(decision.evidence.trust_anchor.is_none());
}

#[test]
fn rejects_non_ca_intermediate() {
    let root_ski = vec![0xA0];
    let intermediate_ski = vec![0xA1];
    let leaf = mock_cert(
        "CN=Leaf",
        "CN=Intermediate",
        false,
        None,
        Some(intermediate_ski.clone()),
    );
    let intermediate = mock_cert(
        "CN=Intermediate",
        "CN=Root",
        false,
        Some(intermediate_ski),
        Some(root_ski.clone()),
    );
    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);

    assert_policy_rejection(&[leaf, intermediate], &config(root));
}

#[test]
fn rejects_intermediate_without_key_cert_sign() {
    let root_ski = vec![0xA0];
    let intermediate_ski = vec![0xA1];
    let leaf = mock_cert(
        "CN=Leaf",
        "CN=Intermediate",
        false,
        None,
        Some(intermediate_ski.clone()),
    );
    let mut intermediate = mock_cert(
        "CN=Intermediate",
        "CN=Root",
        true,
        Some(intermediate_ski),
        Some(root_ski.clone()),
    );
    intermediate.key_usage.as_mut().unwrap().key_cert_sign = false;
    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);

    assert_policy_rejection(&[leaf, intermediate], &config(root));
}

#[test]
fn rejects_path_length_constraint_violation() {
    let root_ski = vec![0xA0];
    let intermediate_ski = vec![0xA1];
    let leaf = mock_cert(
        "CN=Leaf",
        "CN=Intermediate",
        false,
        None,
        Some(intermediate_ski.clone()),
    );
    let intermediate = mock_cert(
        "CN=Intermediate",
        "CN=Root",
        true,
        Some(intermediate_ski),
        Some(root_ski.clone()),
    );
    let mut root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);
    root.basic_constraints.as_mut().unwrap().path_len_constraint = Some(0);

    assert_policy_rejection(&[leaf, intermediate], &config(root));
}

#[test]
fn rejects_unknown_critical_extension() {
    let root_ski = vec![0xA0];
    let mut leaf = mock_cert("CN=Leaf", "CN=Root", false, None, Some(root_ski.clone()));
    leaf.profile.extensions.push(CertificateExtension {
        kind: CertificateExtensionKind::Other(
            ObjectIdentifier::parse("1.3.6.1.4.1.55555.404")
                .expect("test OID is valid and bounded"),
        ),
        critical: true,
    });
    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);

    assert_policy_rejection(&[leaf], &config(root));
}

#[test]
fn rejects_certificates_outside_the_evaluation_time() {
    let root_ski = vec![0xA0];
    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski.clone()), None);
    let mut expired = mock_cert("CN=Expired", "CN=Root", false, None, Some(root_ski.clone()));
    expired.not_before = OffsetDateTime::UNIX_EPOCH - time::Duration::days(2);
    expired.not_after = OffsetDateTime::UNIX_EPOCH - time::Duration::days(1);
    assert_policy_rejection(&[expired], &config(root.clone()));

    let mut not_yet_valid = mock_cert("CN=Future", "CN=Root", false, None, Some(root_ski));
    not_yet_valid.not_before = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1);
    not_yet_valid.not_after = OffsetDateTime::UNIX_EPOCH + time::Duration::days(1);
    assert_policy_rejection(&[not_yet_valid], &config(root));
}

#[test]
fn rejects_non_ca_and_non_signing_configured_anchors() {
    let root_ski = vec![0xA0];
    let leaf = mock_cert("CN=Leaf", "CN=Root", false, None, Some(root_ski.clone()));
    let non_ca_root = mock_cert("CN=Root", "CN=Root", false, Some(root_ski.clone()), None);
    assert_policy_rejection(std::slice::from_ref(&leaf), &config(non_ca_root));

    let mut non_signing_root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);
    non_signing_root.key_usage.as_mut().unwrap().key_cert_sign = false;
    assert_policy_rejection(&[leaf], &config(non_signing_root));
}

#[test]
fn rejects_wrong_anchor_and_issuer_mismatch() {
    let leaf = mock_cert("CN=Leaf", "CN=Expected Root", false, None, None);
    let wrong_root = mock_cert("CN=Wrong Root", "CN=Wrong Root", true, None, None);
    let decision = evaluate_trust_decision(
        std::slice::from_ref(&leaf),
        &config(wrong_root),
        &AllowAllSignatures,
        None,
    )
    .expect("wrong anchor produces a typed rejection");
    assert_eq!(decision.outcome, TrustOutcome::Rejected);
    assert!(decision.failures.contains(&TrustFailureReason::NoValidPath));

    let expected_root = mock_cert("CN=Expected Root", "CN=Expected Root", true, None, None);
    let mut mismatched_leaf = leaf;
    mismatched_leaf.issuer = "CN=Different Issuer".to_owned();
    mismatched_leaf.issuer_der = b"CN=Different Issuer".to_vec();
    let decision = evaluate_trust_decision(
        &[mismatched_leaf],
        &config(expected_root),
        &AllowAllSignatures,
        None,
    )
    .expect("issuer mismatch produces a typed rejection");
    assert_eq!(decision.outcome, TrustOutcome::Rejected);
    assert!(decision.failures.contains(&TrustFailureReason::NoValidPath));
}

#[test]
fn enforces_leaf_digital_signature_when_policy_requires_it() {
    let root_ski = vec![0xA0];
    let mut leaf = mock_cert("CN=Leaf", "CN=Root", false, None, Some(root_ski.clone()));
    leaf.key_usage.as_mut().unwrap().digital_signature = false;
    let root = mock_cert("CN=Root", "CN=Root", true, Some(root_ski), None);
    let mut cfg = config(root);
    cfg.policy.require_leaf_digital_signature = true;

    assert_policy_rejection(&[leaf], &cfg);
}
