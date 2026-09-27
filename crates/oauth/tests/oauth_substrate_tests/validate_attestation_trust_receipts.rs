// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[allow(clippy::unwrap_used)]
fn attestation_trust_decision_with_duplicate_path_der(
    evaluated_at: time::OffsetDateTime,
) -> TrustDecision {
    let mut leaf = attestation_signer(evaluated_at + time::Duration::days(365));
    let mut root = attestation_signer(evaluated_at + time::Duration::days(365));
    root.spki_der = vec![5, 6, 7, 8];
    root.subject = "CN=Wallet Attestation Root".to_owned();
    root.issuer = root.subject.clone();
    root.subject_der = b"CN=Wallet Attestation Root".to_vec();
    root.issuer_der = root.subject_der.clone();
    if let Some(constraints) = root.basic_constraints.as_mut() {
        constraints.ca = true;
    }
    leaf.issuer = root.subject.clone();
    leaf.issuer_der = root.subject_der.clone();
    root.der = leaf.der.clone();

    let source = TrustSourceEvidence {
        source_id: [7; 32],
        snapshot_id: [8; 32],
    };
    let config = TrustConfig {
        trust_roots: vec![root.clone()],
        now: evaluated_at,
        policy: wallet_attestation_x509_policy(),
        link_policy: ChainLinkPolicy {
            require_dn_continuity: true,
            require_aki_ski_when_present: false,
        },
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            source: Some(source),
            status_policy: CertificateStatusPolicy {
                leaf: StatusRequirement::Required,
                intermediates: StatusRequirement::Required,
                trust_anchor: StatusRequirement::Exempt,
            },
        },
        direct_trust: Vec::new(),
    };
    evaluate_trust_decision(
        &[leaf, root],
        &config,
        &UnusedSignatureVerifier,
        Some(&AttestationStatusChecker(TrustOutcome::Trusted)),
    )
    .unwrap()
}

#[test]
fn attestation_receipt_rejects_a_signing_key_outside_the_selected_path() -> Result<(), OauthError> {
    let decision = attestation_trust_decision(TrustOutcome::Trusted);
    let attestation = client_attestation(test_client_instance_jwk(TestP256Key::Primary))?;
    let error = WalletAttestationTrustEvidence::from_trust_decision(
        &decision,
        &attestation,
        &[9, 9, 9, 9],
    )
    .err()
    .map(|value| value.reason());

    assert_eq!(error, Some(Reason::InvalidAttestationReceipt));
    Ok(())
}

#[test]
fn attestation_receipt_rejects_wrong_purpose_and_policy_evidence() -> Result<(), OauthError> {
    let evaluated_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_700_000_000);
    let decision = attestation_trust_decision_for_scope(
        TrustOutcome::Trusted,
        evaluated_at,
        evaluated_at + time::Duration::days(365),
        TrustPurpose::Generic,
        TrustPolicyId::GenericX509V1,
    );
    let attestation = client_attestation(test_client_instance_jwk(TestP256Key::Primary))?;

    assert_eq!(
        WalletAttestationTrustEvidence::from_trust_decision(
            &decision,
            &attestation,
            ATTESTATION_SIGNER_SPKI_DER,
        )
        .err()
        .map(|error| error.reason()),
        Some(Reason::InvalidAttestationReceipt)
    );
    Ok(())
}

#[test]
fn attestation_receipt_rejects_duplicate_selected_path_evidence() -> Result<(), OauthError> {
    let evaluated_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_700_000_000);
    let decision = attestation_trust_decision_with_duplicate_path_der(evaluated_at);
    let attestation = client_attestation(test_client_instance_jwk(TestP256Key::Primary))?;

    assert_eq!(
        WalletAttestationTrustEvidence::from_trust_decision(
            &decision,
            &attestation,
            ATTESTATION_SIGNER_SPKI_DER,
        )
        .err()
        .map(|error| error.reason()),
        Some(Reason::InvalidAttestationReceipt)
    );
    Ok(())
}
