// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conformance vectors for the purpose-scoped national TS5 registrar signer identity.

#![allow(clippy::expect_used)]

use envelopes_x509::{
    model::{BasicConstraints, KeyUsage, X509Certificate, X509Chain},
    policy::X509Policy,
};
use reallyme_trust_core::{
    evaluate_trust_decision, DirectTrustEntry, SignatureVerifier, SignatureVerifyError,
    TrustAnchorKind, TrustConfig, TrustError, TrustEvaluationContext, TrustOutcome, TrustPolicyId,
    TrustPurpose, TrustSourceEvidence,
};
use time::OffsetDateTime;

fn mock_cert(
    subject: &str,
    issuer: &str,
    is_ca: bool,
    ski: Option<Vec<u8>>,
    aki: Option<Vec<u8>>,
) -> X509Certificate {
    X509Certificate {
        der: subject.as_bytes().to_vec(),
        subject: subject.to_owned(),
        issuer: issuer.to_owned(),
        subject_der: subject.as_bytes().to_vec(),
        issuer_der: issuer.as_bytes().to_vec(),
        serial: vec![1, 2, 3],
        not_before: OffsetDateTime::UNIX_EPOCH,
        not_after: OffsetDateTime::UNIX_EPOCH + time::Duration::days(365),
        spki_der: Vec::new(),
        signature_algorithm_oid: "1.2.3.4".to_owned(),
        basic_constraints: Some(BasicConstraints {
            ca: is_ca,
            path_len_constraint: None,
        }),
        key_usage: Some(KeyUsage {
            digital_signature: true,
            content_commitment: false,
            key_encipherment: false,
            data_encipherment: false,
            key_cert_sign: is_ca,
            crl_sign: is_ca,
            key_agreement: false,
            encipher_only: false,
            decipher_only: false,
        }),
        extended_key_usage: None,
        subject_key_identifier: ski,
        authority_key_identifier: aki,
        san_dns: Vec::new(),
        san_ip: Vec::new(),
        certificate_policies: Vec::new(),
        qc_statements: Default::default(),
        profile: Default::default(),
    }
}

struct AllowAllSignatures;

impl SignatureVerifier for AllowAllSignatures {
    fn verify_chain(
        &self,
        _chain: &X509Chain,
        _now: OffsetDateTime,
    ) -> Result<(), SignatureVerifyError> {
        Ok(())
    }
}

struct RejectAllSignatures;

impl SignatureVerifier for RejectAllSignatures {
    fn verify_chain(
        &self,
        _chain: &X509Chain,
        _now: OffsetDateTime,
    ) -> Result<(), SignatureVerifyError> {
        Err(SignatureVerifyError::InvalidSignature)
    }
}

#[test]
fn ts5_registry_signing_direct_trust_vector_is_purpose_scoped() {
    let leaf = mock_cert(
        "CN=National TS5 Registrar",
        "CN=National TS5 Registrar",
        false,
        None,
        None,
    );
    let source = TrustSourceEvidence {
        source_id: [0x51; 32],
        snapshot_id: [0x52; 32],
    };
    let direct_entry = DirectTrustEntry {
        certificate: leaf.clone(),
        purpose: TrustPurpose::WalletRelyingPartyRegistrySigning,
        policy_id: TrustPolicyId::EudiTs5RegistryResponseSigningV1,
        source,
    };
    let mut config = TrustConfig {
        trust_roots: Vec::new(),
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::WalletRelyingPartyRegistrySigning,
            policy_id: TrustPolicyId::EudiTs5RegistryResponseSigningV1,
            source: Some(source),
            ..Default::default()
        },
        direct_trust: vec![direct_entry],
    };

    let decision = evaluate_trust_decision(
        std::slice::from_ref(&leaf),
        &config,
        &RejectAllSignatures,
        None,
    )
    .expect("the exact purpose-scoped direct entry should be evaluated");
    assert_eq!(decision.outcome, TrustOutcome::Trusted);
    assert_eq!(
        decision.evidence.purpose,
        TrustPurpose::WalletRelyingPartyRegistrySigning
    );
    assert_eq!(
        decision.evidence.policy_id,
        TrustPolicyId::EudiTs5RegistryResponseSigningV1
    );
    assert_eq!(
        decision.evidence.trust_anchor.map(|anchor| anchor.kind),
        Some(TrustAnchorKind::DirectEndEntity)
    );

    let unrelated_identities = [
        (TrustPurpose::Generic, TrustPolicyId::GenericX509V1),
        (
            TrustPurpose::JadesSigner,
            TrustPolicyId::EtsiJadesBaselineBV1,
        ),
        (
            TrustPurpose::WalletRelyingPartyRegistrationCertificate,
            TrustPolicyId::EtsiTs119475WrprcV1,
        ),
    ];
    for (purpose, policy_id) in unrelated_identities {
        config.evaluation.purpose = purpose;
        config.evaluation.policy_id = policy_id;
        let decision = evaluate_trust_decision(
            std::slice::from_ref(&leaf),
            &config,
            &AllowAllSignatures,
            None,
        )
        .expect("each unrelated identity is internally consistent");
        assert_eq!(decision.outcome, TrustOutcome::Rejected);
        assert!(decision.evidence.trust_anchor.is_none());
    }
}

#[test]
fn ts5_registry_signing_pkix_vector_retains_exact_identity() {
    let root_ski = vec![0x61];
    let leaf = mock_cert(
        "CN=National TS5 Registrar",
        "CN=Registrar Root",
        false,
        None,
        Some(root_ski.clone()),
    );
    let root = mock_cert(
        "CN=Registrar Root",
        "CN=Registrar Root",
        true,
        Some(root_ski),
        None,
    );
    let config = TrustConfig {
        trust_roots: vec![root],
        now: OffsetDateTime::UNIX_EPOCH,
        policy: X509Policy::default(),
        link_policy: Default::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::WalletRelyingPartyRegistrySigning,
            policy_id: TrustPolicyId::EudiTs5RegistryResponseSigningV1,
            ..Default::default()
        },
        direct_trust: Vec::new(),
    };

    let decision = evaluate_trust_decision(&[leaf], &config, &AllowAllSignatures, None)
        .expect("the registrar chain should produce a typed decision");

    assert_eq!(decision.outcome, TrustOutcome::Trusted);
    assert_eq!(
        decision.evidence.purpose,
        TrustPurpose::WalletRelyingPartyRegistrySigning
    );
    assert_eq!(
        decision.evidence.policy_id,
        TrustPolicyId::EudiTs5RegistryResponseSigningV1
    );
    assert_eq!(
        decision.evidence.trust_anchor.map(|anchor| anchor.kind),
        Some(TrustAnchorKind::RootCertificate)
    );
}

#[test]
fn ts5_registry_signing_rejects_cross_purpose_policy_aliases() {
    let invalid_policies = [
        TrustPolicyId::GenericX509V1,
        TrustPolicyId::EtsiJadesBaselineBV1,
        TrustPolicyId::EtsiTs119475WrprcV1,
    ];
    let leaf = mock_cert("CN=National TS5 Registrar", "CN=Unknown", false, None, None);

    for policy_id in invalid_policies {
        let config = TrustConfig {
            trust_roots: Vec::new(),
            now: OffsetDateTime::UNIX_EPOCH,
            policy: X509Policy::default(),
            link_policy: Default::default(),
            evaluation: TrustEvaluationContext {
                purpose: TrustPurpose::WalletRelyingPartyRegistrySigning,
                policy_id,
                ..Default::default()
            },
            direct_trust: Vec::new(),
        };

        assert_eq!(
            evaluate_trust_decision(
                std::slice::from_ref(&leaf),
                &config,
                &AllowAllSignatures,
                None,
            )
            .err(),
            Some(TrustError::PurposePolicyMismatch)
        );
    }

    let invalid_purposes = [
        TrustPurpose::Generic,
        TrustPurpose::JadesSigner,
        TrustPurpose::WalletRelyingPartyRegistrationCertificate,
    ];
    for purpose in invalid_purposes {
        let config = TrustConfig {
            trust_roots: Vec::new(),
            now: OffsetDateTime::UNIX_EPOCH,
            policy: X509Policy::default(),
            link_policy: Default::default(),
            evaluation: TrustEvaluationContext {
                purpose,
                policy_id: TrustPolicyId::EudiTs5RegistryResponseSigningV1,
                ..Default::default()
            },
            direct_trust: Vec::new(),
        };

        assert_eq!(
            evaluate_trust_decision(
                std::slice::from_ref(&leaf),
                &config,
                &AllowAllSignatures,
                None,
            )
            .err(),
            Some(TrustError::PurposePolicyMismatch)
        );
    }
}
