// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn wrpac_preset_accepts_policy_unions_and_requires_every_subject_family() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let policy = eudi_policy(EudiCertificateProfile::WrpacLeafV1);

    let mut same_family = wrpac_leaf(CertificatePolicyId::WrpacQcpNatural);
    same_family
        .profile
        .certificate_policies
        .push(CertificatePolicyId::WrpacNcpNatural);
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![same_family, provider_anchor()]
            },
            now,
            &policy,
        ),
        Ok(())
    );

    let mut both_families = wrpac_leaf(CertificatePolicyId::WrpacQcpLegal);
    both_families
        .profile
        .certificate_policies
        .push(CertificatePolicyId::WrpacQcpNatural);
    both_families.profile.subject = natural_and_legal_person_name();
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![both_families, provider_anchor()]
            },
            now,
            &policy,
        ),
        Ok(())
    );

    let mut incomplete_subject = wrpac_leaf(CertificatePolicyId::WrpacQcpNatural);
    incomplete_subject
        .profile
        .certificate_policies
        .push(CertificatePolicyId::WrpacQcpLegal);
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![incomplete_subject, provider_anchor()]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafSubjectNameProfile
        ))
    );
}

#[test]
fn wrpac_preset_rejects_missing_policy_qc_and_forbidden_extensions() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let policy = eudi_policy(EudiCertificateProfile::WrpacLeafV1);

    let mut missing_policy = wrpac_leaf(CertificatePolicyId::WrpacNcpNatural);
    missing_policy.profile.certificate_policies.clear();
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![missing_policy, provider_anchor()]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::WrpacPolicyAmbiguous
        ))
    );

    let mut missing_qc_sscd = wrpac_leaf(CertificatePolicyId::WrpacQcpNatural);
    missing_qc_sscd
        .profile
        .qc_statement_ids
        .retain(|statement| *statement != QcStatementId::QcSscd);
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![missing_qc_sscd, provider_anchor()]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::WrpacQcStatements
        ))
    );

    let mut wrong_qc = wrpac_leaf(CertificatePolicyId::WrpacQcpLegal);
    wrong_qc.profile.qc_types = vec![QcType::ElectronicSignature];
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![wrong_qc, provider_anchor()]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::WrpacQcStatements
        ))
    );

    let mut short_term = wrpac_leaf(CertificatePolicyId::WrpacNcpLegal);
    short_term.profile.extensions.push(extension(
        CertificateExtensionKind::Other(ObjectIdentifier::parse("0.4.0.194121.2.1").unwrap()),
        false,
    ));
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![short_term, provider_anchor()]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::WrpacValidityAssuredShortTerm
        ))
    );

    let mut no_rev_avail = wrpac_leaf(CertificatePolicyId::WrpacNcpLegal);
    no_rev_avail.profile.no_rev_avail = true;
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![no_rev_avail, provider_anchor()]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::LeafForbiddenNoRevAvail
        ))
    );
}

#[test]
fn eudi_leaf_profiles_require_positive_serial_numbers() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let cases = [
        (
            pid_or_wallet_leaf(QcType::PidProvider),
            EudiCertificateProfile::PidProviderSignerV1,
        ),
        (
            pid_or_wallet_leaf(QcType::WalletProvider),
            EudiCertificateProfile::WalletProviderSignerV1,
        ),
        (
            wrpac_leaf(CertificatePolicyId::WrpacNcpNatural),
            EudiCertificateProfile::WrpacLeafV1,
        ),
    ];
    for (mut leaf, profile) in cases {
        leaf.serial = vec![0];
        assert_eq!(
            screen_chain_policy_only_no_path_validation(
                &X509Chain { certs: vec![leaf] },
                now,
                &eudi_policy(profile),
            ),
            Err(X509Error::InvalidSerialNumber)
        );
    }
}

#[test]
fn eudi_end_entity_criticality_allows_only_basic_constraints_and_key_usage() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let policy = eudi_policy(EudiCertificateProfile::WrpacLeafV1);
    let mut allowed = wrpac_leaf(CertificatePolicyId::WrpacNcpNatural);
    let key_usage = allowed
        .profile
        .extensions
        .iter_mut()
        .find(|extension| extension.kind == CertificateExtensionKind::KeyUsage)
        .unwrap();
    key_usage.critical = false;
    allowed
        .profile
        .extensions
        .push(extension(CertificateExtensionKind::BasicConstraints, true));
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![allowed, provider_anchor()]
            },
            now,
            &policy,
        ),
        Ok(())
    );

    let baseline = wrpac_leaf(CertificatePolicyId::WrpacNcpNatural);
    for index in 1..baseline.profile.extensions.len() {
        let mut rejected = baseline.clone();
        rejected
            .profile
            .extensions
            .get_mut(index)
            .expect("index comes from the baseline extension list")
            .critical = true;
        assert_eq!(
            screen_chain_policy_only_no_path_validation(
                &X509Chain {
                    certs: vec![rejected, provider_anchor()]
                },
                now,
                &policy,
            ),
            Err(X509Error::PolicyFailed(
                X509PolicyFailure::ExtensionCriticality
            ))
        );
    }
}
