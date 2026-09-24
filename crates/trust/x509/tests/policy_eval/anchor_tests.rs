// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn path_length_constraint_violation_has_a_stable_typed_reason() {
    let leaf = mk_leaf();
    let intermediate = mk_intermediate();
    let mut root = mk_intermediate();
    root.subject = "CN=root".to_owned();
    root.issuer = "CN=root".to_owned();
    root.basic_constraints
        .as_mut()
        .expect("test root has basic constraints")
        .path_len_constraint = Some(0);
    let chain = X509Chain {
        certs: vec![leaf, intermediate, root],
    };

    let error = screen_chain_policy_only_no_path_validation(
        &chain,
        OffsetDateTime::UNIX_EPOCH,
        &X509Policy::default(),
    )
    .expect_err("root pathLenConstraint=0 must reject an intermediate CA");

    assert_eq!(
        error,
        X509Error::PolicyFailed(X509PolicyFailure::PathLengthConstraintExceeded)
    );
}

#[test]
fn wrpac_preset_accepts_telephone_contact_and_rejects_incomplete_anchor() {
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);
    let policy = eudi_policy(EudiCertificateProfile::WrpacLeafV1);
    let mut telephone_contact = wrpac_leaf(CertificatePolicyId::WrpacNcpLegal);
    telephone_contact
        .profile
        .subject_alternative_names
        .uris
        .clear();
    telephone_contact
        .profile
        .subject_alternative_names
        .other_names
        .push(OtherName {
            type_id: ObjectIdentifier::parse("2.5.4.20").unwrap(),
            value_der: vec![0xa0, 0x06, 0x13, 0x04, b'+', b'3', b'5', b'6'],
        });
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![telephone_contact.clone(), provider_anchor()]
            },
            now,
            &policy,
        ),
        Ok(())
    );

    for malformed_value in [
        Vec::new(),
        vec![0x13, 0x04, b'+', b'3', b'5', b'6'],
        vec![0xa0, 0x06, 0x0c, 0x04, b'+', b'3', b'5', b'6'],
        [vec![0xa0, 0x23, 0x13, 0x21], vec![b'1'; 33]].concat(),
    ] {
        let mut malformed_contact = wrpac_leaf(CertificatePolicyId::WrpacNcpLegal);
        malformed_contact
            .profile
            .subject_alternative_names
            .uris
            .clear();
        malformed_contact
            .profile
            .subject_alternative_names
            .other_names
            .push(OtherName {
                type_id: ObjectIdentifier::parse("2.5.4.20").unwrap(),
                value_der: malformed_value,
            });
        assert_eq!(
            screen_chain_policy_only_no_path_validation(
                &X509Chain {
                    certs: vec![malformed_contact, provider_anchor()]
                },
                now,
                &policy,
            ),
            Err(X509Error::PolicyFailed(
                X509PolicyFailure::LeafNameRequirement
            ))
        );
    }

    let mut incomplete_anchor = provider_anchor();
    incomplete_anchor.profile.certificate_policies.clear();
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![telephone_contact, incomplete_anchor]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::TrustAnchorMissingCertificatePolicy
        ))
    );

    let mut invalid_algorithm_anchor = provider_anchor();
    invalid_algorithm_anchor.profile.rsa_public_exponent = Some(vec![0x03]);
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![
                    wrpac_leaf(CertificatePolicyId::WrpacNcpLegal),
                    invalid_algorithm_anchor,
                ]
            },
            now,
            &policy,
        ),
        Err(X509Error::PolicyFailed(
            X509PolicyFailure::AlgorithmParametersNotAllowed
        ))
    );
}
