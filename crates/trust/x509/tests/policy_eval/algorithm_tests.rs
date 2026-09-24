// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn qwac_policy_rejects_unapproved_typed_key_and_signature_algorithms() {
    let policy = eu_policy(EuPreset::Qwac);
    let now = OffsetDateTime::UNIX_EPOCH + time::Duration::days(10);

    let mut unapproved_key = mk_leaf();
    unapproved_key.profile.public_key = PublicKeyProfile::Dsa { bits: 3072 };
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![unapproved_key],
            },
            now,
            &policy,
        )
        .unwrap_err(),
        X509Error::PolicyFailed(X509PolicyFailure::PublicKeyAlgorithmNotAllowed)
    );

    let mut unapproved_signature = mk_leaf();
    unapproved_signature.profile.signature_algorithm = SignatureAlgorithm::Ed25519;
    assert_eq!(
        screen_chain_policy_only_no_path_validation(
            &X509Chain {
                certs: vec![unapproved_signature],
            },
            now,
            &policy,
        )
        .unwrap_err(),
        X509Error::PolicyFailed(X509PolicyFailure::SignatureAlgorithmNotAllowed)
    );
}
