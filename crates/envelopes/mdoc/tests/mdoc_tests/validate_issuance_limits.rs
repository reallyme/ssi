// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn issuance_bounds_key_info_and_issuer_element_names() {
    let (_issuer_public_key, issuer_private_key) = issuer_keys();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: None,
    };
    let config = valid_config().with_key_info_cbor(vec![0_u8; MAX_MDOC_KEY_INFO_BYTES + 1]);
    assert_eq!(
        build_mso_mdoc(&config, &sample_elements(), &signer).err(),
        Some(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::KeyInfoTooLarge
        ))
    );

    let mut maximum_identifier_element = element_for_namespace(
        "n".repeat(MAX_MDOC_IDENTIFIER_BYTES),
        "e".repeat(MAX_MDOC_IDENTIFIER_BYTES),
    );
    maximum_identifier_element.random = vec![7; 16];
    assert!(build_mso_mdoc(
        &valid_config(),
        &[maximum_identifier_element],
        &signer,
    )
    .is_ok());

    let oversized = "a".repeat(MAX_MDOC_IDENTIFIER_BYTES + 1);
    for mut element in [
        element_for_namespace(oversized, "family_name".to_owned()),
        element_for_namespace(
            "org.iso.18013.5.1".to_owned(),
            "a".repeat(MAX_MDOC_IDENTIFIER_BYTES + 1),
        ),
    ] {
        element.random = vec![7; 16];
        assert_eq!(
            build_mso_mdoc(&valid_config(), &[element], &signer).err(),
            Some(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::IdentifierTooLong
            ))
        );
    }
}
