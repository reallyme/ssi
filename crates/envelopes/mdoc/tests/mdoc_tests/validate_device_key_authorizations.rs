// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn issuance_rejects_empty_device_key_authorizations() {
    let (_, issuer_private_key) = issuer_keys();
    let issuer_signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: None,
    };
    let config = valid_config().with_key_authorizations(DeviceKeyAuthorizations {
        name_spaces: Vec::new(),
        data_elements: std::collections::BTreeMap::new(),
    });

    assert_eq!(
        build_mso_mdoc(&config, &sample_elements(), &issuer_signer).err(),
        Some(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::InvalidDeviceAuthentication
        ))
    );
}

#[test]
fn issuance_bounds_authorized_namespace_and_element_names() {
    let (_, issuer_private_key) = issuer_keys();
    let issuer_signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: None,
    };
    let oversized = "a".repeat(MAX_MDOC_IDENTIFIER_BYTES + 1);
    let mut data_elements = std::collections::BTreeMap::new();
    data_elements.insert("org.iso.18013.5.1".to_owned(), vec![oversized.clone()]);
    for authorizations in [
        DeviceKeyAuthorizations {
            name_spaces: vec![oversized],
            data_elements: std::collections::BTreeMap::new(),
        },
        DeviceKeyAuthorizations {
            name_spaces: Vec::new(),
            data_elements,
        },
    ] {
        let config = valid_config().with_key_authorizations(authorizations);
        assert_eq!(
            build_mso_mdoc(&config, &sample_elements(), &issuer_signer).err(),
            Some(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::IdentifierTooLong
            ))
        );
    }
}

#[test]
fn device_key_authorizations_limit_signed_elements() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let (device_public_key, device_private_key) = issuer_keys();
    let kid = b"issuer-key-authorizations".to_vec();
    let issuer_signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let device_signer = CoseDeviceAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: device_private_key.as_slice(),
        kid: None,
    };
    let mut data_elements = std::collections::BTreeMap::new();
    data_elements.insert(
        "org.iso.18013.5.1".to_owned(),
        vec!["family_name".to_owned()],
    );
    let config = valid_config_for_device_key(&device_public_key).with_key_authorizations(
        DeviceKeyAuthorizations {
            name_spaces: Vec::new(),
            data_elements,
        },
    );
    let (document, _) = build_mso_mdoc(&config, &sample_elements(), &issuer_signer).unwrap();
    let session_transcript = session_transcript_cbor();

    let authorized_namespaces = ciborium_bytes(&CiboriumValue::Map(vec![(
        CiboriumValue::Text("org.iso.18013.5.1".to_owned()),
        CiboriumValue::Map(vec![(
            CiboriumValue::Text("family_name".to_owned()),
            CiboriumValue::Text("DOE".to_owned()),
        )]),
    )]));
    let authorized = build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document.clone(),
            session_transcript_cbor: session_transcript.clone(),
            device_name_spaces_cbor: Some(authorized_namespaces),
            issuer_namespaces: None,
        },
        &device_signer,
    )
    .unwrap();
    assert!(verify_mdoc_device_response(
        &authorized,
        resolver_for_kid(kid.clone(), issuer_public_key.clone()),
        &session_transcript,
        1_700_000_001,
    )
    .is_ok());

    let unauthorized_namespaces = ciborium_bytes(&CiboriumValue::Map(vec![(
        CiboriumValue::Text("org.iso.18013.5.1".to_owned()),
        CiboriumValue::Map(vec![(
            CiboriumValue::Text("given_name".to_owned()),
            CiboriumValue::Text("ALICE".to_owned()),
        )]),
    )]));
    let unauthorized = build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: session_transcript.clone(),
            device_name_spaces_cbor: Some(unauthorized_namespaces),
            issuer_namespaces: None,
        },
        &device_signer,
    )
    .unwrap();
    assert_eq!(
        verify_mdoc_device_response(
            &unauthorized,
            resolver_for_kid(kid, issuer_public_key),
            &session_transcript,
            1_700_000_001,
        )
        .err(),
        Some(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::InvalidDeviceAuthentication
        ))
    );
}
