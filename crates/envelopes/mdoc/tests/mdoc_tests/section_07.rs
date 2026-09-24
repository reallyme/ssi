// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn device_response_rejects_attached_device_signature_payload() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let (device_public_key, device_private_key) = issuer_keys();
    let kid = b"issuer-kid-attached".to_vec();
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
    let (document, _) = build_mso_mdoc(
        &valid_config_for_device_key(&device_public_key),
        &sample_elements(),
        &issuer_signer,
    )
    .unwrap();
    let transcript = session_transcript_cbor();
    let response = build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: transcript.clone(),
            device_name_spaces_cbor: None,
            issuer_namespaces: None,
        },
        &device_signer,
    )
    .unwrap();
    let mut decoded = decode_mdoc_device_response_cbor(&response).unwrap();
    let detached_payload = reallyme_mdoc::build_device_authentication_cbor(
        &reallyme_mdoc::DeviceAuthenticationInput {
            session_transcript_cbor: &transcript,
            doc_type: "org.iso.18013.5.1.mDL",
            device_name_spaces_cbor: &[0xa0],
        },
    )
    .unwrap();
    decoded.documents[0].device_signed.device_auth = cose_sign1(
        Algorithm::Ed25519,
        &detached_payload,
        &device_private_key,
        None,
    )
    .unwrap()
    .to_vec();
    let attached = encode_mdoc_device_response_cbor(&decoded).unwrap();

    let error = verify_mdoc_device_response(
        &attached,
        resolver_for_kid(kid, issuer_public_key),
        &transcript,
        1_700_000_001,
    )
    .err();
    assert_eq!(error, Some(MdocEnvelopeError::InvalidDeviceSignature));
}

#[test]
fn device_response_rejects_tampered_device_auth() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let (device_public_key, device_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
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
    let (document, _) = build_mso_mdoc(
        &valid_config_for_device_key(&device_public_key),
        &sample_elements(),
        &issuer_signer,
    )
    .unwrap();
    let session_transcript = session_transcript_cbor();
    let response = build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: session_transcript.clone(),
            device_name_spaces_cbor: None,
            issuer_namespaces: None,
        },
        &device_signer,
    )
    .unwrap();
    let mut decoded = decode_mdoc_device_response_cbor(&response).unwrap();
    let signature_byte = decoded.documents[0]
        .device_signed
        .device_auth
        .last_mut()
        .unwrap();
    *signature_byte ^= 0xff;
    let tampered = encode_mdoc_device_response_cbor(&decoded).unwrap();

    let err = match verify_mdoc_device_response(
        &tampered,
        resolver_for_kid(kid, issuer_public_key),
        &session_transcript,
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(err, MdocEnvelopeError::InvalidDeviceSignature);
}

#[test]
fn device_response_rejects_expired_mso() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let (device_public_key, device_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
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
    let (document, _) = build_mso_mdoc(
        &valid_config_for_device_key(&device_public_key),
        &sample_elements(),
        &issuer_signer,
    )
    .unwrap();
    let session_transcript = session_transcript_cbor();
    let response = build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: session_transcript.clone(),
            device_name_spaces_cbor: None,
            issuer_namespaces: None,
        },
        &device_signer,
    )
    .unwrap();

    let err = match verify_mdoc_device_response(
        &response,
        resolver_for_kid(kid, issuer_public_key),
        &session_transcript,
        1_800_000_000,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(err, MdocEnvelopeError::Expired);
}

#[test]
fn device_response_rejects_wrong_device_key() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let (device_public_key, _device_private_key) = issuer_keys();
    let (_wrong_device_public_key, wrong_device_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let issuer_signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let wrong_device_signer = CoseDeviceAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: wrong_device_private_key.as_slice(),
        kid: None,
    };
    let (document, _) = build_mso_mdoc(
        &valid_config_for_device_key(&device_public_key),
        &sample_elements(),
        &issuer_signer,
    )
    .unwrap();
    let session_transcript = session_transcript_cbor();
    let response = build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: session_transcript.clone(),
            device_name_spaces_cbor: None,
            issuer_namespaces: None,
        },
        &wrong_device_signer,
    )
    .unwrap();

    let err = match verify_mdoc_device_response(
        &response,
        resolver_for_kid(kid, issuer_public_key),
        &session_transcript,
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(err, MdocEnvelopeError::InvalidDeviceSignature);
}

#[test]
fn device_response_preserves_authentication_with_no_optional_issuer_elements() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let (device_public_key, device_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
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
    let (document, _) = build_mso_mdoc(
        &valid_config_for_device_key(&device_public_key),
        &sample_elements(),
        &issuer_signer,
    )
    .unwrap();
    let session_transcript = session_transcript_cbor();

    let response = build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: session_transcript.clone(),
            device_name_spaces_cbor: None,
            // `Some(empty)` is the explicit minimal-disclosure instruction.
            // `None` deliberately retains every issuer-signed element.
            issuer_namespaces: Some(Vec::new()),
        },
        &device_signer,
    )
    .unwrap();
    let decoded = decode_mdoc_device_response_cbor(&response).unwrap();
    let disclosed = decoded.documents[0]
        .issuer_signed
        .issuer_signed
        .name_spaces
        .as_ref()
        .unwrap();

    assert!(disclosed.is_empty());
    verify_mdoc_device_response(
        &response,
        resolver_for_kid(kid, issuer_public_key),
        &session_transcript,
        1_700_000_001,
    )
    .unwrap();
}

#[test]
fn device_response_rejects_missing_requested_namespace() {
    let (_issuer_public_key, issuer_private_key) = issuer_keys();
    let (device_public_key, device_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
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
    let (document, _) = build_mso_mdoc(
        &valid_config_for_device_key(&device_public_key),
        &sample_elements(),
        &issuer_signer,
    )
    .unwrap();

    let err = match build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: session_transcript_cbor(),
            device_name_spaces_cbor: None,
            issuer_namespaces: Some(vec![IssuerNamespaceSelection {
                namespace: "org.iso.18013.5.1.missing".to_owned(),
                element_identifiers: vec!["family_name".to_owned()],
            }]),
        },
        &device_signer,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MissingDisclosedElement)
    );
}

#[test]
fn device_response_rejects_missing_requested_element() {
    let (_issuer_public_key, issuer_private_key) = issuer_keys();
    let (device_public_key, device_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
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
    let (document, _) = build_mso_mdoc(
        &valid_config_for_device_key(&device_public_key),
        &sample_elements(),
        &issuer_signer,
    )
    .unwrap();

    let err = match build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: session_transcript_cbor(),
            device_name_spaces_cbor: None,
            issuer_namespaces: Some(vec![IssuerNamespaceSelection {
                namespace: "org.iso.18013.5.1".to_owned(),
                element_identifiers: vec!["missing_element".to_owned()],
            }]),
        },
        &device_signer,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MissingDisclosedElement)
    );
}

#[test]
fn device_response_rejects_malformed_device_namespaces_cbor() {
    let (_issuer_public_key, issuer_private_key) = issuer_keys();
    let (device_public_key, device_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
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
    let (document, _) = build_mso_mdoc(
        &valid_config_for_device_key(&device_public_key),
        &sample_elements(),
        &issuer_signer,
    )
    .unwrap();

    let err = match build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: session_transcript_cbor(),
            device_name_spaces_cbor: Some(Vec::new()),
            issuer_namespaces: None,
        },
        &device_signer,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceNameSpaces)
    );
}
