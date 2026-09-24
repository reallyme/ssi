// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn device_response_rejects_too_many_documents() {
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
    let first = decoded.documents[0].clone();
    decoded.documents = vec![first; MAX_MDOC_DEVICE_RESPONSE_DOCUMENTS + 1];
    let oversized = encode_mdoc_device_response_cbor(&decoded).unwrap();

    let err = match verify_mdoc_device_response(
        &oversized,
        resolver_for_kid(kid, issuer_public_key),
        &session_transcript,
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::TooManyDocuments)
    );
}

#[test]
fn device_response_rejects_unsupported_version() {
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
    decoded.version = "9.9".to_owned();
    let unsupported = encode_mdoc_device_response_cbor(&decoded).unwrap();

    let err = match verify_mdoc_device_response(
        &unsupported,
        resolver_for_kid(kid, issuer_public_key),
        &session_transcript,
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::UnsupportedDeviceResponseVersion)
    );
}

#[test]
fn device_response_rejects_error_status() {
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
    decoded.status = 10;
    let error_status = encode_mdoc_device_response_cbor(&decoded).unwrap();

    let err = match verify_mdoc_device_response(
        &error_status,
        resolver_for_kid(kid, issuer_public_key),
        &session_transcript,
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceResponseStatus)
    );
}

#[test]
fn device_response_rejects_empty_documents() {
    let response = CiboriumValue::Map(vec![
        (
            CiboriumValue::Text("version".to_owned()),
            CiboriumValue::Text("1.0".to_owned()),
        ),
        (
            CiboriumValue::Text("documents".to_owned()),
            CiboriumValue::Array(Vec::new()),
        ),
        (
            CiboriumValue::Text("status".to_owned()),
            CiboriumValue::Integer(0_u64.into()),
        ),
    ]);

    let err = match verify_mdoc_device_response(
        &ciborium_bytes(&response),
        |_algorithm, _kid| None,
        &session_transcript_cbor(),
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedDeviceResponse)
    );
}
