// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn device_response_rejects_device_mac_instead_of_device_signature() {
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
    let encoded = build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: session_transcript.clone(),
            device_name_spaces_cbor: None,
            issuer_namespaces: None,
        },
        &device_signer,
    )
    .unwrap();
    let mut response = ciborium_value(&encoded);
    let root = match &mut response {
        CiboriumValue::Map(entries) => Some(entries),
        _ => None,
    }
    .unwrap();
    let documents = match text_map_value_mut(root, "documents") {
        CiboriumValue::Array(values) => Some(values),
        _ => None,
    }
    .unwrap();
    let first_document = match documents.first_mut().unwrap() {
        CiboriumValue::Map(entries) => Some(entries),
        _ => None,
    }
    .unwrap();
    let device_signed = match text_map_value_mut(first_document, "deviceSigned") {
        CiboriumValue::Map(entries) => Some(entries),
        _ => None,
    }
    .unwrap();
    let device_auth = match text_map_value_mut(device_signed, "deviceAuth") {
        CiboriumValue::Map(entries) => Some(entries),
        _ => None,
    }
    .unwrap();
    device_auth.clear();
    device_auth.push((
        CiboriumValue::Text("deviceMac".to_owned()),
        CiboriumValue::Bytes(vec![0_u8; 32]),
    ));

    let error = match verify_mdoc_device_response(
        &ciborium_bytes(&response),
        resolver_for_kid(kid, issuer_public_key),
        &session_transcript,
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(error) => error,
    };

    assert_eq!(
        error,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedDeviceResponse)
    );
}

#[test]
fn device_response_rejects_wrong_session_transcript() {
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
            session_transcript_cbor: session_transcript,
            device_name_spaces_cbor: None,
            issuer_namespaces: None,
        },
        &device_signer,
    )
    .unwrap();
    let wrong_session_transcript = encode_dag_cbor(&CborValue::Array(vec![
        CborValue::String("sessionTranscript".to_owned()),
        CborValue::Int(2),
    ]))
    .unwrap();

    let err = match verify_mdoc_device_response(
        &response,
        resolver_for_kid(kid, issuer_public_key),
        &wrong_session_transcript,
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidDeviceSignature
    );
}
