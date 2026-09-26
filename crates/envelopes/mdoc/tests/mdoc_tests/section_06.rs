// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_mdoc::{
    decode_issuer_signed_item, IssuerSignedItemBytes, MdocIdentifierList, MdocStatus,
    MdocStatusList, MAX_MDOC_ITEM_RANDOM_BYTES, MIN_MDOC_ITEM_RANDOM_BYTES,
};
use envelopes_x509::{parse_cert_der, verify_chain_signatures_pure_rust, X509Chain};

const SYNTHETIC_STATUS_URI: &str = "https://issuer.example/revocation/status-list";
const STATUS_CERTIFICATE_DER: &[u8] =
    include_bytes!("../../../../revocation/ocsp/openssl/tests/fixtures/leaf.der");
const STATUS_ISSUER_DER: &[u8] =
    include_bytes!("../../../../revocation/ocsp/openssl/tests/fixtures/issuer.der");
const STATUS_ROOT_DER: &[u8] =
    include_bytes!("../../../../revocation/ocsp/openssl/tests/fixtures/root.der");

#[test]
fn signed_mso_status_list_interoperates_with_verification() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"status-list-issuer".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let status = MdocStatus::status_list(
        MdocStatusList::new(
            42,
            SYNTHETIC_STATUS_URI.to_owned(),
            Some(STATUS_CERTIFICATE_DER.to_vec()),
        )
        .unwrap(),
    );
    let config = valid_config().with_status(status.clone());
    let (document, issued_mso) = build_mso_mdoc(&config, &sample_elements(), &signer).unwrap();

    let verified = verify_issuer_signed_mdoc(
        &document,
        resolver_for_kid(kid, issuer_public_key),
        1_700_000_001,
    )
    .unwrap();

    assert!(issued_mso.status.as_ref() == Some(&status));
    assert!(verified.mobile_security_object.status.as_ref() == Some(&status));
    let certificate = verified
        .mobile_security_object
        .status
        .as_ref()
        .and_then(MdocStatus::status_list_ref)
        .and_then(MdocStatusList::certificate_der)
        .unwrap();
    let chain = X509Chain {
        certs: vec![
            parse_cert_der(certificate).unwrap(),
            parse_cert_der(STATUS_ISSUER_DER).unwrap(),
            parse_cert_der(STATUS_ROOT_DER).unwrap(),
        ],
    };
    verify_chain_signatures_pure_rust(&chain).unwrap();
}

#[test]
fn signed_mso_identifier_list_interoperates_with_verification() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"identifier-list-issuer".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let status = MdocStatus::identifier_list(
        MdocIdentifierList::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            SYNTHETIC_STATUS_URI.to_owned(),
            None,
        )
        .unwrap(),
    );
    let config = valid_config().with_status(status.clone());
    let (document, issued_mso) = build_mso_mdoc(&config, &sample_elements(), &signer).unwrap();

    let verified = verify_issuer_signed_mdoc(
        &document,
        resolver_for_kid(kid, issuer_public_key),
        1_700_000_001,
    )
    .unwrap();

    assert!(issued_mso.status.as_ref() == Some(&status));
    assert!(verified.mobile_security_object.status.as_ref() == Some(&status));
}

#[test]
fn device_response_rejects_device_auth_algorithm_not_bound_to_device_key() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let (ed25519_device_public_key, _) = issuer_keys();
    let (_, p256_device_private_key) = generate_keypair(Algorithm::P256).unwrap();
    let kid = b"issuer-kid-1".to_vec();
    let issuer_signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    // The MSO authenticates an OKP/Ed25519 device key, but DeviceAuth is
    // produced under ES256; the verifier must not try the key under ES256.
    let device_signer = CoseDeviceAuthSigner {
        alg: Algorithm::P256,
        private_key: &p256_device_private_key,
        kid: None,
    };
    let (document, _) = build_mso_mdoc(
        &valid_config_for_device_key(&ed25519_device_public_key),
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

    let err = match verify_mdoc_device_response(
        &response,
        resolver_for_kid(kid, issuer_public_key),
        &transcript,
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::DeviceKeyAlgorithmMismatch)
    );
}

#[test]
fn issuance_rejects_issuer_signed_item_random_outside_accepted_length() {
    let (_, issuer_private_key) = issuer_keys();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: None,
    };
    for random_len in [1, MIN_MDOC_ITEM_RANDOM_BYTES - 1, MAX_MDOC_ITEM_RANDOM_BYTES + 1] {
        let mut elements = sample_elements();
        elements[0].random = vec![3_u8; random_len];
        let err = match build_mso_mdoc(&valid_config(), &elements, &signer) {
            Ok(_) => MdocEnvelopeError::UnsupportedOperation,
            Err(err) => err,
        };
        assert_eq!(
            err,
            MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidRandomLength)
        );
    }

    let err = match iso23220_relationship_element(
        Iso23220RelationshipKind::LegalRepresentative,
        parse_iso23220_relationship_value(&ciborium_bytes(&CiboriumValue::Array(vec![
            CiboriumValue::Map(vec![(
                CiboriumValue::Text("family_name".to_owned()),
                CiboriumValue::Text("Doe".to_owned()),
            )]),
        ])))
        .unwrap(),
        vec![7_u8; 1],
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };
    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidRandomLength)
    );
}

#[test]
fn decoding_rejects_issuer_signed_item_with_short_random() {
    let item = ciborium_bytes(&CiboriumValue::Map(vec![
        (
            CiboriumValue::Text("digestID".to_owned()),
            CiboriumValue::Integer(1.into()),
        ),
        (
            CiboriumValue::Text("random".to_owned()),
            CiboriumValue::Bytes(vec![1_u8; MIN_MDOC_ITEM_RANDOM_BYTES - 1]),
        ),
        (
            CiboriumValue::Text("elementIdentifier".to_owned()),
            CiboriumValue::Text("family_name".to_owned()),
        ),
        (
            CiboriumValue::Text("elementValue".to_owned()),
            CiboriumValue::Text("Doe".to_owned()),
        ),
    ]));

    let err = match decode_issuer_signed_item(&IssuerSignedItemBytes::new_tag24(item)) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };
    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidRandomLength)
    );
}

#[test]
fn device_response_rejects_cbor_item_amplification_before_decoding() {
    // A 64 KiB input of single-byte items inside nested arrays exceeds the
    // item bound; the pre-scan must reject it before a value tree is built.
    let mut encoded = vec![0x99, 0x01, 0x00];
    for _ in 0..256 {
        encoded.extend_from_slice(&[0x99, 0x01, 0x00]);
        encoded.extend_from_slice(&[0x00; 256]);
    }

    let err = match decode_mdoc_device_response_cbor(&encoded) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };
    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::CborTooManyItems)
    );
}
