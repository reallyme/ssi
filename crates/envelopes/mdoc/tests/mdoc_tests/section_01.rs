// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value as CiboriumValue;
use reallyme_mdoc::{
    build_mdoc_device_response_cbor, build_mso_mdoc, decode_mdoc_device_response_cbor,
    decode_mdoc_issuer_signed_cbor, encode_mdoc_device_response_cbor,
    encode_mdoc_issuer_signed_cbor, iso23220_relationship_element,
    parse_iso23220_relationship_value, validate_x5chain_issuer_auth,
    verify_issuer_signed_mdoc, verify_issuer_signed_mdoc_receipt_with_x5chain,
    verify_mdoc_device_response,
    verify_mdoc_device_response_with_x5chain, BuildMdocDeviceResponseInput, CoseDeviceAuthSigner,
    CoseIssuerAuthSigner, CoseX5ChainIssuerAuthSigner, Iso23220RelationshipKind,
    IssuerAuthSigner, IssuerNamespaceSelection, MdocElement, MdocEnvelopeError,
    MdocInvalidInputReason,
    MdocIssueConfig, ValidityInfo, ISO_23220_NAMESPACE,
    MAX_MDOC_CBOR_ARRAY_ITEMS, MAX_MDOC_CBOR_DEPTH, MAX_MDOC_CBOR_INPUT_BYTES,
    MAX_MDOC_CBOR_MAP_ENTRIES, MAX_MDOC_DEVICE_RESPONSE_DOCUMENTS, MAX_MDOC_ELEMENTS_PER_NAMESPACE,
    MAX_MDOC_ELEMENT_VALUE_BYTES, MAX_MDOC_ISSUER_ELEMENTS, MAX_MDOC_NAMESPACES,
    MAX_MDOC_TOTAL_ELEMENT_VALUE_BYTES,
};
use reallyme_codec::cbor::{encode_dag_cbor, CborValue};
use reallyme_cose::{
    cose_key_from_public_bytes, cose_key_from_signature_public_bytes, cose_key_to_vec,
    cose_sign1, cose_verify1, Algorithm, CoseSignatureAlgorithm,
};
use reallyme_crypto::dispatch::generate_keypair;
use serde_json::Value;

const MDOC_ISSUER_SIGNED_VECTORS: &str =
    include_str!("../../../../../vectors/mdoc-issuer-signed.json");

fn cbor_text(value: &str) -> Vec<u8> {
    encode_dag_cbor(&CborValue::String(value.to_owned())).unwrap()
}

fn issuer_keys() -> (Vec<u8>, Vec<u8>) {
    let (public, private) = generate_keypair(Algorithm::Ed25519).unwrap();
    (public, private.to_vec())
}

fn resolver_for_kid(
    expected_kid: Vec<u8>,
    issuer_public_key: Vec<u8>,
) -> impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>> {
    move |algorithm, kid| {
        if algorithm == Algorithm::Ed25519 && kid == expected_kid.as_slice() {
            Some(issuer_public_key.clone())
        } else {
            None
        }
    }
}

fn valid_config() -> MdocIssueConfig {
    let (device_public_key, _) = issuer_keys();
    valid_config_for_device_key(&device_public_key)
}

fn valid_config_for_device_key(device_public_key: &[u8]) -> MdocIssueConfig {
    MdocIssueConfig::new(
        "org.iso.18013.5.1.mDL",
        ValidityInfo {
            signed: 1_700_000_000,
            valid_from: 1_700_000_000,
            valid_until: 1_800_000_000,
        },
        device_cose_key(device_public_key),
    )
}

fn device_cose_key(device_public_key: &[u8]) -> Vec<u8> {
    cose_key_to_vec(&cose_key_from_public_bytes(Algorithm::Ed25519, device_public_key).unwrap())
        .unwrap()
        .to_vec()
}

fn session_transcript_cbor() -> Vec<u8> {
    encode_dag_cbor(&CborValue::Array(vec![
        CborValue::String("sessionTranscript".to_owned()),
        CborValue::Int(1),
    ]))
    .unwrap()
}

fn sample_elements() -> Vec<MdocElement> {
    vec![
        MdocElement {
            namespace: "org.iso.18013.5.1".to_owned(),
            element_identifier: "family_name".to_owned(),
            element_value_cbor: cbor_text("DOE"),
            random: vec![1_u8; 16],
        },
        MdocElement {
            namespace: "org.iso.18013.5.1".to_owned(),
            element_identifier: "given_name".to_owned(),
            element_value_cbor: cbor_text("ALICE"),
            random: vec![2_u8; 16],
        },
    ]
}

fn element_for_namespace(namespace: String, element_identifier: String) -> MdocElement {
    MdocElement {
        namespace,
        element_identifier,
        element_value_cbor: cbor_text("value"),
        random: vec![9_u8; 16],
    }
}

fn ciborium_bytes(value: &CiboriumValue) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).unwrap();
    out
}

fn ciborium_value(bytes: &[u8]) -> CiboriumValue {
    ciborium::de::from_reader(bytes).unwrap()
}

fn text_map_value<'a>(
    entries: &'a [(CiboriumValue, CiboriumValue)],
    key: &str,
) -> &'a CiboriumValue {
    entries
        .iter()
        .find_map(|(candidate, value)| match candidate {
            CiboriumValue::Text(candidate) if candidate == key => Some(value),
            _ => None,
        })
        .unwrap()
}

fn text_map_value_mut<'a>(
    entries: &'a mut [(CiboriumValue, CiboriumValue)],
    key: &str,
) -> &'a mut CiboriumValue {
    entries
        .iter_mut()
        .find_map(|(candidate, value)| match candidate {
            CiboriumValue::Text(candidate) if candidate == key => Some(value),
            _ => None,
        })
        .unwrap()
}

struct MutatingMsoSigner<'a> {
    private_key: &'a [u8],
    kid: &'a [u8],
    field: &'a str,
    replacement: &'a str,
}

impl IssuerAuthSigner for MutatingMsoSigner<'_> {
    fn sign_issuer_auth(&self, mso_cbor: &[u8]) -> Result<Vec<u8>, MdocEnvelopeError> {
        let mut tagged_mso = ciborium_value(mso_cbor);
        let encoded_mso = match &mut tagged_mso {
            CiboriumValue::Tag(24, value) => value.as_bytes_mut(),
            _ => None,
        }
        .unwrap();
        let mut mso = ciborium_value(encoded_mso);
        let entries = mso.as_map_mut().unwrap();
        *text_map_value_mut(entries, self.field) =
            CiboriumValue::Text(self.replacement.to_owned());
        *encoded_mso = ciborium_bytes(&mso);
        cose_sign1(
            Algorithm::Ed25519,
            &ciborium_bytes(&tagged_mso),
            self.private_key,
            Some(self.kid),
        )
        .map(|signed| signed.to_vec())
        .map_err(|_| MdocEnvelopeError::Signing)
    }
}

fn hex_to_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair.as_slice()).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[test]
fn builds_and_verifies_device_response() {
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

    let verified = verify_mdoc_device_response(
        &response,
        resolver_for_kid(kid, issuer_public_key),
        &session_transcript,
        1_700_000_001,
    )
    .unwrap();

    assert_eq!(verified.device_response.documents.len(), 1);
    assert_eq!(verified.verified_documents.len(), 1);
    assert_eq!(
        verified.verified_documents[0].doc_type,
        "org.iso.18013.5.1.mDL"
    );
}

#[test]
fn device_response_uses_tagged_namespaces_and_detached_device_signature() {
    let (_, issuer_private_key) = issuer_keys();
    let (device_public_key, device_private_key) = issuer_keys();
    let issuer_signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: None,
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
    let encoded = build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: session_transcript_cbor(),
            device_name_spaces_cbor: None,
            issuer_namespaces: None,
        },
        &device_signer,
    )
    .unwrap();

    let response = ciborium_value(&encoded);
    let root = match &response {
        CiboriumValue::Map(entries) => Some(entries),
        _ => None,
    }
    .unwrap();
    let documents = match text_map_value(root, "documents") {
        CiboriumValue::Array(values) => Some(values),
        _ => None,
    }
    .unwrap();
    let document = match documents.first() {
        Some(CiboriumValue::Map(entries)) => Some(entries),
        _ => None,
    }
    .unwrap();
    let device_signed = match text_map_value(document, "deviceSigned") {
        CiboriumValue::Map(entries) => Some(entries),
        _ => None,
    }
    .unwrap();
    assert!(matches!(
        text_map_value(device_signed, "nameSpaces"),
        CiboriumValue::Tag(24, value)
            if matches!(value.as_ref(), CiboriumValue::Bytes(bytes) if bytes == &[0xa0])
    ));
    let device_auth = match text_map_value(device_signed, "deviceAuth") {
        CiboriumValue::Map(entries) => Some(entries),
        _ => None,
    }
    .unwrap();
    let sign1 = match text_map_value(device_auth, "deviceSignature") {
        CiboriumValue::Tag(18, value) => value.as_ref(),
        value => value,
    };
    assert!(matches!(
        sign1,
        CiboriumValue::Array(fields)
            if matches!(fields.get(2), Some(CiboriumValue::Null))
    ));
}

#[test]
fn device_response_rejects_noncanonical_device_namespaces_containers() {
    let (_, issuer_private_key) = issuer_keys();
    let (device_public_key, device_private_key) = issuer_keys();
    let issuer_signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: None,
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
    let encoded = build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: session_transcript_cbor(),
            device_name_spaces_cbor: None,
            issuer_namespaces: None,
        },
        &device_signer,
    )
    .unwrap();
    let response = ciborium_value(&encoded);

    for invalid_name_spaces in [
        CiboriumValue::Map(Vec::new()),
        CiboriumValue::Tag(25, Box::new(CiboriumValue::Bytes(vec![0xa0]))),
        CiboriumValue::Tag(24, Box::new(CiboriumValue::Text("not-a-bstr".to_owned()))),
    ] {
        let mut invalid = response.clone();
        let root = match &mut invalid {
            CiboriumValue::Map(entries) => Some(entries),
            _ => None,
        }
        .unwrap();
        let documents = match text_map_value_mut(root, "documents") {
            CiboriumValue::Array(values) => Some(values),
            _ => None,
        }
        .unwrap();
        let document = match documents.first_mut() {
            Some(CiboriumValue::Map(entries)) => Some(entries),
            _ => None,
        }
        .unwrap();
        let device_signed = match text_map_value_mut(document, "deviceSigned") {
            CiboriumValue::Map(entries) => Some(entries),
            _ => None,
        }
        .unwrap();
        *text_map_value_mut(device_signed, "nameSpaces") = invalid_name_spaces;

        let error = decode_mdoc_device_response_cbor(&ciborium_bytes(&invalid)).err();
        assert_eq!(
            error,
            Some(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::InvalidDeviceNameSpaces
            ))
        );
    }
}

#[test]
fn device_response_rejects_duplicate_device_signed_members() {
    let (_, issuer_private_key) = issuer_keys();
    let (device_public_key, device_private_key) = issuer_keys();
    let issuer_signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: None,
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
    let encoded = build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: session_transcript_cbor(),
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
    let document = match documents.first_mut() {
        Some(CiboriumValue::Map(entries)) => Some(entries),
        _ => None,
    }
    .unwrap();
    let device_signed = match text_map_value_mut(document, "deviceSigned") {
        CiboriumValue::Map(entries) => Some(entries),
        _ => None,
    }
    .unwrap();
    device_signed.push((
        CiboriumValue::Text("nameSpaces".to_owned()),
        CiboriumValue::Tag(24, Box::new(CiboriumValue::Bytes(vec![0xa0]))),
    ));

    let error = decode_mdoc_device_response_cbor(&ciborium_bytes(&response)).err();
    assert_eq!(
        error,
        Some(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedDeviceResponse
        ))
    );
}

#[test]
fn p256_device_signature_round_trip_matches_haip_profile() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let (device_public_key, device_private_key) = generate_keypair(Algorithm::P256).unwrap();
    let device_cose_key = cose_key_to_vec(
        &cose_key_from_public_bytes(Algorithm::P256, &device_public_key).unwrap(),
    )
    .unwrap();
    let issuer_kid = b"issuer-kid-p256".to_vec();
    let issuer_signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(issuer_kid.as_slice()),
    };
    let device_signer = CoseDeviceAuthSigner {
        alg: Algorithm::P256,
        private_key: &device_private_key,
        kid: None,
    };
    let (document, _) = build_mso_mdoc(
        &MdocIssueConfig::new(
            "org.iso.18013.5.1.mDL",
            ValidityInfo {
                signed: 1_700_000_000,
                valid_from: 1_700_000_000,
                valid_until: 1_800_000_000,
            },
            device_cose_key.to_vec(),
        ),
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

    verify_mdoc_device_response(
        &response,
        resolver_for_kid(issuer_kid, issuer_public_key),
        &transcript,
        1_700_000_001,
    )
    .unwrap();
}

#[test]
fn builds_and_verifies_x5chain_device_response() {
    const LEAF_CERTIFICATE_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];

    let (issuer_public_key, issuer_private_key) = generate_keypair(Algorithm::P256).unwrap();
    let (device_public_key, device_private_key) = issuer_keys();
    let certificate_path = vec![LEAF_CERTIFICATE_DER.to_vec()];
    let issuer_signer = CoseX5ChainIssuerAuthSigner {
        algorithm: CoseSignatureAlgorithm::Es256,
        private_key: &issuer_private_key,
        kid: None,
        x5chain_der: &certificate_path,
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

    let verified = verify_mdoc_device_response_with_x5chain(
        &response,
        |presented_path| {
            (presented_path == certificate_path.as_slice()).then(|| issuer_public_key.clone())
        },
        &session_transcript,
        1_700_000_001,
    )
    .unwrap();
    assert_eq!(verified.verified_documents.len(), 1);

    let error = match verify_mdoc_device_response_with_x5chain(
        &response,
        |_presented_path| None,
        &session_transcript,
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(error) => error,
    };
    assert_eq!(error, MdocEnvelopeError::InvalidSignature);
}

#[test]
fn issuance_rejects_malformed_device_cose_key() {
    let (_, issuer_private_key) = issuer_keys();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: None,
    };
    let mut config = valid_config();
    config.device_key_cose_key_cbor = vec![0xa0];

    let error = build_mso_mdoc(&config, &sample_elements(), &signer).err();
    assert_eq!(
        error,
        Some(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::InvalidDeviceAuthentication
        ))
    );
}

#[test]
fn device_response_rejects_missing_device_signed_holder_authentication() {
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
    first_document.retain(|(key, _)| {
        !matches!(key, CiboriumValue::Text(value) if value == "deviceSigned")
    });

    // Regression for CVE-2026-77456: issuerAuth alone authenticates issuer
    // data, not the presenting device. OpenID4VP Appendix B.2.6 requires the
    // DeviceAuthentication proof bound to this SessionTranscript.
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
