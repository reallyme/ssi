// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn device_response_decoder_requires_status() {
    let response = CiboriumValue::Map(vec![
        (
            CiboriumValue::Text("version".to_owned()),
            CiboriumValue::Text("1.0".to_owned()),
        ),
        (
            CiboriumValue::Text("documents".to_owned()),
            CiboriumValue::Array(Vec::new()),
        ),
    ]);

    let err = match decode_mdoc_device_response_cbor(&ciborium_bytes(&response)) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };
    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedDeviceResponse)
    );
}

#[test]
fn device_response_decoder_rejects_trailing_cbor() {
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
    let mut encoded = ciborium_bytes(&response);
    encoded.push(0xf6);

    let err = match decode_mdoc_device_response_cbor(&encoded) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };
    assert_eq!(err, MdocEnvelopeError::Cbor);
}

#[test]
fn device_response_rejects_cbor_depth_over_limit() {
    let mut value = CiboriumValue::Null;
    for _ in 0..=MAX_MDOC_CBOR_DEPTH {
        value = CiboriumValue::Array(vec![value]);
    }

    let err = match decode_mdoc_device_response_cbor(&ciborium_bytes(&value)) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::CborDepthExceeded)
    );
}

#[test]
fn device_response_rejects_cbor_array_over_limit() {
    let items = (0..=MAX_MDOC_CBOR_ARRAY_ITEMS)
        .map(|_| CiboriumValue::Null)
        .collect::<Vec<_>>();

    let err = match decode_mdoc_device_response_cbor(&ciborium_bytes(&CiboriumValue::Array(items)))
    {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::CborArrayTooLarge)
    );
}

#[test]
fn device_response_rejects_cbor_map_over_limit() {
    let entries = (0..=MAX_MDOC_CBOR_MAP_ENTRIES)
        .map(|index| {
            (
                CiboriumValue::Text(format!("k{index}")),
                CiboriumValue::Null,
            )
        })
        .collect::<Vec<_>>();

    let err = match decode_mdoc_device_response_cbor(&ciborium_bytes(&CiboriumValue::Map(entries)))
    {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::CborMapTooLarge)
    );
}

#[test]
fn portable_mdoc_issuer_signed_vector_matches_value_digests() {
    let suite: Value = serde_json::from_str(MDOC_ISSUER_SIGNED_VECTORS).unwrap();
    let case = &suite["cases"][0];
    let elements = case["elements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|element| MdocElement {
            namespace: element["namespace"].as_str().unwrap().to_owned(),
            element_identifier: element["element_identifier"].as_str().unwrap().to_owned(),
            element_value_cbor: hex_to_bytes(element["element_value_cbor_hex"].as_str().unwrap()),
            random: hex_to_bytes(element["random_hex"].as_str().unwrap()),
        })
        .collect::<Vec<_>>();
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let (device_public_key, _) = issuer_keys();
    let cfg = MdocIssueConfig::new(
        case["doc_type"].as_str().unwrap(),
        ValidityInfo {
            signed: case["validity_info"]["signed"].as_u64().unwrap(),
            valid_from: case["validity_info"]["valid_from"].as_u64().unwrap(),
            valid_until: case["validity_info"]["valid_until"].as_u64().unwrap(),
        },
        device_cose_key(&device_public_key),
    );

    let (document, mobile_security_object) = build_mso_mdoc(&cfg, &elements, &signer).unwrap();
    verify_issuer_signed_mdoc(
        &document,
        resolver_for_kid(kid, issuer_public_key),
        1_700_000_001,
    )
    .unwrap();

    let namespace = "org.iso.18013.5.1";
    let expected_items = case["elements"].as_array().unwrap();
    let actual_items = document
        .issuer_signed
        .name_spaces
        .as_ref()
        .unwrap()
        .get(namespace)
        .unwrap();
    assert_eq!(actual_items.len(), expected_items.len());
    for (actual, expected) in actual_items.iter().zip(expected_items) {
        let issuer_signed_item_bytes = ciborium_bytes(&CiboriumValue::Tag(
            actual.tag,
            Box::new(CiboriumValue::Bytes(actual.bstr.clone())),
        ));
        assert_eq!(
            bytes_to_hex(issuer_signed_item_bytes.as_slice()),
            expected["issuer_signed_item_bytes_hex"].as_str().unwrap()
        );
    }

    let actual_digests = mobile_security_object.value_digests.get(namespace).unwrap();
    let expected_digests = case["expected_value_digests"][namespace]
        .as_object()
        .unwrap();
    assert_eq!(actual_digests.len(), expected_digests.len());
    for (digest_id, expected_digest) in expected_digests {
        let digest_id = digest_id.parse::<u64>().unwrap();
        assert_eq!(
            bytes_to_hex(actual_digests.get(&digest_id).unwrap()),
            expected_digest.as_str().unwrap()
        );
    }
}

#[test]
fn verification_rejects_authenticated_unsupported_mso_version_and_digest_algorithm() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1";
    let cases = [
        (
            "version",
            "9.9",
            MdocInvalidInputReason::UnsupportedMsoVersion,
        ),
        (
            "digestAlgorithm",
            "SHA-512",
            MdocInvalidInputReason::UnsupportedDigestAlgorithm,
        ),
    ];

    for (field, replacement, expected_reason) in cases {
        let signer = MutatingMsoSigner {
            private_key: issuer_private_key.as_slice(),
            kid,
            field,
            replacement,
        };
        let (document, _) = build_mso_mdoc(&valid_config(), &sample_elements(), &signer).unwrap();
        let error = verify_issuer_signed_mdoc(
            &document,
            resolver_for_kid(kid.to_vec(), issuer_public_key.clone()),
            1_700_000_001,
        )
        .err();
        assert_eq!(
            error,
            Some(MdocEnvelopeError::InvalidInput(expected_reason))
        );
    }
}

#[test]
fn issuer_auth_uses_iso_tagged_mso_types() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let (document, _) = build_mso_mdoc(&valid_config(), &sample_elements(), &signer).unwrap();
    let payload = cose_verify1(
        &document.issuer_signed.issuer_auth,
        resolver_for_kid(kid, issuer_public_key),
    )
    .unwrap();
    let payload_value = ciborium_value(&payload);
    let (tag, encoded_mso) = payload_value.as_tag().unwrap();
    assert_eq!(tag, 24);
    let mso = ciborium_value(encoded_mso.as_bytes().unwrap());
    let mso_entries = mso.as_map().unwrap();

    let validity_entries = text_map_value(mso_entries, "validityInfo")
        .as_map()
        .unwrap();
    let (signed_tag, signed_value) = text_map_value(validity_entries, "signed").as_tag().unwrap();
    assert_eq!(signed_tag, 0);
    assert!(signed_value.as_text().is_some());

    let namespace_entries = text_map_value(mso_entries, "valueDigests")
        .as_map()
        .unwrap();
    let digest_entries = text_map_value(namespace_entries, "org.iso.18013.5.1")
        .as_map()
        .unwrap();
    assert!(
        digest_entries
            .iter()
            .all(|(digest_id, digest)| digest_id.as_integer().is_some()
                && digest.as_bytes().is_some())
    );

    let device_key_entries = text_map_value(mso_entries, "deviceKeyInfo")
        .as_map()
        .unwrap();
    assert!(text_map_value(device_key_entries, "deviceKey")
        .as_map()
        .is_some());
}

#[test]
fn issuer_signed_transport_embeds_es256_x5chain_cose() {
    const LEAF_CERTIFICATE_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];

    let (device_public_key, _) = generate_keypair(Algorithm::P256).unwrap();
    let (issuer_public_key, issuer_private_key) = generate_keypair(Algorithm::P256).unwrap();
    let device_key = cose_key_to_vec(
        &cose_key_from_signature_public_bytes(CoseSignatureAlgorithm::Es256, &device_public_key)
            .unwrap(),
    )
    .unwrap();
    let config = MdocIssueConfig::new(
        "eu.europa.ec.eudi.pid.1",
        ValidityInfo {
            signed: 1_700_000_000,
            valid_from: 1_700_000_000,
            valid_until: 1_800_000_000,
        },
        device_key.to_vec(),
    );
    let certificates = vec![LEAF_CERTIFICATE_DER.to_vec()];
    let signer = CoseX5ChainIssuerAuthSigner {
        algorithm: CoseSignatureAlgorithm::Es256,
        private_key: &issuer_private_key,
        kid: None,
        x5chain_der: &certificates,
    };
    let (document, _) = build_mso_mdoc(&config, &sample_elements(), &signer).unwrap();
    let encoded = reallyme_mdoc::encode_mdoc_issuer_signed_cbor(&document).unwrap();
    let issuer_signed = ciborium_value(&encoded);
    let issuer_auth = text_map_value(issuer_signed.as_map().unwrap(), "issuerAuth");
    let fields = issuer_auth.as_array().unwrap();
    let protected = ciborium_value(
        fields
            .first()
            .and_then(CiboriumValue::as_bytes)
            .unwrap(),
    );
    assert!(protected.as_map().unwrap().iter().any(|(label, value)| {
        label.as_integer().map(i128::from) == Some(1)
            && value.as_integer().map(i128::from) == Some(-7)
    }));
    assert!(
        fields
            .get(1)
            .and_then(CiboriumValue::as_map)
            .unwrap()
            .iter()
            .any(|(label, value)| {
                label.as_integer().map(i128::from) == Some(33)
                    && value
                        .as_bytes()
                        .is_some_and(|bytes| bytes.as_slice() == LEAF_CERTIFICATE_DER)
            })
    );
    let verified = validate_x5chain_issuer_auth(
        &document.issuer_signed.issuer_auth,
        |presented_certificates| {
            (presented_certificates == certificates.as_slice())
                .then(|| issuer_public_key.clone())
        },
    )
    .unwrap();
    assert_eq!(verified.x5chain_der, certificates);
    let verified_receipt = verify_issuer_signed_mdoc_receipt_with_x5chain(
        &document,
        |presented_certificates| {
            (presented_certificates == certificates.as_slice())
                .then(|| issuer_public_key.clone())
        },
        1_750_000_000,
    )
    .unwrap();
    assert_eq!(verified_receipt.doc_type, "eu.europa.ec.eudi.pid.1");
    assert_eq!(
        verify_issuer_signed_mdoc_receipt_with_x5chain(
            &document,
            |presented_certificates| {
                (presented_certificates == certificates.as_slice())
                    .then(|| issuer_public_key.clone())
            },
            1_800_000_000,
        )
        .err(),
        Some(MdocEnvelopeError::Expired)
    );
}

#[test]
fn x5chain_issuer_signer_rejects_an_empty_certificate_path() {
    let (_, issuer_private_key) = generate_keypair(Algorithm::P256).unwrap();
    let signer = CoseX5ChainIssuerAuthSigner {
        algorithm: CoseSignatureAlgorithm::Es256,
        private_key: &issuer_private_key,
        kid: None,
        x5chain_der: &[],
    };

    assert_eq!(
        build_mso_mdoc(&valid_config(), &sample_elements(), &signer).err(),
        Some(MdocEnvelopeError::Signing),
    );
}

#[test]
fn issues_and_verifies_issuer_signed_mdoc() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };

    let (document, mobile_security_object) =
        build_mso_mdoc(&valid_config(), &sample_elements(), &signer).unwrap();
    let verified =
        verify_issuer_signed_mdoc(
            &document,
            resolver_for_kid(kid, issuer_public_key),
            1_700_000_001,
        )
        .unwrap();

    assert_eq!(document.doc_type, "org.iso.18013.5.1.mDL");
    assert_eq!(verified.doc_type, document.doc_type);
    assert_eq!(
        verified.mobile_security_object.doc_type,
        mobile_security_object.doc_type
    );
    assert!(verified.namespaces.is_some());
    assert_eq!(
        mobile_security_object
            .value_digests
            .get("org.iso.18013.5.1")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn issuance_is_deterministic_for_ordered_content() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let mut reversed = sample_elements();
    reversed.reverse();

    let (first_document, first_mso) =
        build_mso_mdoc(&valid_config(), &sample_elements(), &signer).unwrap();
    let (second_document, second_mso) =
        build_mso_mdoc(&valid_config(), &reversed, &signer).unwrap();

    verify_issuer_signed_mdoc(
        &first_document,
        resolver_for_kid(kid.clone(), issuer_public_key),
        1_700_000_001,
    )
    .unwrap();
    assert_eq!(first_mso.value_digests, second_mso.value_digests);
    assert!(first_document.issuer_signed.name_spaces == second_document.issuer_signed.name_spaces);
}

#[test]
fn verification_rejects_tampered_issuer_signed_item() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let (mut document, _) = build_mso_mdoc(&valid_config(), &sample_elements(), &signer).unwrap();
    let items = document
        .issuer_signed
        .name_spaces
        .as_mut()
        .unwrap()
        .get_mut("org.iso.18013.5.1")
        .unwrap();
    items[0].bstr[0] ^= 0xff;

    let err = match verify_issuer_signed_mdoc(
        &document,
        resolver_for_kid(kid, issuer_public_key),
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(err, MdocEnvelopeError::InvalidDigest);
}

#[test]
fn verification_rejects_wrong_issuer_namespace() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let (mut document, _) = build_mso_mdoc(&valid_config(), &sample_elements(), &signer).unwrap();
    let namespaces = document.issuer_signed.name_spaces.as_mut().unwrap();
    let items = namespaces.remove("org.iso.18013.5.1").unwrap();
    namespaces.insert("org.iso.18013.5.1.wrong".to_owned(), items);

    let err = match verify_issuer_signed_mdoc(
        &document,
        resolver_for_kid(kid, issuer_public_key),
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(err, MdocEnvelopeError::InvalidDigest);
}

#[test]
fn verification_rejects_wrong_issuer_key() {
    let (_issuer_public_key, issuer_private_key) = issuer_keys();
    let (wrong_public_key, _) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let (document, _) = build_mso_mdoc(&valid_config(), &sample_elements(), &signer).unwrap();

    let err = match verify_issuer_signed_mdoc(
        &document,
        resolver_for_kid(kid, wrong_public_key),
        1_700_000_001,
    ) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(err, MdocEnvelopeError::InvalidSignature);
}

#[test]
fn issuance_rejects_invalid_validity_window() {
    let (_issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let (device_public_key, _) = issuer_keys();
    let cfg = MdocIssueConfig::new(
        "org.iso.18013.5.1.mDL",
        ValidityInfo {
            signed: 10,
            valid_from: 20,
            valid_until: 19,
        },
        device_cose_key(&device_public_key),
    );

    let err = match build_mso_mdoc(&cfg, &sample_elements(), &signer) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidValidityWindow)
    );
}

#[test]
fn issuance_rejects_too_many_elements() {
    let (_issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let elements = (0..=MAX_MDOC_ISSUER_ELEMENTS)
        .map(|index| {
            element_for_namespace("org.iso.18013.5.1".to_owned(), format!("element_{index}"))
        })
        .collect::<Vec<_>>();

    let err = match build_mso_mdoc(&valid_config(), &elements, &signer) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::TooManyElements)
    );
}

#[test]
fn issuance_rejects_too_many_namespaces() {
    let (_issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let elements = (0..=MAX_MDOC_NAMESPACES)
        .map(|index| {
            element_for_namespace(
                format!("org.iso.18013.5.1.ns.{index}"),
                "family_name".to_owned(),
            )
        })
        .collect::<Vec<_>>();

    let err = match build_mso_mdoc(&valid_config(), &elements, &signer) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::TooManyNamespaces)
    );
}

#[test]
fn issuance_rejects_too_many_elements_per_namespace() {
    let (_issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let elements = (0..=MAX_MDOC_ELEMENTS_PER_NAMESPACE)
        .map(|index| {
            element_for_namespace("org.iso.18013.5.1".to_owned(), format!("element_{index}"))
        })
        .collect::<Vec<_>>();

    let err = match build_mso_mdoc(&valid_config(), &elements, &signer) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::TooManyElementsPerNamespace)
    );
}

#[test]
fn issuance_rejects_conflicting_duplicate_element_identifier() {
    let (_issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let mut elements = sample_elements();
    let mut conflicting = elements[0].clone();
    conflicting.element_value_cbor = vec![0x65, b'S', b'm', b'i', b't', b'h'];
    elements.push(conflicting);

    let err = match build_mso_mdoc(&valid_config(), &elements, &signer) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::DuplicateElementIdentifier)
    );
}

#[test]
fn device_response_decoder_rejects_oversized_serialized_cbor_before_parsing() {
    let oversized = vec![0_u8; MAX_MDOC_CBOR_INPUT_BYTES + 1];

    let err = match decode_mdoc_device_response_cbor(&oversized) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };

    assert_eq!(
        err,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::CborInputTooLarge)
    );
}

#[test]
fn issuance_rejects_oversized_single_and_aggregate_element_values() {
    let (_issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-1".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let mut single = element_for_namespace("org.iso.18013.5.1".to_owned(), "portrait".to_owned());
    single.element_value_cbor = vec![0_u8; MAX_MDOC_ELEMENT_VALUE_BYTES + 1];
    let single_error = match build_mso_mdoc(&valid_config(), &[single], &signer) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };
    assert_eq!(
        single_error,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::ElementValueTooLarge)
    );

    let per_element = MAX_MDOC_TOTAL_ELEMENT_VALUE_BYTES / 2;
    let aggregate = (0..3)
        .map(|index| {
            let mut element =
                element_for_namespace("org.iso.18013.5.1".to_owned(), format!("large_{index}"));
            element.element_value_cbor = vec![0_u8; per_element];
            element
        })
        .collect::<Vec<_>>();
    let aggregate_error = match build_mso_mdoc(&valid_config(), &aggregate, &signer) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(err) => err,
    };
    assert_eq!(
        aggregate_error,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::TotalElementValuesTooLarge)
    );
}

#[test]
fn iso23220_relationship_accepts_clause_cddl_shape() {
    let encoded = ciborium_bytes(&CiboriumValue::Array(vec![CiboriumValue::Map(vec![
        (
            CiboriumValue::Text("family_name".to_owned()),
            CiboriumValue::Text("Example".to_owned()),
        ),
        (
            CiboriumValue::Text("birth_date".to_owned()),
            CiboriumValue::Map(vec![(
                CiboriumValue::Text("birth_date".to_owned()),
                CiboriumValue::Text("2000-01-01".to_owned()),
            )]),
        ),
    ])]));

    let value = parse_iso23220_relationship_value(&encoded).unwrap();
    assert_eq!(value.relationship_count(), 1);
    let element = iso23220_relationship_element(
        Iso23220RelationshipKind::LegalRepresentative,
        value,
        vec![7_u8; 16],
    )
    .unwrap();

    assert_eq!(element.namespace, ISO_23220_NAMESPACE);
    assert_eq!(element.element_identifier, "legal_representative");
    assert_eq!(element.element_value_cbor, encoded);
}

#[test]
fn iso23220_relationship_accepts_empty_personal_data_map() {
    let encoded = ciborium_bytes(&CiboriumValue::Array(vec![CiboriumValue::Map(vec![])]));

    let value = parse_iso23220_relationship_value(&encoded).unwrap();

    assert_eq!(value.relationship_count(), 1);
    assert_eq!(value.as_cbor(), encoded);
}

#[test]
fn iso23220_relationship_rejects_table_text_array_shape() {
    let encoded = ciborium_bytes(&CiboriumValue::Array(vec![CiboriumValue::Text(
        "family_name".to_owned(),
    )]));

    let error = match parse_iso23220_relationship_value(&encoded) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(error) => error,
    };

    assert_eq!(
        error,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedIso23220Relationship)
    );
}

#[test]
fn iso23220_relationship_rejects_duplicate_personal_data_identifier() {
    let encoded = ciborium_bytes(&CiboriumValue::Array(vec![CiboriumValue::Map(vec![
        (
            CiboriumValue::Text("family_name".to_owned()),
            CiboriumValue::Text("First".to_owned()),
        ),
        (
            CiboriumValue::Text("family_name".to_owned()),
            CiboriumValue::Text("Second".to_owned()),
        ),
    ])]));

    let error = match parse_iso23220_relationship_value(&encoded) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(error) => error,
    };

    assert_eq!(
        error,
        MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::DuplicateIso23220PersonalDataIdentifier
        )
    );
}
