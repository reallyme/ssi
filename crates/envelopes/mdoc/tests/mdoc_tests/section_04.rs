// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn issuer_signed_transport_decodes_and_verifies_through_canonical_path() {
    let (issuer_public_key, issuer_private_key) = issuer_keys();
    let kid = b"issuer-kid-receipt".to_vec();
    let signer = CoseIssuerAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: issuer_private_key.as_slice(),
        kid: Some(kid.as_slice()),
    };
    let (issued, _) = build_mso_mdoc(&valid_config(), &sample_elements(), &signer).unwrap();
    let encoded = encode_mdoc_issuer_signed_cbor(&issued).unwrap();

    let decoded =
        decode_mdoc_issuer_signed_cbor(&encoded, "org.iso.18013.5.1.mDL").unwrap();
    let verified = verify_issuer_signed_mdoc(
        &decoded,
        resolver_for_kid(kid, issuer_public_key),
        1_700_000_001,
    )
    .unwrap();

    assert!(decoded == issued);
    assert_eq!(verified.doc_type, "org.iso.18013.5.1.mDL");
}

#[test]
fn issuer_signed_transport_rejects_malformed_oversized_and_deep_cbor() {
    let malformed = decode_mdoc_issuer_signed_cbor(&[0xff], "org.iso.18013.5.1.mDL");
    assert!(matches!(malformed, Err(MdocEnvelopeError::Cbor)));

    let oversized = vec![0_u8; MAX_MDOC_CBOR_INPUT_BYTES + 1];
    assert_eq!(
        decode_mdoc_issuer_signed_cbor(&oversized, "org.iso.18013.5.1.mDL").err(),
        Some(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::CborInputTooLarge
        ))
    );

    let mut deep = CiboriumValue::Null;
    for _ in 0..=MAX_MDOC_CBOR_DEPTH {
        deep = CiboriumValue::Array(vec![deep]);
    }
    assert_eq!(
        decode_mdoc_issuer_signed_cbor(
            &ciborium_bytes(&deep),
            "org.iso.18013.5.1.mDL"
        )
        .err(),
        Some(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::CborDepthExceeded
        ))
    );
}

#[test]
fn issuer_signed_transport_rejects_duplicate_top_level_and_namespace_members() {
    let cose = CiboriumValue::Array(vec![
        CiboriumValue::Bytes(Vec::new()),
        CiboriumValue::Map(Vec::new()),
        CiboriumValue::Null,
        CiboriumValue::Bytes(vec![0_u8; 64]),
    ]);
    let duplicate_top_level = CiboriumValue::Map(vec![
        (
            CiboriumValue::Text("issuerAuth".to_owned()),
            cose.clone(),
        ),
        (CiboriumValue::Text("issuerAuth".to_owned()), cose.clone()),
    ]);
    assert_eq!(
        decode_mdoc_issuer_signed_cbor(
            &ciborium_bytes(&duplicate_top_level),
            "org.iso.18013.5.1.mDL"
        )
        .err(),
        Some(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedIssuerSignedDocument
        ))
    );

    let duplicate_namespace = CiboriumValue::Map(vec![
        (
            CiboriumValue::Text("nameSpaces".to_owned()),
            CiboriumValue::Map(vec![
                (
                    CiboriumValue::Text("org.iso.18013.5.1".to_owned()),
                    CiboriumValue::Array(Vec::new()),
                ),
                (
                    CiboriumValue::Text("org.iso.18013.5.1".to_owned()),
                    CiboriumValue::Array(Vec::new()),
                ),
            ]),
        ),
        (CiboriumValue::Text("issuerAuth".to_owned()), cose),
    ]);
    assert_eq!(
        decode_mdoc_issuer_signed_cbor(
            &ciborium_bytes(&duplicate_namespace),
            "org.iso.18013.5.1.mDL"
        )
        .err(),
        Some(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedIssuerSignedDocument
        ))
    );
}

#[test]
fn issuer_signed_transport_rejects_malformed_namespace_item_tag_and_cose_body() {
    let malformed_item = CiboriumValue::Map(vec![
        (
            CiboriumValue::Text("nameSpaces".to_owned()),
            CiboriumValue::Map(vec![(
                CiboriumValue::Text("org.iso.18013.5.1".to_owned()),
                CiboriumValue::Array(vec![CiboriumValue::Tag(
                    23,
                    Box::new(CiboriumValue::Bytes(Vec::new())),
                )]),
            )]),
        ),
        (
            CiboriumValue::Text("issuerAuth".to_owned()),
            CiboriumValue::Array(vec![
                CiboriumValue::Bytes(Vec::new()),
                CiboriumValue::Map(Vec::new()),
                CiboriumValue::Null,
                CiboriumValue::Bytes(vec![0_u8; 64]),
            ]),
        ),
    ]);
    assert_eq!(
        decode_mdoc_issuer_signed_cbor(
            &ciborium_bytes(&malformed_item),
            "org.iso.18013.5.1.mDL"
        )
        .err(),
        Some(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedIssuerSignedDocument
        ))
    );

    let malformed_cose = CiboriumValue::Map(vec![(
        CiboriumValue::Text("issuerAuth".to_owned()),
        CiboriumValue::Array(vec![CiboriumValue::Null; 3]),
    )]);
    assert_eq!(
        decode_mdoc_issuer_signed_cbor(
            &ciborium_bytes(&malformed_cose),
            "org.iso.18013.5.1.mDL"
        )
        .err(),
        Some(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedIssuerSignedDocument
        ))
    );
}
