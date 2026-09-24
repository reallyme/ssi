// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn replace_authenticated_validity(
    document: &mut reallyme_mdoc::MdocIssuerSignedDocument,
    validity: ValidityInfo,
    signer: &dyn reallyme_mdoc::IssuerAuthSigner,
) {
    let issuer_auth = ciborium_value(&document.issuer_signed.issuer_auth);
    let payload = issuer_auth
        .as_array()
        .and_then(|fields| fields.get(2))
        .and_then(CiboriumValue::as_bytes)
        .unwrap();
    let mut tagged_mso = ciborium_value(payload);
    let encoded_mso = match &mut tagged_mso {
        CiboriumValue::Tag(24, value) => value.as_bytes_mut(),
        _ => None,
    }
    .unwrap();
    let mut mso = ciborium_value(encoded_mso);
    let mso_entries = mso.as_map_mut().unwrap();
    let validity_info = text_map_value_mut(mso_entries, "validityInfo")
        .as_map_mut()
        .unwrap();
    replace_tdate(validity_info, "signed", validity.signed);
    replace_tdate(validity_info, "validFrom", validity.valid_from);
    replace_tdate(validity_info, "validUntil", validity.valid_until);
    *encoded_mso = ciborium_bytes(&mso);

    document.issuer_signed.issuer_auth = signer.sign_issuer_auth(&ciborium_bytes(&tagged_mso)).unwrap();
}

fn replace_tdate(entries: &mut [(CiboriumValue, CiboriumValue)], key: &str, unix_seconds: u64) {
    let unix_seconds = i64::try_from(unix_seconds).unwrap();
    let timestamp = time::OffsetDateTime::from_unix_timestamp(unix_seconds)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    *text_map_value_mut(entries, key) =
        CiboriumValue::Tag(0, Box::new(CiboriumValue::Text(timestamp)));
}

fn malformed_validity_windows() -> [ValidityInfo; 6] {
    [
        ValidityInfo {
            signed: 1_750_000_000,
            valid_from: 1_700_000_000,
            valid_until: 1_800_000_000,
        },
        ValidityInfo {
            signed: 0,
            valid_from: 1_700_000_000,
            valid_until: 1_800_000_000,
        },
        ValidityInfo {
            signed: 1_700_000_000,
            valid_from: 0,
            valid_until: 1_800_000_000,
        },
        ValidityInfo {
            signed: 1_700_000_000,
            valid_from: 1_700_000_000,
            valid_until: 0,
        },
        ValidityInfo {
            signed: 1_700_000_000,
            valid_from: 1_800_000_000,
            valid_until: 1_700_000_000,
        },
        ValidityInfo {
            signed: 1_700_000_000,
            valid_from: 1_750_000_000,
            valid_until: 1_750_000_000,
        },
    ]
}

#[test]
fn issuance_receipt_rejects_authenticated_malformed_validity_windows() {
    const LEAF_CERTIFICATE_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];

    for validity in malformed_validity_windows() {
        let (issuer_public_key, issuer_private_key) = generate_keypair(Algorithm::P256).unwrap();
        let certificates = vec![LEAF_CERTIFICATE_DER.to_vec()];
        let signer = CoseX5ChainIssuerAuthSigner {
            algorithm: CoseSignatureAlgorithm::Es256,
            private_key: &issuer_private_key,
            kid: None,
            x5chain_der: &certificates,
        };
        let mut document =
            build_mso_mdoc(&valid_config(), &sample_elements(), &signer).unwrap().0;
        replace_authenticated_validity(&mut document, validity, &signer);

        let error = verify_issuer_signed_mdoc_receipt_with_x5chain(
            &document,
            |presented_path| {
                (presented_path == certificates.as_slice()).then(|| issuer_public_key.clone())
            },
            1_750_000_000,
        )
        .err();

        assert_eq!(
            error,
            Some(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::InvalidValidityWindow
            ))
        );
    }
}

#[test]
fn device_response_rejects_authenticated_malformed_validity_windows() {
    for validity in malformed_validity_windows() {
        let (issuer_public_key, issuer_private_key) = issuer_keys();
        let (device_public_key, device_private_key) = issuer_keys();
        let kid = b"issuer-kid-invalid-validity".to_vec();
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
        let mut document = build_mso_mdoc(
            &valid_config_for_device_key(&device_public_key),
            &sample_elements(),
            &issuer_signer,
        )
        .unwrap()
        .0;
        replace_authenticated_validity(&mut document, validity, &issuer_signer);
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

        let error = verify_mdoc_device_response(
            &response,
            resolver_for_kid(kid, issuer_public_key),
            &session_transcript,
            1_700_000_001,
        )
        .err();

        assert_eq!(
            error,
            Some(MdocEnvelopeError::InvalidInput(
                MdocInvalidInputReason::InvalidValidityWindow
            ))
        );
    }
}
