// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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

    let per_element = MAX_MDOC_ELEMENT_VALUE_BYTES;
    let aggregate = (0..5)
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
