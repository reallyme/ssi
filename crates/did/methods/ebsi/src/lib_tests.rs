// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    generate_did_ebsi, parse_did_ebsi, DidEbsiErrorReason, EbsiDidVersion, EBSI_V1_PAYLOAD_LEN,
};

#[test]
fn generated_legal_entity_did_ebsi_round_trips_versioned_payload(
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = [0x11u8; EBSI_V1_PAYLOAD_LEN];
    let did = generate_did_ebsi(EbsiDidVersion::LegalEntity, &payload)?;

    assert!(did.starts_with("did:ebsi:z"));
    let parsed = parse_did_ebsi(&did)?;
    assert_eq!(parsed.version, EbsiDidVersion::LegalEntity);
    assert_eq!(parsed.payload, payload);
    Ok(())
}

#[test]
fn published_ebsi_resolver_examples_decode_as_legal_entity(
) -> Result<(), Box<dyn std::error::Error>> {
    let examples = [
        "did:ebsi:zub5ZZUfHLLptCduwEy8xRj",
        "did:ebsi:ztRBFfMCY7VAGHH1Ba8Q5o9",
    ];

    for did in examples {
        let parsed = parse_did_ebsi(did)?;
        assert_eq!(parsed.version, EbsiDidVersion::LegalEntity);
        assert_eq!(parsed.payload.len(), EBSI_V1_PAYLOAD_LEN);
        assert_eq!(generate_did_ebsi(parsed.version, &parsed.payload)?, did);
    }
    Ok(())
}

#[test]
fn did_ebsi_rejects_non_base58_identifier() {
    let err = parse_did_ebsi("did:ebsi:z0OIl")
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidEbsiErrorReason::InvalidBase58));
}

#[test]
fn did_ebsi_rejects_missing_multibase_prefix() {
    let err = parse_did_ebsi("did:ebsi:ub5ZZUfHLLptCduwEy8xRj")
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidEbsiErrorReason::MissingMultibasePrefix));
}

#[test]
fn did_ebsi_rejects_wrong_payload_length_for_version() {
    let err = generate_did_ebsi(EbsiDidVersion::LegalEntity, &[0x11u8; 15])
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidEbsiErrorReason::InvalidPayloadLength));
}

#[test]
fn did_ebsi_rejects_noncanonical_and_oversized_method_identifiers_before_adoption() {
    let cases = [
        (
            "did:ebsi:z1ub5ZZUfHLLptCduwEy8xRj",
            DidEbsiErrorReason::NonCanonicalEncoding,
        ),
        (
            "did:ebsi:z1111111111111111111111111",
            DidEbsiErrorReason::IdentifierTooLong,
        ),
    ];
    for (did, expected) in cases {
        assert_eq!(
            parse_did_ebsi(did).err().map(|error| error.reason),
            Some(expected)
        );
    }
}
