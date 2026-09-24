// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public-boundary conformance tests for the legal-entity did:ebsi profile.

use reallyme_did_method_ebsi::{
    create_did_ebsi_document, generate_did_ebsi, parse_and_validate_did_ebsi_document,
    parse_did_ebsi, DidEbsiDocumentLimits, DidEbsiErrorReason, EbsiDidVersion, EBSI_V1_PAYLOAD_LEN,
};

const DID: &str = "did:ebsi:zub5ZZUfHLLptCduwEy8xRj";
const COORDINATE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn document(did: &str, relationship: &str, private_member: &str) -> Vec<u8> {
    format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{did}","controller":["{did}"],"verificationMethod":[{{"id":"{did}#key-1","type":"JsonWebKey2020","controller":"{did}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","key_ops":["verify"],"x":"{COORDINATE}","y":"{COORDINATE}"{private_member}}}}}],"assertionMethod":["{relationship}"],"capabilityInvocation":["{did}#key-1"]}}"#
    )
    .into_bytes()
}

#[test]
fn identifier_profile_vectors_round_trip_byte_exact() -> Result<(), Box<dyn std::error::Error>> {
    let payload = [0x11u8; EBSI_V1_PAYLOAD_LEN];
    let generated = generate_did_ebsi(EbsiDidVersion::LegalEntity, &payload)?;
    let parsed = parse_did_ebsi(&generated)?;

    assert_eq!(parsed.version, EbsiDidVersion::LegalEntity);
    assert_eq!(parsed.payload, payload);
    assert_eq!(
        generate_did_ebsi(parsed.version, &parsed.payload)?,
        generated
    );
    for published in [DID, "did:ebsi:ztRBFfMCY7VAGHH1Ba8Q5o9"] {
        let parsed = parse_did_ebsi(published)?;
        assert_eq!(parsed.version, EbsiDidVersion::LegalEntity);
        assert_eq!(
            generate_did_ebsi(parsed.version, &parsed.payload)?,
            published
        );
    }
    Ok(())
}

#[test]
fn identifier_profile_rejects_noncanonical_personal_and_oversized_values() {
    let cases = [
        (
            "did:ebsi:z1ub5ZZUfHLLptCduwEy8xRj",
            DidEbsiErrorReason::NonCanonicalEncoding,
        ),
        (
            "did:ebsi:z1111111111111111111111111",
            DidEbsiErrorReason::IdentifierTooLong,
        ),
        ("did:ebsi:z0OIl", DidEbsiErrorReason::InvalidBase58),
    ];
    for (did, expected) in cases {
        assert_eq!(
            parse_did_ebsi(did).err().map(|error| error.reason),
            Some(expected)
        );
    }

    assert_eq!(
        parse_did_ebsi("did:ebsi:zbTdjzaWCb6UY9AZqTMMbPSc3VzHeVR9By6ueiqrY2uVZ")
            .err()
            .map(|error| error.reason),
        Some(DidEbsiErrorReason::IdentifierTooLong)
    );
}

#[test]
fn document_profile_accepts_canonical_legal_entity_document() {
    let bytes = document(DID, &format!("{DID}#key-1"), "");
    let parsed =
        parse_and_validate_did_ebsi_document(DID, &bytes, DidEbsiDocumentLimits::default());
    assert!(parsed.is_ok());
}

#[test]
fn document_profile_creation_preserves_canonical_bytes() {
    let bytes = document(DID, &format!("{DID}#key-1"), "");
    let created = create_did_ebsi_document(DID, &bytes, DidEbsiDocumentLimits::default());
    assert_eq!(
        created.as_ref().map(|document| document.as_bytes()),
        Ok(bytes.as_slice())
    );
}

#[test]
fn document_profile_rejects_mismatch_private_dangling_and_limits() {
    let invalid = [
        document(
            "did:ebsi:ztRBFfMCY7VAGHH1Ba8Q5o9",
            &format!("{DID}#key-1"),
            "",
        ),
        document(DID, &format!("{DID}#key-1"), r#", "d":"secret""#),
        document(DID, &format!("{DID}#missing"), ""),
    ];
    for bytes in invalid {
        let reason =
            parse_and_validate_did_ebsi_document(DID, &bytes, DidEbsiDocumentLimits::default())
                .err()
                .map(|error| error.reason);
        assert!(matches!(
            reason,
            Some(
                DidEbsiErrorReason::InvalidDocument
                    | DidEbsiErrorReason::DocumentIdentifierMismatch
            )
        ));
    }

    let limits = DidEbsiDocumentLimits {
        max_bytes: 64,
        max_depth: 4,
        ..DidEbsiDocumentLimits::default()
    };
    assert_eq!(
        parse_and_validate_did_ebsi_document(DID, &[b' '; 65], limits)
            .err()
            .map(|error| error.reason),
        Some(DidEbsiErrorReason::DocumentLimitExceeded)
    );
    assert_eq!(
        parse_and_validate_did_ebsi_document(DID, br#"[[[[[[[[[]]]]]]]]]"#, limits)
            .err()
            .map(|error| error.reason),
        Some(DidEbsiErrorReason::DocumentLimitExceeded)
    );
}
