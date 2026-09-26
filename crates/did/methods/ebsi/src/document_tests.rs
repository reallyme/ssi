// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{parse_and_validate_did_ebsi_document, DidEbsiDocumentLimits, DidEbsiErrorReason};

const DID: &str = "did:ebsi:zub5ZZUfHLLptCduwEy8xRj";
const COORDINATE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn document(did: &str, relationship: &str, private_member: &str, curve: &str) -> Vec<u8> {
    format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{did}","controller":["{did}"],"verificationMethod":[{{"id":"{did}#key-1","type":"JsonWebKey2020","controller":"{did}","publicKeyJwk":{{"kty":"EC","crv":"{curve}","alg":"ES256","use":"sig","key_ops":["verify"],"x":"{COORDINATE}","y":"{COORDINATE}"{private_member}}}}}],"assertionMethod":["{relationship}"],"capabilityInvocation":["{did}#key-1"]}}"#
    )
    .into_bytes()
}

#[test]
fn validates_a_bounded_legal_entity_document() {
    let bytes = document(DID, &format!("{DID}#key-1"), "", "P-256");
    let parsed =
        parse_and_validate_did_ebsi_document(DID, &bytes, DidEbsiDocumentLimits::default());
    assert!(parsed.is_ok());
}

#[test]
fn rejects_wrong_identifier_private_jwk_and_unresolved_relationship() {
    let cases = [
        document(
            "did:ebsi:ztRBFfMCY7VAGHH1Ba8Q5o9",
            &format!("{DID}#key-1"),
            "",
            "P-256",
        ),
        document(DID, &format!("{DID}#key-1"), r#", "d":"secret""#, "P-256"),
        document(DID, &format!("{DID}#missing"), "", "P-256"),
        document(DID, &format!("{DID}#key-1"), "", "secp256k1"),
    ];
    for bytes in cases {
        let error =
            parse_and_validate_did_ebsi_document(DID, &bytes, DidEbsiDocumentLimits::default())
                .err()
                .map(|value| value.reason);
        assert!(matches!(
            error,
            Some(
                DidEbsiErrorReason::InvalidDocument
                    | DidEbsiErrorReason::DocumentIdentifierMismatch
                    | DidEbsiErrorReason::UnsupportedAlgorithm
            )
        ));
    }
}

#[test]
fn rejects_missing_invocation_authority_and_inconsistent_jwk_policy() {
    let missing_invocation = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","x":"{COORDINATE}","y":"{COORDINATE}"}}}}],"assertionMethod":["{DID}#key-1"]}}"#
    );
    let invalid_usage = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","use":"enc","key_ops":["sign"],"x":"{COORDINATE}","y":"{COORDINATE}"}}}}],"capabilityInvocation":["{DID}#key-1"]}}"#
    );
    let reasons = [missing_invocation, invalid_usage].map(|document| {
        parse_and_validate_did_ebsi_document(
            DID,
            document.as_bytes(),
            DidEbsiDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason)
    });
    assert_eq!(
        reasons,
        [
            Some(DidEbsiErrorReason::CapabilityInvocationMissing),
            Some(DidEbsiErrorReason::InvalidKeyUsage),
        ]
    );
}

#[test]
fn rejects_oversized_and_excessively_nested_registry_documents() {
    let oversized = vec![b' '; 65];
    let limits = DidEbsiDocumentLimits {
        max_bytes: 64,
        ..DidEbsiDocumentLimits::default()
    };
    let oversized_error = parse_and_validate_did_ebsi_document(DID, &oversized, limits)
        .err()
        .map(|value| value.reason);
    assert_eq!(
        oversized_error,
        Some(DidEbsiErrorReason::DocumentLimitExceeded)
    );

    let nested = br#"[[[[[[[[[]]]]]]]]]"#;
    let limits = DidEbsiDocumentLimits {
        max_depth: 4,
        ..DidEbsiDocumentLimits::default()
    };
    let nested_error = parse_and_validate_did_ebsi_document(DID, nested, limits)
        .err()
        .map(|value| value.reason);
    assert_eq!(
        nested_error,
        Some(DidEbsiErrorReason::DocumentLimitExceeded)
    );
}

#[test]
fn rejects_duplicate_registry_document_members() {
    let bytes = document(DID, &format!("{DID}#key-1"), r#", "x":"AA""#, "P-256");
    assert_eq!(
        parse_and_validate_did_ebsi_document(DID, &bytes, DidEbsiDocumentLimits::default())
            .err()
            .map(|error| error.reason),
        Some(DidEbsiErrorReason::InvalidDocument)
    );
}
