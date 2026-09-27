// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    parse_and_validate_did_ebsi_document, parse_and_validate_did_ebsi_document_for_state,
    DidEbsiDocumentLimits, DidEbsiDocumentState, DidEbsiErrorReason,
};

const DID: &str = "did:ebsi:zub5ZZUfHLLptCduwEy8xRj";
const P256_X: &str = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY";
const P256_Y: &str = "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU";
const SECP256K1_X: &str = "eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g";
const SECP256K1_Y: &str = "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg";

fn document(did: &str, relationship: &str, private_member: &str, curve: &str) -> Vec<u8> {
    format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{did}","controller":["{did}"],"verificationMethod":[{{"id":"{did}#key-1","type":"JsonWebKey2020","controller":"{did}","publicKeyJwk":{{"kty":"EC","crv":"{curve}","alg":"ES256","use":"sig","key_ops":["verify"],"x":"{P256_X}","y":"{P256_Y}"{private_member}}}}}],"assertionMethod":["{relationship}"],"capabilityInvocation":["{did}#key-1"]}}"#
    )
    .into_bytes()
}

#[test]
fn validates_a_bounded_legal_entity_document() {
    let bytes = document(DID, &format!("{DID}#key-1"), "", "P-256");
    let parsed =
        parse_and_validate_did_ebsi_document(DID, &bytes, DidEbsiDocumentLimits::default());
    assert!(parsed.is_ok());

    let with_bound_key_id = document(DID, &format!("{DID}#key-1"), r#", "kid":"key-1""#, "P-256");
    assert!(parse_and_validate_did_ebsi_document(
        DID,
        &with_bound_key_id,
        DidEbsiDocumentLimits::default(),
    )
    .is_ok());
}

#[test]
fn rejects_noncanonical_percent_encoding_in_did_urls() -> Result<(), Box<dyn std::error::Error>> {
    for encoded_identifier in ["k%65y-1", "key%3a1"] {
        let valid = document(DID, &format!("{DID}#key-1"), "", "P-256");
        let encoded = String::from_utf8(valid)?.replace("key-1", encoded_identifier);
        assert_eq!(
            parse_and_validate_did_ebsi_document(
                DID,
                encoded.as_bytes(),
                DidEbsiDocumentLimits::default(),
            )
            .err()
            .map(|error| error.reason),
            Some(DidEbsiErrorReason::InvalidDidUrl)
        );
    }
    Ok(())
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
fn accepts_es256k_invocation_authority_from_the_registry_profile() {
    let document = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"secp256k1","alg":"ES256K","use":"sig","key_ops":["verify"],"x":"{SECP256K1_X}","y":"{SECP256K1_Y}"}}}}],"capabilityInvocation":["{DID}#key-1"]}}"#
    );
    assert!(parse_and_validate_did_ebsi_document(
        DID,
        document.as_bytes(),
        DidEbsiDocumentLimits::default(),
    )
    .is_ok());

    let registry_document_without_optional_alg = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"secp256k1","x":"{SECP256K1_X}","y":"{SECP256K1_Y}"}}}}],"capabilityInvocation":["{DID}#key-1"]}}"#
    );
    assert!(parse_and_validate_did_ebsi_document(
        DID,
        registry_document_without_optional_alg.as_bytes(),
        DidEbsiDocumentLimits::default(),
    )
    .is_ok());
}

#[test]
fn accepts_es256k_signature_relationships_present_in_ebsi_registry_documents() {
    let document = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"secp256k1","alg":"ES256K","use":"sig","key_ops":["verify"],"x":"{SECP256K1_X}","y":"{SECP256K1_Y}"}}}}],"authentication":["{DID}#key-1"],"assertionMethod":["{DID}#key-1"],"capabilityInvocation":["{DID}#key-1"]}}"#
    );

    assert!(parse_and_validate_did_ebsi_document(
        DID,
        document.as_bytes(),
        DidEbsiDocumentLimits::default(),
    )
    .is_ok());
}

#[test]
fn rejects_active_document_without_local_invocation_and_inconsistent_jwk_policy() {
    let missing_invocation = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","x":"{P256_X}","y":"{P256_Y}"}}}}],"assertionMethod":["{DID}#key-1"]}}"#
    );
    let invalid_usage = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","use":"enc","key_ops":["sign"],"x":"{P256_X}","y":"{P256_Y}"}}}}],"capabilityInvocation":["{DID}#key-1"]}}"#
    );
    assert_eq!(
        parse_and_validate_did_ebsi_document(
            DID,
            missing_invocation.as_bytes(),
            DidEbsiDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
        Some(DidEbsiErrorReason::InvalidDocument)
    );
    assert_eq!(
        parse_and_validate_did_ebsi_document(
            DID,
            invalid_usage.as_bytes(),
            DidEbsiDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
        Some(DidEbsiErrorReason::InvalidKeyUsage)
    );
}

#[test]
fn accepts_did_core_also_known_as() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = document(DID, &format!("{DID}#key-1"), "", "P-256");
    let text = String::from_utf8(bytes)?;
    let extended = text.replacen(
        &format!(r#""id":"{DID}","#),
        &format!(r#""id":"{DID}","alsoKnownAs":["https://example.com/identities/123"],"#),
        1,
    );
    assert!(parse_and_validate_did_ebsi_document(
        DID,
        extended.as_bytes(),
        DidEbsiDocumentLimits::default(),
    )
    .is_ok());
    Ok(())
}

#[test]
fn accepts_services_on_explicitly_historical_immutable_documents(
) -> Result<(), Box<dyn std::error::Error>> {
    let service_document = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","service":[{{"id":"{DID}#registry","type":["LinkedDomains","Registry"],"serviceEndpoint":["https://legal-entity.example",{{"uri":"https://backup.example"}}]}}]}}"#
    );
    parse_and_validate_did_ebsi_document_for_state(
        DID,
        service_document.as_bytes(),
        DidEbsiDocumentLimits::default(),
        DidEbsiDocumentState::EffectivelyDeactivated,
    )?;

    let immutable = format!(r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}"}}"#);
    parse_and_validate_did_ebsi_document_for_state(
        DID,
        immutable.as_bytes(),
        DidEbsiDocumentLimits::default(),
        DidEbsiDocumentState::EffectivelyDeactivated,
    )?;

    let immutable_with_assertion_key = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","x":"{P256_X}","y":"{P256_Y}"}}}}],"assertionMethod":["{DID}#key-1"]}}"#
    );
    parse_and_validate_did_ebsi_document_for_state(
        DID,
        immutable_with_assertion_key.as_bytes(),
        DidEbsiDocumentLimits::default(),
        DidEbsiDocumentState::EffectivelyDeactivated,
    )?;
    Ok(())
}

#[test]
fn active_document_requires_a_controller() {
    let document = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","verificationMethod":[]}}"#
    );

    assert_eq!(
        parse_and_validate_did_ebsi_document(
            DID,
            document.as_bytes(),
            DidEbsiDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
        Some(DidEbsiErrorReason::InvalidDocument)
    );
}

#[test]
fn rejects_non_profile_controllers_methods_and_keys() {
    const OTHER_DID: &str = "did:ebsi:ztRBFfMCY7VAGHH1Ba8Q5o9";
    let foreign_controller = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":"did:web:controller.example"}}"#
    );
    let foreign_method_id = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{OTHER_DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","x":"{P256_X}","y":"{P256_Y}"}}}}]}}"#
    );
    let unlisted_method_controller = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{OTHER_DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","x":"{P256_X}","y":"{P256_Y}"}}}}]}}"#
    );
    let ed25519 = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":"11qYAYdkYOC5VYxRjAtUjR5_bVG7pR3v-d-TG3L_6Xk"}}}}]}}"#
    );
    let rsa = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"RSA","alg":"RS256","n":"AQAB","e":"AQAB"}}}}]}}"#
    );
    let wrong_kid = document(
        DID,
        &format!("{DID}#key-1"),
        r#", "kid":"different-key""#,
        "P-256",
    );

    for (bytes, expected) in [
        (
            foreign_controller.into_bytes(),
            DidEbsiErrorReason::InvalidDocument,
        ),
        (
            foreign_method_id.into_bytes(),
            DidEbsiErrorReason::InvalidDocument,
        ),
        (
            unlisted_method_controller.into_bytes(),
            DidEbsiErrorReason::InvalidDocument,
        ),
        (
            ed25519.into_bytes(),
            DidEbsiErrorReason::UnsupportedAlgorithm,
        ),
        (rsa.into_bytes(), DidEbsiErrorReason::UnsupportedAlgorithm),
        (wrong_kid, DidEbsiErrorReason::InvalidDocument),
    ] {
        assert_eq!(
            parse_and_validate_did_ebsi_document(DID, &bytes, DidEbsiDocumentLimits::default(),)
                .err()
                .map(|error| error.reason),
            Some(expected)
        );
    }
}

#[test]
fn rejects_key_agreement_material_as_local_invocation_authority() {
    let document = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":"{DID}","verificationMethod":[{{"id":"{DID}#agreement-key","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"OKP","crv":"X25519","use":"enc","key_ops":["deriveKey"],"x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}}}}],"capabilityInvocation":["{DID}#agreement-key"]}}"#
    );
    assert_eq!(
        parse_and_validate_did_ebsi_document(
            DID,
            document.as_bytes(),
            DidEbsiDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
        Some(DidEbsiErrorReason::UnsupportedAlgorithm)
    );
}

#[test]
fn rejects_non_profile_ml_dsa_verification_method() -> Result<(), Box<dyn std::error::Error>> {
    let public_key = reallyme_codec::base64url::bytes_to_base64url(&[0x5a; 1_312]);
    let document = serde_json::json!({
        "@context": "https://www.w3.org/ns/did/v1",
        "id": DID,
        "controller": [DID],
        "verificationMethod": [{
            "id": format!("{DID}#ml-dsa-44"),
            "type": "JsonWebKey2020",
            "controller": DID,
            "publicKeyJwk": {
                "kty": "AKP",
                "alg": "ML-DSA-44",
                "pub": public_key,
                "use": "sig",
                "key_ops": ["verify"]
            }
        }],
        "assertionMethod": [format!("{DID}#ml-dsa-44")]
    });
    let encoded = serde_json::to_vec(&document)?;
    assert_eq!(
        parse_and_validate_did_ebsi_document(DID, &encoded, DidEbsiDocumentLimits::default())
            .err()
            .map(|error| error.reason),
        Some(DidEbsiErrorReason::UnsupportedAlgorithm)
    );
    Ok(())
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

#[test]
fn rejects_did_context_that_is_not_first() {
    let document = format!(
        r#"{{"@context":["https://example.com/context","https://www.w3.org/ns/did/v1"],"id":"{DID}"}}"#
    );
    assert_eq!(
        parse_and_validate_did_ebsi_document(
            DID,
            document.as_bytes(),
            DidEbsiDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
        Some(DidEbsiErrorReason::InvalidDocument)
    );
}

#[test]
fn embedded_capability_invocation_cannot_hide_a_live_registry_key() {
    let document = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","key_ops":["verify"],"x":"{P256_X}","y":"{P256_Y}"}}}}],"assertionMethod":["{DID}#key-1"],"capabilityInvocation":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","x":"{P256_X}","y":"{P256_Y}"}}}},"{DID}#key-1"]}}"#
    );

    assert_eq!(
        parse_and_validate_did_ebsi_document(
            DID,
            document.as_bytes(),
            DidEbsiDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
        Some(DidEbsiErrorReason::InvalidDocument)
    );
}
