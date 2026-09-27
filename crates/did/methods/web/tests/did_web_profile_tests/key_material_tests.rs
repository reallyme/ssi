// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    parse_and_validate_did_web_document, parse_did_web, DidWebDocumentLimits, DidWebErrorReason,
    DID,
};

#[test]
fn document_validation_accepts_registered_verification_method_key_pairs(
) -> Result<(), Box<dyn std::error::Error>> {
    let identifier = parse_did_web(DID)?;
    let ed25519_jwk =
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    let secp256k1_jwk = r#"{"kty":"EC","crv":"secp256k1","x":"eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g","y":"SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg"}"#;
    for (method_type, jwk) in [
        ("JsonWebKey", ed25519_jwk),
        ("Ed25519VerificationKey2018", ed25519_jwk),
        ("EcdsaSecp256k1VerificationKey2019", secp256k1_jwk),
    ] {
        let document = format!(
            r#"{{"id":"{DID}","verificationMethod":[{{"id":"{DID}#key-1","type":"{method_type}","controller":"{DID}","publicKeyJwk":{jwk}}}]}}"#
        );
        parse_and_validate_did_web_document(
            &identifier,
            document.as_bytes(),
            DidWebDocumentLimits::default(),
        )?;
    }

    let mldsa_multikey = reallyme_codec::multikey::encode_multikey("mldsa-87-pub", &[7; 2592])?;
    let document = format!(
        r#"{{"id":"{DID}","verificationMethod":[{{"id":"{DID}#pq","type":"Multikey","controller":"{DID}","publicKeyMultibase":"{mldsa_multikey}"}}]}}"#
    );
    parse_and_validate_did_web_document(
        &identifier,
        document.as_bytes(),
        DidWebDocumentLimits::default(),
    )?;
    Ok(())
}

#[test]
fn document_validation_rejects_explicit_key_type_mismatches(
) -> Result<(), Box<dyn std::error::Error>> {
    let identifier = parse_did_web(DID)?;
    let mismatched = format!(
        r#"{{"id":"{DID}","verificationMethod":[{{"id":"{DID}#key-1","type":"EcdsaSecp256k1VerificationKey2019","controller":"{DID}","publicKeyJwk":{{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}}}]}}"#
    );
    assert_eq!(
        parse_and_validate_did_web_document(
            &identifier,
            mismatched.as_bytes(),
            DidWebDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
        Some(DidWebErrorReason::InvalidVerificationMethod)
    );
    Ok(())
}
