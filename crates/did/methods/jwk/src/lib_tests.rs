// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::indexing_slicing)]

use super::{
    did_jwk_url, generate_did_jwk, generate_did_jwk_from_json_bytes, parse_did_jwk,
    DidJwkErrorReason,
};
use serde_json::json;

const SPEC_P256_DID: &str = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
const SPEC_P256_JWK: &[u8] = br#"{"crv":"P-256","kty":"EC","x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0","y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"}"#;
const SPEC_X25519_DID: &str = "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9";
const SPEC_X25519_JWK: &[u8] =
        br#"{"kty":"OKP","crv":"X25519","use":"enc","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#;

#[test]
fn generated_p256_did_jwk_matches_method_encoding() -> Result<(), Box<dyn std::error::Error>> {
    let jwk = json!({
        "crv": "P-256",
        "kty": "EC",
        "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
        "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
    });

    let did = generate_did_jwk(&jwk)?;
    assert!(did.starts_with("did:jwk:"));
    assert!(!did.contains('='));
    let parsed = parse_did_jwk(&did)?;
    assert_eq!(parsed.jwk, jwk);
    assert_eq!(did_jwk_url(&did)?, format!("{did}#0"));
    Ok(())
}

#[test]
fn published_p256_did_jwk_vector_decodes_and_regenerates() -> Result<(), Box<dyn std::error::Error>>
{
    let parsed = parse_did_jwk(SPEC_P256_DID)?;
    let jwk: serde_json::Value = serde_json::from_slice(SPEC_P256_JWK)?;

    assert_eq!(parsed.jwk, jwk);
    assert_eq!(
        generate_did_jwk_from_json_bytes(SPEC_P256_JWK)?,
        SPEC_P256_DID
    );
    assert_eq!(did_jwk_url(SPEC_P256_DID)?, format!("{SPEC_P256_DID}#0"));
    Ok(())
}

#[test]
fn published_x25519_did_jwk_vector_decodes_and_regenerates(
) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = parse_did_jwk(SPEC_X25519_DID)?;
    let jwk: serde_json::Value = serde_json::from_slice(SPEC_X25519_JWK)?;

    assert_eq!(parsed.jwk, jwk);
    assert_eq!(
        generate_did_jwk_from_json_bytes(SPEC_X25519_JWK)?,
        SPEC_X25519_DID
    );
    assert_eq!(
        did_jwk_url(SPEC_X25519_DID)?,
        format!("{SPEC_X25519_DID}#0")
    );
    Ok(())
}

#[test]
fn did_jwk_rejects_private_key_material() {
    let jwk = json!({
        "crv": "Ed25519",
        "kty": "OKP",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "d": "nWGxne_9WmC6Sff6YQ2M-fcXhQWdAyd2R2zVdu7VcMc"
    });

    let err = generate_did_jwk(&jwk).err().map(|error| error.reason);
    assert_eq!(err, Some(DidJwkErrorReason::PrivateKeyMaterial));
}

#[test]
fn did_jwk_rejects_padded_base64url() {
    let err = parse_did_jwk("did:jwk:eyJrdHkiOiJPS1AifQ==")
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidJwkErrorReason::InvalidBase64Url));
}

#[test]
fn rejects_duplicate_jwk_members_at_both_byte_boundaries() {
    let input = br#"{"kty":"RSA","kty":"OKP","crv":"Ed25519","x":"AA"}"#;
    assert_eq!(
        generate_did_jwk_from_json_bytes(input)
            .err()
            .map(|error| error.reason),
        Some(DidJwkErrorReason::InvalidJson)
    );
    let did = format!(
        "did:jwk:{}",
        reallyme_codec::base64url::bytes_to_base64url(input)
    );
    assert_eq!(
        parse_did_jwk(&did).err().map(|error| error.reason),
        Some(DidJwkErrorReason::InvalidJson)
    );
}

#[test]
fn did_jwk_rejects_malformed_public_parameters_and_inconsistent_standard_usage() {
    for jwk in [
        json!({"kty":"EC","crv":"P-256","x":"not+base64url","y":"AA"}),
        json!({"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
        json!({"kty":"OKP","crv":"Ed25519","x":"AA","use":"sig","key_ops":["verify","verify"]}),
        json!({"kty":"OKP","crv":"Ed25519","x":"AA","use":"sig","key_ops":["encrypt"]}),
        json!({"kty":"RSA","n":"AQ","e":"AQ"}),
    ] {
        assert_eq!(
            generate_did_jwk(&jwk).err().map(|error| error.reason),
            Some(DidJwkErrorReason::InvalidPublicJwk)
        );
    }
}

#[test]
fn did_jwk_rejects_rsa_moduli_below_2048_bits() {
    let short_modulus = vec![0xFF; 255];
    let weak_leading_bit = {
        let mut value = vec![0xFF; 256];
        value[0] = 0x7F;
        value
    };
    for modulus in [short_modulus, weak_leading_bit] {
        let jwk = json!({
            "kty": "RSA",
            "n": reallyme_codec::base64url::bytes_to_base64url(&modulus),
            "e": "AQAB"
        });
        assert_eq!(
            generate_did_jwk(&jwk).err().map(|error| error.reason),
            Some(DidJwkErrorReason::InvalidPublicJwk)
        );
    }
}

#[test]
fn did_jwk_rejects_oversized_or_even_rsa_moduli_and_oversized_exponents() {
    let mut oversized_modulus = vec![0; 2_049];
    oversized_modulus[0] = 1;
    oversized_modulus[2_048] = 1;
    let mut even_modulus = vec![0xff; 256];
    even_modulus[255] = 0xfe;
    let valid_modulus = vec![0xff; 256];
    let oversized_exponent = [1_u8, 0, 0, 0, 0, 0, 0, 0, 1];

    for jwk in [
        json!({
            "kty": "RSA",
            "n": reallyme_codec::base64url::bytes_to_base64url(&oversized_modulus),
            "e": "AQAB"
        }),
        json!({
            "kty": "RSA",
            "n": reallyme_codec::base64url::bytes_to_base64url(&even_modulus),
            "e": "AQAB"
        }),
        json!({
            "kty": "RSA",
            "n": reallyme_codec::base64url::bytes_to_base64url(&valid_modulus),
            "e": reallyme_codec::base64url::bytes_to_base64url(&oversized_exponent)
        }),
    ] {
        assert_eq!(
            generate_did_jwk(&jwk).err().map(|error| error.reason),
            Some(DidJwkErrorReason::InvalidPublicJwk)
        );
    }
}

#[test]
fn did_jwk_accepts_collision_resistant_usage_extension_names(
) -> Result<(), Box<dyn std::error::Error>> {
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "use": "https://example.com/jwk-use/audit",
        "key_ops": ["https://example.com/jwk-operation/audit"]
    });

    let did = generate_did_jwk(&jwk)?;
    assert_eq!(parse_did_jwk(&did)?.jwk, jwk);

    let extended_operation = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "use": "sig",
        "key_ops": ["https://example.com/jwk-operation/audit-sign"]
    });
    let did = generate_did_jwk(&extended_operation)?;
    assert_eq!(parse_did_jwk(&did)?.jwk, extended_operation);
    Ok(())
}

#[test]
fn did_jwk_accepts_registered_and_extension_akp_public_keys(
) -> Result<(), Box<dyn std::error::Error>> {
    let ml_dsa_public = reallyme_codec::base64url::bytes_to_base64url(&[0x5a; 1_312]);
    let ml_dsa = json!({
        "kty": "AKP",
        "alg": "ML-DSA-44",
        "pub": ml_dsa_public,
        "use": "sig",
        "key_ops": ["verify"]
    });
    let did = generate_did_jwk(&ml_dsa)?;
    assert_eq!(parse_did_jwk(&did)?.jwk, ml_dsa);

    let extension = json!({
        "kty": "AKP",
        "alg": "https://example.com/algorithms/example-akp",
        "pub": "AQID"
    });
    let did = generate_did_jwk(&extension)?;
    assert_eq!(parse_did_jwk(&did)?.jwk, extension);
    Ok(())
}

#[test]
fn did_jwk_rejects_invalid_or_private_akp_keys() {
    for jwk in [
        json!({"kty":"AKP","alg":"ML-DSA-44","pub":"AQID"}),
        json!({"kty":"AKP","alg":"ML-DSA-44","pub":"AQID","priv":"AA"}),
        json!({"kty":"AKP","alg":"ML-DSA-44","pub":"AQID="}),
        json!({"kty":"AKP","alg":"","pub":"AQID"}),
    ] {
        assert!(generate_did_jwk(&jwk).is_err());
    }
}
