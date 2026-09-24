// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
        "x": "11qYAYdkYOC5VYxRjAtUjR5_bVG7pR3v-d-TG3L_6Xk",
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
