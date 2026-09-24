// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::jose::{bind_jwk_to_certificate, parse_protected_header, validate_key_operations};
use super::{JoseRegistryJwsVerifier, RegistryJwsVerifier, ValidatedJwks};
use crate::json::StrictValue;
use crate::{RegistrationError, RegistrationErrorReason};

const ED25519_JWK: &[u8] = br#"{
    "kty":"OKP",
    "crv":"Ed25519",
    "x":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
    "alg":"EdDSA",
    "use":"sig",
    "kid":"mismatch-key"
}"#;
const RSA_CERTIFICATE_B64: &str =
    include_str!("../../../../trust/x509/tests/fixtures/qwac_server_auth_cert.der.b64");
const ED25519_PUBLIC_X: &str = "oTAW9-L-_6jfPknLn8QI6XEEJeGQdTuPK-yyaVql44E";
const ED25519_PRIVATE_D: &str = "YDJ4Zc0ZAUD8NV1fXcV8kQPDdLZ2lQEfOX98qsTLyAY";
const ED25519_CERTIFICATE_B64: &str = "MIIBTDCB/6ADAgECAhR8ihYYs45gphDNqlBWi1e/4u8ePTAFBgMrZXAwHDEaMBgGA1UEAwwRcmVnaXN0cmFyLmV4YW1wbGUwHhcNMjYwOTE3MDIyNjA5WhcNMzYwOTE0MDIyNjA5WjAcMRowGAYDVQQDDBFyZWdpc3RyYXIuZXhhbXBsZTAqMAUGAytlcAMhAKEwFvfi/v+o3z5Jy5/ECOlxBCXhkHU7jyvssmlapeOBo1MwUTAdBgNVHQ4EFgQUI84oCnu825+r7YxjQ16htWGRJ9QwHwYDVR0jBBgwFoAUI84oCnu825+r7YxjQ16htWGRJ9QwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQACG8TaM4FszNVtp3cqZHH9TsmLKSe7UVokJkctTnt+OM5YRATKw4OYyh42O8G/yglt4JH83Kekr0ua64YmWAIF";

#[test]
fn rejects_jwk_certificate_public_key_mismatch() -> Result<(), RegistrationError> {
    let jwk = serde_json::from_slice(ED25519_JWK)
        .map_err(|_error| RegistrationError::from_reason(RegistrationErrorReason::InvalidField))?;
    let certificate_der = reallyme_codec::base64::base64_to_bytes(RSA_CERTIFICATE_B64.trim())
        .map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::InvalidCertificate)
        })?;
    let error = bind_jwk_to_certificate(&jwk, &certificate_der, "EdDSA").err();
    assert_eq!(
        error.map(crate::RegistrationError::reason),
        Some(RegistrationErrorReason::AuthenticationReceiptMismatch)
    );
    Ok(())
}

#[test]
fn accepts_standard_jwt_header_without_optional_typ() -> Result<(), RegistrationError> {
    let encoded = reallyme_codec::base64url::bytes_to_base64url(
        br#"{"alg":"EdDSA","kid":"registrar-key-1"}"#,
    );
    let compact = format!("{encoded}.cGF5bG9hZA.c2ln");
    let header = parse_protected_header(compact.as_bytes())?;
    assert_eq!(header.typ, None);
    Ok(())
}

#[test]
fn verifies_jws_with_certificate_bound_jwks_key() -> Result<(), RegistrationError> {
    let public_jwk_json = format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED25519_PUBLIC_X}","alg":"EdDSA","use":"sig","kid":"registrar-key-1"}}"#
    );
    let jwk = serde_json::from_str(&public_jwk_json)
        .map_err(|_error| RegistrationError::from_reason(RegistrationErrorReason::InvalidField))?;
    let private_key = zeroize::Zeroizing::new(
        reallyme_codec::base64url::base64url_to_bytes(ED25519_PRIVATE_D).map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::InvalidField)
        })?,
    );
    let claims = serde_json::json!({"iss":"registry-1","iat":42,"data":true});
    let compact =
        reallyme_jose::jwt::encode_signed_jwt(&claims, &jwk, &private_key).map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::SignatureVerificationFailed)
        })?;
    let jwks_body = format!(
        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{ED25519_PUBLIC_X}","alg":"EdDSA","use":"sig","key_ops":["verify"],"kid":"registrar-key-1","x5c":["{ED25519_CERTIFICATE_B64}"]}}]}}"#
    );
    let jwks = ValidatedJwks::try_new(
        "https://registry.example/jwks",
        "https://registry.example/jwks",
        0,
        "application/jwk-set+json",
        jwks_body.as_bytes(),
    )?;
    let receipt = JoseRegistryJwsVerifier.verify(compact.as_bytes(), &jwks)?;
    let decoded: serde_json::Value = serde_json::from_slice(&receipt.payload)
        .map_err(|_error| RegistrationError::from_reason(RegistrationErrorReason::InvalidJson))?;
    assert_eq!(decoded, claims);
    Ok(())
}

#[test]
fn rejects_non_verification_jwks_key_operation() {
    let key_operations = StrictValue::Array(vec![StrictValue::String("sign".to_owned())]);
    let error = validate_key_operations(Some(key_operations)).err();
    assert_eq!(
        error.map(RegistrationError::reason),
        Some(RegistrationErrorReason::InvalidField)
    );
}
