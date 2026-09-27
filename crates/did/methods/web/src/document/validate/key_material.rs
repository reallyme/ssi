// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn validate_public_key_material(
    method_type: &str,
    object: &Map<String, Value>,
) -> Result<(), DidWebError> {
    let multibase = object.get("publicKeyMultibase");
    let jwk = object.get("publicKeyJwk");
    let account = object.get("blockchainAccountId");
    let count = usize::from(multibase.is_some())
        .checked_add(usize::from(jwk.is_some()))
        .and_then(|value| value.checked_add(usize::from(account.is_some())))
        .ok_or(DidWebError::new(
            DidWebErrorReason::InvalidVerificationMethod,
        ))?;
    if count != 1 {
        return Err(DidWebError::new(
            DidWebErrorReason::InvalidVerificationMethod,
        ));
    }
    if let Some(value) = multibase {
        let encoded = value
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or(DidWebError::new(
                DidWebErrorReason::InvalidVerificationMethod,
            ))?;
        if !valid_base58btc_multibase(encoded)
            || !multibase_matches_verification_method(method_type, encoded)
        {
            return Err(DidWebError::new(
                DidWebErrorReason::InvalidVerificationMethod,
            ));
        }
    }
    if let Some(value) = account {
        if value.as_str().is_none_or(str::is_empty) {
            return Err(DidWebError::new(
                DidWebErrorReason::InvalidVerificationMethod,
            ));
        }
    }
    if let Some(value) = jwk {
        if reallyme_did_method_jwk::validate_public_jwk(value).is_err()
            || !jwk_matches_verification_method(method_type, value)
        {
            return Err(DidWebError::new(
                DidWebErrorReason::InvalidVerificationMethod,
            ));
        }
    }
    Ok(())
}

fn valid_base58btc_multibase(value: &str) -> bool {
    if !value.starts_with('z') || value.len() > MAX_PUBLIC_KEY_MULTIBASE_BYTES {
        return false;
    }
    reallyme_codec::multibase::multibase_to_bytes(value)
        .is_ok_and(|decoded| valid_multicodec_payload(&decoded))
}

fn valid_multicodec_payload(value: &[u8]) -> bool {
    for (index, byte) in value.iter().take(MAX_MULTICODEC_VARINT_BYTES).enumerate() {
        if byte & 0x80 == 0 {
            let noncanonical = index > 0 && *byte == 0;
            let payload_start = index.checked_add(1);
            let overflows_u64 =
                payload_start == Some(MAX_MULTICODEC_VARINT_BYTES) && byte & 0x7f > 1;
            return !noncanonical
                && !overflows_u64
                && payload_start.is_some_and(|start| value.len() > start);
        }
    }
    false
}

fn multibase_matches_verification_method(method_type: &str, value: &str) -> bool {
    use reallyme_did_method_key::DidKeyMulticodec;

    match method_type {
        "JsonWebKey"
        | "JsonWebKey2020"
        | "Ed25519VerificationKey2018"
        | "EcdsaSecp256k1VerificationKey2019" => false,
        "Ed25519VerificationKey2020" | "X25519KeyAgreementKey2020" => {
            let mut did_key = String::from("did:key:");
            did_key.push_str(value);
            reallyme_did_method_key::parse_did_key(&did_key).is_ok_and(|parsed| match method_type {
                "Ed25519VerificationKey2020" => parsed.multicodec == DidKeyMulticodec::Ed25519,
                "X25519KeyAgreementKey2020" => parsed.multicodec == DidKeyMulticodec::X25519,
                _ => false,
            })
        }
        // Multikey is an extensible multicodec container. This crate validates
        // the bounded multibase representation and leaves unfamiliar codecs
        // to the cryptographic consumer instead of rejecting valid documents.
        "Multikey" => match reallyme_codec::multikey::parse_multikey(value) {
            Ok(_) | Err(reallyme_codec::multikey::MultikeyError::UnknownCodecPrefix) => true,
            Err(_) => false,
        },
        _ => true,
    }
}

fn jwk_matches_verification_method(method_type: &str, value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let key_type = object.get("kty").and_then(Value::as_str);
    let curve = object.get("crv").and_then(Value::as_str);
    match method_type {
        "JsonWebKey" | "JsonWebKey2020" => true,
        "Ed25519VerificationKey2018" => key_type == Some("OKP") && curve == Some("Ed25519"),
        "EcdsaSecp256k1VerificationKey2019" => key_type == Some("EC") && curve == Some("secp256k1"),
        "Multikey" | "Ed25519VerificationKey2020" | "X25519KeyAgreementKey2020" => false,
        _ => true,
    }
}
