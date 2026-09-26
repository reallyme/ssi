// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_cose::CoseSignatureAlgorithm;
use reallyme_credential_status::{
    verify_token_status_list_cwt, verify_token_status_list_jwt, TokenStatusListFreshnessPolicy,
};
use reallyme_crypto::jwk::{Jwk, OkpJwk};

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let key = [0_u8; 32];
    let jwk = Jwk::Okp(OkpJwk {
        kty: "OKP".to_owned(),
        crv: "Ed25519".to_owned(),
        x: reallyme_codec::base64url::bytes_to_base64url(&key),
        alg: Some("EdDSA".to_owned()),
        use_: Some("sig".to_owned()),
        kid: None,
    });
    if let Ok(jwt) = core::str::from_utf8(data) {
        let _ = verify_token_status_list_jwt(
            jwt,
            &jwk,
            &key,
            "https://issuer.example/status",
            1_800_000_000,
            TokenStatusListFreshnessPolicy::default(),
        );
    }
    let _ = verify_token_status_list_cwt(
        data,
        CoseSignatureAlgorithm::Ed25519,
        |_, _| Some(key.to_vec()),
        "https://issuer.example/status",
        1_800_000_000,
        TokenStatusListFreshnessPolicy::default(),
    );
});
