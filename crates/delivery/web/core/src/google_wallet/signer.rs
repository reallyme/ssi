// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::save::GoogleWalletJwtSigner;
use crate::WebDeliveryError;

use envelopes_jwk::Jwk;
use envelopes_jwt::jwt::encode_signed_jwt;
use serde_json::Value;

/// JOSE-backed Google Wallet JWT signer.
pub struct GoogleWalletJwtSignerImpl<'a> {
    /// Issuer identifier (service account email or issuer identifier)
    pub issuer: &'a str,

    /// JWK describing the signing key (must be ES256-capable)
    pub jwk: &'a Jwk,

    /// Raw private key bytes
    pub private_key: &'a [u8],
}

impl<'a> GoogleWalletJwtSigner for GoogleWalletJwtSignerImpl<'a> {
    fn sign_jwt(&self, payload_json: &[u8]) -> Result<String, WebDeliveryError> {
        let payload: Value =
            serde_json::from_slice(payload_json).map_err(|_| WebDeliveryError::Serialization)?;

        // Google Save-to-Wallet wrapper structure:
        // { iss, aud:"google", typ:"savetowallet", payload:<object JSON> }
        let claims = serde_json::json!({
            "iss": self.issuer,
            "aud": "google",
            "typ": "savetowallet",
            "payload": payload,
        });

        encode_signed_jwt(&claims, self.jwk, self.private_key)
            .map_err(|_| WebDeliveryError::SigningFailed)
    }
}
