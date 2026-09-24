// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 7636 PKCE support. This crate permits S256 only.

use core::fmt;

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::sha2::digest as digest_sha2_256;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{OauthError, OauthResult, Reason};
use crate::validation::validate_token;

/// PKCE code challenge method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    /// S256 code challenge method.
    #[serde(rename = "S256")]
    S256,
}

/// Secret-bearing PKCE verifier.
#[derive(ZeroizeOnDrop)]
pub struct PkceVerifier {
    verifier: SecretString,
}

impl PkceVerifier {
    /// Creates a verifier after RFC 7636 length and character validation.
    pub fn new(verifier: SecretString) -> OauthResult<Self> {
        validate_code_verifier(verifier.expose_secret())?;
        Ok(Self { verifier })
    }

    /// Computes the S256 code challenge.
    #[must_use]
    pub fn challenge(&self) -> PkceChallenge {
        let digest = digest_sha2_256(self.verifier.expose_secret().as_bytes());
        PkceChallenge {
            code_challenge: bytes_to_base64url(digest.as_bytes()),
            code_challenge_method: CodeChallengeMethod::S256,
        }
    }

    /// Exposes the verifier for token request construction.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.verifier.expose_secret()
    }
}

/// Public PKCE challenge parameters for authorization or PAR requests.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct PkceChallenge {
    /// S256 challenge.
    pub code_challenge: String,
    /// Challenge method. Only S256 is supported.
    pub code_challenge_method: CodeChallengeMethod,
}

impl fmt::Debug for PkceChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PkceChallenge([REDACTED])")
    }
}

impl Zeroize for PkceChallenge {
    fn zeroize(&mut self) {
        self.code_challenge.zeroize();
    }
}

impl Drop for PkceChallenge {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PkceChallenge {}

impl PkceChallenge {
    /// Validates the public challenge.
    pub fn validate(&self) -> OauthResult<()> {
        validate_token(&self.code_challenge)
    }
}

fn validate_code_verifier(value: &str) -> OauthResult<()> {
    validate_token(value)?;
    let len = value.len();
    if !(43..=128).contains(&len) {
        return Err(OauthError::new(Reason::InvalidPkce));
    }
    for byte in value.as_bytes() {
        let valid = matches!(
            *byte,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
        );
        if !valid {
            return Err(OauthError::new(Reason::InvalidPkce));
        }
    }
    Ok(())
}
