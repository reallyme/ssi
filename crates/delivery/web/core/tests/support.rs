// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
#![allow(dead_code)]
//! Shared test helpers for web delivery tests.

use crypto_core::Algorithm;
use crypto_dispatch::generate_keypair;

use envelopes_jwk::p256_public_key_to_jwk;
use envelopes_jwk::{Jwk, JwkOptions};

/// Test signing key for Google Wallet JWTs (ES256).
#[derive(Debug)]
pub struct TestSigningKey {
    /// Public key bytes.
    pub public: Vec<u8>,
    /// Private key bytes used only by tests.
    pub private: Vec<u8>,
    /// Public JWK used by the JWT helper.
    pub jwk: Jwk,
}

/// Generate a real P-256 keypair suitable for Google Wallet.
pub fn gen_google_wallet_key() -> TestSigningKey {
    let (public, private) = generate_keypair(Algorithm::P256).expect("P-256 keygen must succeed");

    let jwk = p256_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,     // include "alg": "ES256"
            use_sig: true, // include "use": "sig"
            use_enc: false,
            kid: Some("gw-test-key-1".into()),
        },
    )
    .expect("P-256 JWK conversion must succeed");

    TestSigningKey {
        public,
        private: private.to_vec(),
        jwk: Jwk::Ec(jwk),
    }
}
