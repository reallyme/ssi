// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! OpenSSL-backed certificate signature verifier.
//!
//! This crate adapts parsed identity X.509 chains into OpenSSL's path
//! verification APIs. Trust policy, revocation, and TSL handling remain in the
//! identity trust layers so this backend stays focused on cryptographic chain
//! signature validation.

use envelopes_x509::X509Chain;
use reallyme_trust_core::{SignatureVerifier, SignatureVerifyError};

#[cfg(not(target_arch = "wasm32"))]
use openssl::stack::Stack;
#[cfg(not(target_arch = "wasm32"))]
use openssl::x509::store::X509StoreBuilder;
#[cfg(not(target_arch = "wasm32"))]
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
#[cfg(not(target_arch = "wasm32"))]
use openssl::x509::{X509StoreContext, X509};

use time::OffsetDateTime;

/// Certificate signature verifier backed by OpenSSL.
pub struct OpenSslSignatureVerifier;

impl OpenSslSignatureVerifier {
    /// Create an OpenSSL-backed signature verifier.
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpenSslSignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureVerifier for OpenSslSignatureVerifier {
    fn verify_chain(
        &self,
        chain: &X509Chain,
        now: OffsetDateTime,
    ) -> Result<(), SignatureVerifyError> {
        verify_chain_with_backend(chain, now)
    }
}

#[cfg(target_arch = "wasm32")]
fn verify_chain_with_backend(
    _chain: &X509Chain,
    _now: OffsetDateTime,
) -> Result<(), SignatureVerifyError> {
    Err(SignatureVerifyError::BackendFailure)
}

#[cfg(not(target_arch = "wasm32"))]
fn verify_chain_with_backend(
    chain: &X509Chain,
    now: OffsetDateTime,
) -> Result<(), SignatureVerifyError> {
    if chain.certs.len() < 2 {
        return Err(SignatureVerifyError::BackendFailure);
    }

    // leaf to intermediates to root.
    let leaf = &chain.certs[0];
    let root = chain
        .certs
        .last()
        .ok_or(SignatureVerifyError::BackendFailure)?;

    let intermediates = &chain.certs[1..chain.certs.len() - 1];

    // eIDAS/QTSP validation must not accept a chain with a broken issuer path.
    let last = chain
        .certs
        .get(chain.certs.len() - 2)
        .ok_or(SignatureVerifyError::BackendFailure)?;

    if last.issuer != root.subject {
        return Err(SignatureVerifyError::InvalidSignature);
    }

    let leaf_x509 = X509::from_der(&leaf.der).map_err(|_| SignatureVerifyError::BackendFailure)?;

    let root_x509 = X509::from_der(&root.der).map_err(|_| SignatureVerifyError::BackendFailure)?;

    let mut intermediate_stack =
        Stack::<X509>::new().map_err(|_| SignatureVerifyError::BackendFailure)?;

    for c in intermediates {
        intermediate_stack
            .push(X509::from_der(&c.der).map_err(|_| SignatureVerifyError::BackendFailure)?)
            .map_err(|_| SignatureVerifyError::BackendFailure)?;
    }

    let mut store_builder =
        X509StoreBuilder::new().map_err(|_| SignatureVerifyError::BackendFailure)?;

    let mut verification_parameters =
        X509VerifyParam::new().map_err(|_| SignatureVerifyError::BackendFailure)?;
    verification_parameters
        .set_flags(
            X509VerifyFlags::X509_STRICT
                | X509VerifyFlags::NO_ALT_CHAINS
                | X509VerifyFlags::TRUSTED_FIRST,
        )
        .map_err(|_| SignatureVerifyError::BackendFailure)?;
    // RFC 5280 §6.1.3 requires validity processing at the selected validation
    // time. Supplying the caller's time here is essential for deterministic
    // historical evaluation and avoids OpenSSL's ambient-clock default.
    verification_parameters.set_time(now.unix_timestamp());
    store_builder
        .set_param(&verification_parameters)
        .map_err(|_| SignatureVerifyError::BackendFailure)?;

    store_builder
        .add_cert(root_x509)
        .map_err(|_| SignatureVerifyError::BackendFailure)?;

    let store = store_builder.build();

    let mut ctx = X509StoreContext::new().map_err(|_| SignatureVerifyError::BackendFailure)?;

    let verified = ctx
        .init(&store, &leaf_x509, &intermediate_stack, |c| c.verify_cert())
        .map_err(|_| SignatureVerifyError::InvalidSignature)?;

    if verified {
        Ok(())
    } else {
        // OpenSSL reports ordinary path-validation rejection as `Ok(false)`;
        // accepting that value would bypass time, signature, and constraint checks.
        Err(SignatureVerifyError::InvalidSignature)
    }
}
