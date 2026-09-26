// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::{
    verify_chain_signatures_pure_rust, X509Chain, X509Error, X509SignatureFailure,
};
use reallyme_trust_core::{SignatureVerifier, SignatureVerifyError};
use time::OffsetDateTime;

/// Portable certificate signature verifier for WASM and mobile compositions.
///
/// Algorithm ownership remains in `reallyme/crypto`; this adapter only maps
/// the X.509 package's bounded, typed result into the trust-policy interface.
pub struct WasmSignatureVerifier;

impl WasmSignatureVerifier {
    /// Construct the stateless portable certificate signature verifier.
    pub const fn new() -> Self {
        Self
    }
}

impl Default for WasmSignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureVerifier for WasmSignatureVerifier {
    fn verify_chain(
        &self,
        chain: &X509Chain,
        _now: OffsetDateTime,
    ) -> Result<(), SignatureVerifyError> {
        verify_chain_signatures_pure_rust(chain).map_err(map_x509_error)
    }
}

const fn map_x509_error(error: X509Error) -> SignatureVerifyError {
    match error {
        // Path constraints this lane cannot process fail closed with the same
        // typed unsupported result as a missing algorithm provider.
        X509Error::SignatureFailed(
            X509SignatureFailure::UnsupportedAlgorithm
            | X509SignatureFailure::UnsupportedPathConstraint,
        ) => SignatureVerifyError::UnsupportedAlgorithm,
        X509Error::SignatureFailed(
            X509SignatureFailure::InvalidSignature
            | X509SignatureFailure::ChainIssuerMismatch
            | X509SignatureFailure::AlgorithmIdentifierMismatch,
        ) => SignatureVerifyError::InvalidSignature,
        X509Error::InvalidDer
        | X509Error::InvalidSerialNumber
        | X509Error::DuplicateExtension
        | X509Error::InvalidPem
        | X509Error::UnsupportedPemLabel
        | X509Error::ParseError
        | X509Error::MissingField(_)
        | X509Error::PolicyFailed(_)
        | X509Error::SignatureFailed(_)
        | X509Error::ResourceLimitExceeded(_) => SignatureVerifyError::BackendFailure,
    }
}
