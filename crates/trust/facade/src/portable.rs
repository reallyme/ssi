// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::{
    verify_chain_signatures_pure_rust, X509Chain, X509Error, X509SignatureFailure,
};
use reallyme_trust_core::{SignatureVerifier, SignatureVerifyError};
use time::OffsetDateTime;
use x509_parser::{
    prelude::{FromDer, X509Certificate as ParsedCertificate},
    public_key::PublicKey,
};

/// Match the native trust backend's minimum RSA security level.
const MIN_RSA_MODULUS_BITS: usize = 2_048;
const BITS_PER_BYTE: usize = 8;

fn rsa_modulus_bits(modulus: &[u8]) -> Option<usize> {
    let first_nonzero = modulus.iter().position(|byte| *byte != 0)?;
    let significant = modulus.get(first_nonzero..)?;
    let first = *significant.first()?;
    let leading_zeros = usize::try_from(first.leading_zeros()).ok()?;
    let first_bits = BITS_PER_BYTE.checked_sub(leading_zeros)?;
    significant
        .len()
        .checked_sub(1)?
        .checked_mul(BITS_PER_BYTE)?
        .checked_add(first_bits)
}

/// Portable verifier for the X.509 signature algorithms supported by the
/// published X.509 package. No platform or network fallback is selected.
#[derive(Debug, Default, Clone, Copy)]
pub struct PortableSignatureVerifier;

impl PortableSignatureVerifier {
    /// Construct the explicit portable backend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SignatureVerifier for PortableSignatureVerifier {
    fn verify_chain(
        &self,
        chain: &X509Chain,
        _now: OffsetDateTime,
    ) -> Result<(), SignatureVerifyError> {
        // Core policy may be caller-configured. Enforce the portable backend's
        // key floor from authenticated DER, rather than a mutable model field,
        // so a valid signature from a weak issuer cannot become trusted.
        for certificate in &chain.certs {
            let (remaining, parsed) = ParsedCertificate::from_der(&certificate.der)
                .map_err(|_| SignatureVerifyError::BackendFailure)?;
            if !remaining.is_empty() {
                return Err(SignatureVerifyError::BackendFailure);
            }
            if let PublicKey::RSA(key) = parsed
                .public_key()
                .parsed()
                .map_err(|_| SignatureVerifyError::BackendFailure)?
            {
                let modulus_bits =
                    rsa_modulus_bits(key.modulus).ok_or(SignatureVerifyError::BackendFailure)?;
                if modulus_bits < MIN_RSA_MODULUS_BITS {
                    return Err(SignatureVerifyError::InvalidSignature);
                }
            }
        }
        verify_chain_signatures_pure_rust(chain).map_err(|error| match error {
            X509Error::SignatureFailed(X509SignatureFailure::InvalidSignature)
            | X509Error::SignatureFailed(X509SignatureFailure::AlgorithmIdentifierMismatch)
            | X509Error::SignatureFailed(X509SignatureFailure::ChainIssuerMismatch) => {
                SignatureVerifyError::InvalidSignature
            }
            // An unsupported algorithm or path constraint leaves trust unknown;
            // reporting an invalid signature would imply evidence we do not have.
            X509Error::SignatureFailed(X509SignatureFailure::UnsupportedAlgorithm)
            | X509Error::SignatureFailed(X509SignatureFailure::UnsupportedPathConstraint) => {
                SignatureVerifyError::UnsupportedAlgorithm
            }
            _ => SignatureVerifyError::BackendFailure,
        })
    }
}

#[cfg(test)]
#[path = "portable_tests.rs"]
mod tests;
