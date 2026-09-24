// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded trust-root validation performed before native backend allocation.

use envelopes_x509::{X509Certificate, MAX_X509_CERTIFICATE_DER_BYTES, MAX_X509_CHAIN_PEM_BYTES};

use crate::error::{TslOpenSslError, TslTrustRootErrorReason};

/// Maximum trust roots accepted before any OpenSSL or XML processing.
pub const MAX_TSL_TRUST_ROOTS: usize = reallyme_trust_core::MAX_TRUST_ROOTS;
/// Maximum DER bytes accepted for one TSL trust root.
pub const MAX_TSL_TRUST_ROOT_DER_BYTES: usize = MAX_X509_CERTIFICATE_DER_BYTES;
/// Maximum bytes reserved for the complete XMLSec trust-root PEM bundle.
pub const MAX_TSL_TRUST_ROOT_PEM_BUNDLE_BYTES: usize = MAX_X509_CHAIN_PEM_BYTES;

const PEM_BEGIN_CERTIFICATE_BYTES: usize = b"-----BEGIN CERTIFICATE-----\n".len();
const PEM_END_CERTIFICATE_BYTES: usize = b"-----END CERTIFICATE-----\n".len();
const PEM_BASE64_LINE_BYTES: usize = 64;
const PEM_BASE64_LINE_ROUNDING_BYTES: usize = 63;

/// Validate TSL trust-root count and encoded-size budgets without allocating.
///
/// Callers that retain roots can use this at their construction boundary. The
/// verifier repeats the check because its lower-level slice API is public.
pub fn validate_tsl_trust_roots(trust_roots: &[X509Certificate]) -> Result<(), TslOpenSslError> {
    validate_trust_root_budget(trust_roots).map(|_| ())
}

pub(crate) fn validate_trust_root_budget(
    trust_roots: &[X509Certificate],
) -> Result<usize, TslOpenSslError> {
    if trust_roots.is_empty() {
        return Err(TslOpenSslError::TrustRoots(TslTrustRootErrorReason::Empty));
    }
    if trust_roots.len() > MAX_TSL_TRUST_ROOTS {
        return Err(TslOpenSslError::TrustRoots(
            TslTrustRootErrorReason::TooManyTrustRoots,
        ));
    }

    let mut bundle_bytes = 0_usize;
    for root in trust_roots {
        if root.der.is_empty() {
            return Err(TslOpenSslError::TrustRoots(
                TslTrustRootErrorReason::InvalidCertificateDer,
            ));
        }
        if root.der.len() > MAX_TSL_TRUST_ROOT_DER_BYTES {
            return Err(TslOpenSslError::TrustRoots(
                TslTrustRootErrorReason::CertificateDerTooLarge,
            ));
        }
        let root_pem_bytes = pem_encoded_upper_bound(root.der.len())?;
        bundle_bytes =
            bundle_bytes
                .checked_add(root_pem_bytes)
                .ok_or(TslOpenSslError::TrustRoots(
                    TslTrustRootErrorReason::PemBundleTooLarge,
                ))?;
        if bundle_bytes > MAX_TSL_TRUST_ROOT_PEM_BUNDLE_BYTES {
            return Err(TslOpenSslError::TrustRoots(
                TslTrustRootErrorReason::PemBundleTooLarge,
            ));
        }
    }
    Ok(bundle_bytes)
}

pub(crate) fn pem_encoded_upper_bound(der_bytes: usize) -> Result<usize, TslOpenSslError> {
    // RFC 7468 uses base64 text with 64-character lines. The checked upper
    // bound includes every line ending and both certificate delimiters.
    let base64_quanta = der_bytes.checked_add(2).ok_or(TslOpenSslError::TrustRoots(
        TslTrustRootErrorReason::PemBundleTooLarge,
    ))? / 3;
    let base64_bytes = base64_quanta
        .checked_mul(4)
        .ok_or(TslOpenSslError::TrustRoots(
            TslTrustRootErrorReason::PemBundleTooLarge,
        ))?;
    let line_count = base64_bytes
        .checked_add(PEM_BASE64_LINE_ROUNDING_BYTES)
        .ok_or(TslOpenSslError::TrustRoots(
            TslTrustRootErrorReason::PemBundleTooLarge,
        ))?
        / PEM_BASE64_LINE_BYTES;
    PEM_BEGIN_CERTIFICATE_BYTES
        .checked_add(base64_bytes)
        .and_then(|value| value.checked_add(line_count))
        .and_then(|value| value.checked_add(PEM_END_CERTIFICATE_BYTES))
        .ok_or(TslOpenSslError::TrustRoots(
            TslTrustRootErrorReason::PemBundleTooLarge,
        ))
}
