// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded validation of caller-supplied DER trust roots before any native call.

use crate::error::{XmlSecError, XmlSecTrustRootErrorReason};

/// Maximum number of DER trust roots accepted by one verification call.
///
/// Matches the workspace trust-root budget used by the OpenSSL trusted-list
/// verifier so that every root that passes that boundary is also loaded here.
pub const MAX_TSL_XMLSEC_TRUSTED_ROOTS: usize = 32;

/// Maximum DER bytes accepted for one trust root.
///
/// Matches the workspace X.509 certificate DER budget.
pub const MAX_TSL_XMLSEC_TRUSTED_ROOT_DER_BYTES: usize = 65_536;

#[cfg(feature = "xmlsec-ffi")]
const _: [(); MAX_TSL_XMLSEC_TRUSTED_ROOTS] =
    [(); identity_trust_tsl_xmlsec_sys::MEID_XMLSEC_MAX_TRUSTED_ROOTS];
#[cfg(feature = "xmlsec-ffi")]
const _: [(); MAX_TSL_XMLSEC_TRUSTED_ROOT_DER_BYTES] =
    [(); identity_trust_tsl_xmlsec_sys::MEID_XMLSEC_MAX_TRUSTED_ROOT_DER_BYTES];

/// Validate trust-root count and per-root size without allocating.
pub(super) fn validate_trusted_roots(trusted_roots_der: &[&[u8]]) -> Result<(), XmlSecError> {
    if trusted_roots_der.is_empty() {
        return Err(XmlSecError::TrustRoots(XmlSecTrustRootErrorReason::Empty));
    }
    if trusted_roots_der.len() > MAX_TSL_XMLSEC_TRUSTED_ROOTS {
        return Err(XmlSecError::TrustRoots(
            XmlSecTrustRootErrorReason::TooManyTrustRoots,
        ));
    }
    for root in trusted_roots_der {
        if root.is_empty() {
            return Err(XmlSecError::TrustRoots(
                XmlSecTrustRootErrorReason::InvalidCertificateDer,
            ));
        }
        if root.len() > MAX_TSL_XMLSEC_TRUSTED_ROOT_DER_BYTES {
            return Err(XmlSecError::TrustRoots(
                XmlSecTrustRootErrorReason::CertificateDerTooLarge,
            ));
        }
    }
    Ok(())
}
