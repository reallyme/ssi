// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 5280 Section 5.2 and 5.3 extension screening for complete CRLs.

use x509_parser::der_parser::oid::Oid;
use x509_parser::extensions::X509Extension;
use x509_parser::oid_registry::{
    OID_PKIX_AUTHORITY_INFO_ACCESS, OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_CRL_NUMBER,
    OID_X509_EXT_DELTA_CRL_INDICATOR, OID_X509_EXT_FRESHEST_CRL,
    OID_X509_EXT_HOLD_INSTRUCTION_CODE, OID_X509_EXT_INVALIDITY_DATE, OID_X509_EXT_ISSUER,
    OID_X509_EXT_ISSUER_ALT_NAME, OID_X509_EXT_ISSUER_DISTRIBUTION_POINT, OID_X509_EXT_REASON_CODE,
};

use crate::CrlError;

/// Maximum number of CRL-level extensions accepted.
pub const MAX_CRL_EXTENSIONS: usize = 32;
/// Maximum number of extensions accepted on one revoked-certificate entry.
pub const MAX_CRL_ENTRY_EXTENSIONS: usize = 16;

/// Screen CRL-level extensions.
///
/// Delta CRLs (Section 5.2.4) and CRLs carrying an issuing distribution point
/// (Section 5.2.5, which scopes the CRL or marks it indirect) do not provide
/// complete status for every certificate from the issuer, so they are
/// rejected. Any other critical extension this implementation does not
/// process is rejected as required by Section 5.2.
pub(crate) fn inspect_crl_extensions(extensions: &[X509Extension<'_>]) -> Result<(), CrlError> {
    if extensions.len() > MAX_CRL_EXTENSIONS {
        return Err(CrlError::TooLarge);
    }
    reject_duplicates(extensions)?;
    for extension in extensions {
        let oid = &extension.oid;
        if *oid == OID_X509_EXT_DELTA_CRL_INDICATOR
            || *oid == OID_X509_EXT_ISSUER_DISTRIBUTION_POINT
        {
            return Err(CrlError::UnsupportedScope);
        }
        let understood = *oid == OID_X509_EXT_CRL_NUMBER
            || *oid == OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER
            || *oid == OID_X509_EXT_ISSUER_ALT_NAME
            || *oid == OID_PKIX_AUTHORITY_INFO_ACCESS
            || *oid == OID_X509_EXT_FRESHEST_CRL;
        if extension.critical && !understood {
            return Err(CrlError::UnsupportedCriticalExtension);
        }
    }
    Ok(())
}

/// Screen extensions on one revoked-certificate entry.
///
/// The certificate issuer entry extension (Section 5.3.3) only appears in
/// indirect CRLs and changes which issuer later entries belong to, so it is
/// rejected. Unrecognized critical entry extensions are rejected.
pub(crate) fn inspect_entry_extensions(extensions: &[X509Extension<'_>]) -> Result<(), CrlError> {
    if extensions.len() > MAX_CRL_ENTRY_EXTENSIONS {
        return Err(CrlError::TooLarge);
    }
    reject_duplicates(extensions)?;
    for extension in extensions {
        let oid = &extension.oid;
        if *oid == OID_X509_EXT_ISSUER {
            return Err(CrlError::UnsupportedScope);
        }
        let understood = *oid == OID_X509_EXT_REASON_CODE
            || *oid == OID_X509_EXT_INVALIDITY_DATE
            || *oid == OID_X509_EXT_HOLD_INSTRUCTION_CODE;
        if extension.critical && !understood {
            return Err(CrlError::UnsupportedCriticalExtension);
        }
    }
    Ok(())
}

/// RFC 5280 Section 4.2: an extension must not appear more than once.
fn reject_duplicates(extensions: &[X509Extension<'_>]) -> Result<(), CrlError> {
    let mut seen: Vec<&Oid<'_>> = Vec::with_capacity(extensions.len());
    for extension in extensions {
        if seen.contains(&&extension.oid) {
            return Err(CrlError::InvalidCrl);
        }
        seen.push(&extension.oid);
    }
    Ok(())
}
