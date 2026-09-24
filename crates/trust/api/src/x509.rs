// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use envelopes_x509::{
    model::{KeyUsage, X509Certificate},
    parse_cert_der, MAX_X509_CHAIN_CERTIFICATES,
};
use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::dto::{X509CertificateDer, X509ChainDer};
use crate::{TrustApiError, TrustApiResult};

const MAX_CERTIFICATE_DER_BYTES: usize = 1024 * 1024;

/// Public certificate metadata returned through the typed Rust API.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CertificateMetadata {
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Certificate validity start.
    #[zeroize(skip)]
    pub not_before: OffsetDateTime,
    /// Certificate validity end.
    #[zeroize(skip)]
    pub not_after: OffsetDateTime,
    /// Key-usage projection, when present.
    #[zeroize(skip)]
    pub key_usage: Option<KeyUsageMetadata>,
    /// Extended-key-usage OIDs.
    pub extended_key_usage: Vec<String>,
    /// Certificate serial bytes.
    pub serial: Vec<u8>,
    /// Signature algorithm OID.
    pub signature_algorithm_oid: String,
}

impl core::fmt::Debug for CertificateMetadata {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CertificateMetadata")
            .field("subject", &"<redacted>")
            .field("issuer", &"<redacted>")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("key_usage", &self.key_usage)
            .field("extended_key_usage", &"<redacted>")
            .field("serial", &"<redacted>")
            .field("signature_algorithm_oid", &self.signature_algorithm_oid)
            .finish()
    }
}

/// Boolean certificate key-usage flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyUsageMetadata {
    /// Digital-signature usage.
    pub digital_signature: bool,
    /// Content-commitment (formerly non-repudiation) usage.
    pub content_commitment: bool,
    /// Key-encipherment usage.
    pub key_encipherment: bool,
    /// Data-encipherment usage.
    pub data_encipherment: bool,
    /// Certificate-signing usage.
    pub key_cert_sign: bool,
    /// CRL-signing usage.
    pub crl_sign: bool,
    /// Key-agreement usage.
    pub key_agreement: bool,
    /// Encipher-only usage.
    pub encipher_only: bool,
    /// Decipher-only usage.
    pub decipher_only: bool,
}

/// ---------------------------------------------------------------------------
/// Typed metadata extraction
/// ---------------------------------------------------------------------------
///
/// Extract human- and policy-relevant metadata from a parsed X.509 certificate.
///
/// This function is typed-only and intended for API-layer composition.
pub fn extract_certificate_metadata(cert: &X509Certificate) -> TrustApiResult<CertificateMetadata> {
    Ok(CertificateMetadata {
        subject: cert.subject.clone(),
        issuer: cert.issuer.clone(),
        not_before: cert.not_before,
        not_after: cert.not_after,
        key_usage: cert.key_usage.as_ref().map(key_usage_metadata),
        extended_key_usage: cert.extended_key_usage.clone().unwrap_or_default(),
        serial: cert.serial.clone(),
        signature_algorithm_oid: cert.signature_algorithm_oid.clone(),
    })
}

/// ---------------------------------------------------------------------------
/// Typed DER boundary → metadata
/// ---------------------------------------------------------------------------
///
/// Parse an owned DER certificate and extract metadata.
///
/// - No crypto verification
/// - No trust decisions
pub fn extract_certificate_metadata_der(
    cert: &X509CertificateDer,
) -> TrustApiResult<CertificateMetadata> {
    if cert.der.is_empty() || cert.der.len() > MAX_CERTIFICATE_DER_BYTES {
        return Err(TrustApiError::InvalidInput);
    }
    let x509: X509Certificate =
        parse_cert_der(&cert.der).map_err(|_| TrustApiError::InvalidInput)?;

    extract_certificate_metadata(&x509)
}

/// ---------------------------------------------------------------------------
/// Helpers
/// ---------------------------------------------------------------------------
/// Convert X.509 key usage to the package-owned typed projection.
fn key_usage_metadata(ku: &KeyUsage) -> KeyUsageMetadata {
    KeyUsageMetadata {
        digital_signature: ku.digital_signature,
        content_commitment: ku.content_commitment,
        key_encipherment: ku.key_encipherment,
        data_encipherment: ku.data_encipherment,
        key_cert_sign: ku.key_cert_sign,
        crl_sign: ku.crl_sign,
        key_agreement: ku.key_agreement,
        encipher_only: ku.encipher_only,
        decipher_only: ku.decipher_only,
    }
}

/// Parse a DER-encoded X.509 chain into typed metadata objects.
///
/// - NO validation
/// - NO trust
/// - NO crypto verification
///
/// Intended for inspection and user-facing metadata display.
pub fn parse_x509_chain_der(chain: &X509ChainDer) -> TrustApiResult<Vec<CertificateMetadata>> {
    if chain.certs.is_empty() || chain.certs.len() > MAX_X509_CHAIN_CERTIFICATES {
        return Err(TrustApiError::InvalidInput);
    }

    let mut out = Vec::with_capacity(chain.certs.len());

    for cert in &chain.certs {
        if cert.der.is_empty() || cert.der.len() > MAX_CERTIFICATE_DER_BYTES {
            return Err(TrustApiError::InvalidInput);
        }
        let x509: X509Certificate =
            parse_cert_der(&cert.der).map_err(|_| TrustApiError::InvalidInput)?;

        let meta = crate::x509::extract_certificate_metadata(&x509)?;
        out.push(meta);
    }

    Ok(out)
}
