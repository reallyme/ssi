// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signer-bound XMLSec verification for the ETSI trusted-list profile.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{XmlSecError, XmlSecPolicyViolationReason};

mod profile;

/// Authenticated XML SignatureMethod admitted by the TS 119 612 profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum TslXmlSignatureAlgorithm {
    /// RSA PKCS#1 v1.5 with SHA-256.
    RsaSha256,
    /// RSA PKCS#1 v1.5 with SHA-384.
    RsaSha384,
    /// RSA PKCS#1 v1.5 with SHA-512.
    RsaSha512,
    /// RSASSA-PSS with SHA-256 and MGF1-SHA-256.
    RsaPssSha256,
    /// RSASSA-PSS with SHA-384 and MGF1-SHA-384.
    RsaPssSha384,
    /// RSASSA-PSS with SHA-512 and MGF1-SHA-512.
    RsaPssSha512,
    /// ECDSA with SHA-256.
    EcdsaSha256,
    /// ECDSA with SHA-384.
    EcdsaSha384,
    /// ECDSA with SHA-512.
    EcdsaSha512,
}

/// Cryptographic result binding the verified XML signature to the exact
/// certificate selected by xmlsec and the certificates carried by its KeyInfo.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VerifiedXmlSignature {
    signer_certificate_der: Vec<u8>,
    key_info_certificates_der: Vec<Vec<u8>>,
    signature_algorithm: TslXmlSignatureAlgorithm,
}

impl core::fmt::Debug for VerifiedXmlSignature {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedXmlSignature")
            .field("signer_certificate_der", &"<redacted>")
            .field("key_info_certificates_der", &"<redacted>")
            .finish()
    }
}

impl VerifiedXmlSignature {
    /// DER of the certificate whose public key verified `SignatureValue`.
    pub fn signer_certificate_der(&self) -> &[u8] {
        &self.signer_certificate_der
    }

    /// Certificates embedded in the verified signature's own KeyInfo.
    pub fn key_info_certificates_der(&self) -> &[Vec<u8>] {
        &self.key_info_certificates_der
    }

    /// Returns the authenticated `ds:SignatureMethod` selected by the profile.
    #[must_use]
    pub const fn signature_algorithm(&self) -> TslXmlSignatureAlgorithm {
        self.signature_algorithm
    }
}

/// Verify one strict ETSI TSL enveloped signature and return signer-bound evidence.
///
/// The structural pass follows the XML Signature 1.1 processing model but uses
/// a deliberately narrower profile: one direct-child signature, exactly one
/// reference to the unique TSL document root (by exact ID or the standard
/// empty-document URI), exactly one reference to the required SignedProperties
/// element, a DataObjectFormat classification for every signed data reference,
/// strong algorithms, and X509Data without key indirection. This makes the
/// backend-selected key unambiguous and prevents a caller from independently
/// selecting an unrelated certificate from the XML.
pub fn verify_tsl_xmldsig_xmlsec(
    xml: &str,
    trusted_pem_path: &str,
    verification_time: time::OffsetDateTime,
) -> Result<VerifiedXmlSignature, XmlSecError> {
    verify_tsl_xmldsig_xmlsec_impl(xml, trusted_pem_path, verification_time, false)
}

/// Verify one strict ETSI TSL signature against an exactly pinned leaf signer.
///
/// XMLSec is allowed to treat the configured end-entity certificate as the
/// terminal trust point only for this entry point. Verification succeeds only
/// when the backend-selected signer exactly matches `expected_signer_der`.
pub fn verify_tsl_xmldsig_xmlsec_with_exact_signer(
    xml: &str,
    trusted_pem_path: &str,
    verification_time: time::OffsetDateTime,
    expected_signer_der: &[u8],
) -> Result<VerifiedXmlSignature, XmlSecError> {
    let verified = verify_tsl_xmldsig_xmlsec_impl(xml, trusted_pem_path, verification_time, true)?;
    if verified.signer_certificate_der() != expected_signer_der {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::SignerBindingMismatch,
        ));
    }
    Ok(verified)
}

fn verify_tsl_xmldsig_xmlsec_impl(
    xml: &str,
    trusted_pem_path: &str,
    verification_time: time::OffsetDateTime,
    allow_trusted_leaf: bool,
) -> Result<VerifiedXmlSignature, XmlSecError> {
    let mut signature_profile = profile::enforce_signature_profile(xml)?;
    let signer_certificate_der = profile::verify_xmlsec_backend(
        xml,
        trusted_pem_path,
        verification_time.unix_timestamp(),
        allow_trusted_leaf,
    )?;
    if !signature_profile
        .key_info_certificates_der
        .iter()
        .any(|certificate| certificate == &signer_certificate_der)
    {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::SignerBindingMismatch,
        ));
    }
    profile::verify_signing_certificate_v2(&signature_profile, &signer_certificate_der)?;

    Ok(VerifiedXmlSignature {
        signer_certificate_der,
        key_info_certificates_der: core::mem::take(
            &mut signature_profile.key_info_certificates_der,
        ),
        signature_algorithm: signature_profile.signature_algorithm.ok_or(
            XmlSecError::PolicyViolation(XmlSecPolicyViolationReason::UnsupportedAlgorithm),
        )?,
    })
}
