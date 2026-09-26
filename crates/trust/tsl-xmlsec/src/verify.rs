// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signer-bound XMLSec verification for the ETSI trusted-list profile.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{XmlSecError, XmlSecPolicyViolationReason};

mod profile;
mod validate_trusted_roots;

pub use validate_trusted_roots::{
    MAX_TSL_XMLSEC_TRUSTED_ROOTS, MAX_TSL_XMLSEC_TRUSTED_ROOT_DER_BYTES,
};

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
///
/// `trusted_roots_der` carries DER certificates; every entry is loaded as a
/// trust anchor for XMLSec path validation. At least one and at most
/// [`MAX_TSL_XMLSEC_TRUSTED_ROOTS`] roots are accepted, each at most
/// [`MAX_TSL_XMLSEC_TRUSTED_ROOT_DER_BYTES`] bytes.
pub fn verify_tsl_xmldsig_xmlsec(
    xml: &str,
    trusted_roots_der: &[&[u8]],
    verification_time: time::OffsetDateTime,
) -> Result<VerifiedXmlSignature, XmlSecError> {
    verify_tsl_xmldsig_xmlsec_impl(xml, trusted_roots_der, verification_time, false)
}

/// Verify one strict ETSI TSL signature against a set of exactly pinned leaf signers.
///
/// XMLSec is allowed to treat the signing end-entity certificate as the
/// terminal trust point only for this entry point. The profile pre-pass and the
/// native verification each run once; verification succeeds only when the
/// backend-selected signer is byte-identical to one of `expected_signers_der`.
/// An empty candidate list, or a signer that matches no candidate, returns
/// [`XmlSecPolicyViolationReason::SignerBindingMismatch`].
pub fn verify_tsl_xmldsig_xmlsec_with_exact_signers(
    xml: &str,
    trusted_roots_der: &[&[u8]],
    verification_time: time::OffsetDateTime,
    expected_signers_der: &[&[u8]],
) -> Result<VerifiedXmlSignature, XmlSecError> {
    validate_trusted_roots::validate_trusted_roots(trusted_roots_der)?;
    if expected_signers_der.is_empty() {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::SignerBindingMismatch,
        ));
    }
    let verified = verify_tsl_xmldsig_xmlsec_impl(xml, trusted_roots_der, verification_time, true)?;
    if !expected_signers_der
        .iter()
        .any(|expected| *expected == verified.signer_certificate_der())
    {
        return Err(XmlSecError::PolicyViolation(
            XmlSecPolicyViolationReason::SignerBindingMismatch,
        ));
    }
    Ok(verified)
}

fn verify_tsl_xmldsig_xmlsec_impl(
    xml: &str,
    trusted_roots_der: &[&[u8]],
    verification_time: time::OffsetDateTime,
    allow_trusted_leaf: bool,
) -> Result<VerifiedXmlSignature, XmlSecError> {
    validate_trusted_roots::validate_trusted_roots(trusted_roots_der)?;
    let mut signature_profile = profile::enforce_signature_profile(xml)?;
    let signer_certificate_der = profile::verify_xmlsec_backend(
        xml,
        trusted_roots_der,
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
