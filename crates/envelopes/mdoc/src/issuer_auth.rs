// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;

use crate::MdocEnvelopeError;
use reallyme_cose::{
    cose_sign1, cose_sign1_with_signature_algorithm_and_external_aad, cose_verify1,
    cose_verify1_with_x5chain, Algorithm, CosePolicy, CoseSign1EncodeOptions,
    CoseSignatureAlgorithm,
};
use zeroize::Zeroizing;

/// Signs issuerAuth COSE_Sign1 payloads.
pub trait IssuerAuthSigner {
    /// Sign canonical MobileSecurityObject CBOR bytes.
    fn sign_issuer_auth(&self, mso_cbor: &[u8]) -> Result<Vec<u8>, MdocEnvelopeError>;
}

/// IssuerAuth signer backed by `reallyme-cose`.
pub struct CoseIssuerAuthSigner<'a> {
    /// COSE/crypto algorithm to use for issuerAuth.
    pub alg: Algorithm,

    /// Issuer private key bytes accepted by the selected ReallyMe Crypto lane.
    pub private_key: &'a [u8],

    /// COSE key identifier written into the protected header.
    pub kid: Option<&'a [u8]>,
}

impl IssuerAuthSigner for CoseIssuerAuthSigner<'_> {
    fn sign_issuer_auth(&self, mso_cbor: &[u8]) -> Result<Vec<u8>, MdocEnvelopeError> {
        cose_sign1(self.alg, mso_cbor, self.private_key, self.kid)
            .map(|signed| signed.to_vec())
            .map_err(|_| MdocEnvelopeError::Signing)
    }
}

/// IssuerAuth signer with an exact COSE algorithm and RFC 9360 certificate path.
///
/// This adapter is intended for raw-key fixtures and software-backed providers.
/// Deployments with non-exportable keys should implement [`IssuerAuthSigner`]
/// over their HSM or platform provider while preserving the same exact
/// algorithm and leaf-first certificate-path policy.
pub struct CoseX5ChainIssuerAuthSigner<'a> {
    /// Exact COSE signature algorithm written into the protected header.
    pub algorithm: CoseSignatureAlgorithm,

    /// Issuer private key bytes accepted by the selected ReallyMe Crypto lane.
    pub private_key: &'a [u8],

    /// Optional COSE key identifier written into the protected header.
    pub kid: Option<&'a [u8]>,

    /// RFC 9360 leaf-first certificate path, excluding the trust anchor.
    pub x5chain_der: &'a [Vec<u8>],
}

impl IssuerAuthSigner for CoseX5ChainIssuerAuthSigner<'_> {
    fn sign_issuer_auth(&self, mso_cbor: &[u8]) -> Result<Vec<u8>, MdocEnvelopeError> {
        if self.x5chain_der.is_empty() {
            return Err(MdocEnvelopeError::Signing);
        }
        let options = CoseSign1EncodeOptions::new().with_x5chain_der(self.x5chain_der.to_vec());
        cose_sign1_with_signature_algorithm_and_external_aad(
            self.algorithm,
            mso_cbor,
            self.private_key,
            self.kid,
            &[],
            options,
        )
        .map(|signed| signed.to_vec())
        .map_err(|_| MdocEnvelopeError::Signing)
    }
}

/// Validate issuerAuth and return the signed MobileSecurityObject payload.
pub fn validate_issuer_auth(
    issuer_auth: &[u8],
    issuer_public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, MdocEnvelopeError> {
    cose_verify1(issuer_auth, issuer_public_key_resolver)
        .map(|payload| payload.to_vec())
        .map_err(|_| MdocEnvelopeError::InvalidSignature)
}

/// Verified issuerAuth payload and leaf-first RFC 9360 certificate path.
#[must_use]
pub struct ValidatedX5ChainIssuerAuth {
    /// Verified tagged MobileSecurityObject payload.
    pub payload: Zeroizing<Vec<u8>>,
    /// Bounded certificate path authenticated by the supplied trust resolver.
    pub x5chain_der: Vec<Vec<u8>>,
    /// Inclusive certificate validity start selected by the trust resolver.
    pub certificate_not_before_unix: u64,
    /// Inclusive certificate validity end selected by the trust resolver.
    pub certificate_not_after_unix: u64,
}

/// Trust-resolver output bound to a document-signer path validated at the
/// supplied MSO signing time.
pub struct MdocCertificatePathValidation {
    /// P-256 document-signer public key bytes.
    pub public_key: Vec<u8>,
    /// Inclusive certificate validity start as Unix seconds.
    pub not_before_unix: u64,
    /// Inclusive certificate validity end as Unix seconds.
    pub not_after_unix: u64,
}

/// Validate an ES256 issuerAuth using its RFC 9360 certificate path.
///
/// The resolver is responsible for certificate parsing, path validation,
/// document-signer profile policy, and returning the leaf P-256 public key. It
/// receives the MSO signing time so certificate validity can be evaluated when
/// the document was signed rather than when it is presented. The time is read
/// before signature verification, but this function accepts the result only
/// after the same payload and timestamp have been authenticated.
pub fn validate_x5chain_issuer_auth(
    issuer_auth: &[u8],
    trust_resolver: impl FnOnce(&[Vec<u8>], u64) -> Option<MdocCertificatePathValidation>,
) -> Result<ValidatedX5ChainIssuerAuth, MdocEnvelopeError> {
    let mso_signing_time_unix = unverified_mso_signing_time(issuer_auth)?;
    let policy = CosePolicy::new().allow_cose_algorithm(CoseSignatureAlgorithm::Es256);
    let mut certificate_window = None;
    let verified = cose_verify1_with_x5chain(issuer_auth, &policy, |algorithm, certificates| {
        if algorithm != Algorithm::P256 {
            return None;
        }
        let validated = trust_resolver(certificates, mso_signing_time_unix)?;
        if validated.not_before_unix > validated.not_after_unix {
            return None;
        }
        certificate_window = Some((validated.not_before_unix, validated.not_after_unix));
        Some(validated.public_key)
    })
    .map_err(|_| MdocEnvelopeError::InvalidSignature)?;
    let authenticated_mso = crate::cbor::decode_mso_cbor(&verified.payload)?;
    if authenticated_mso.validity_info.signed != mso_signing_time_unix {
        return Err(MdocEnvelopeError::InvalidSignature);
    }
    // The certificate callback needs the unverified signing time to choose a
    // path, but only the authenticated MSO may determine semantic validity.
    // Validate its intrinsic window before applying certificate-time policy so
    // malformed signed data retains the stable, domain-specific error.
    crate::validity::validate_validity_window(&authenticated_mso.validity_info)?;
    let (certificate_not_before_unix, certificate_not_after_unix) =
        certificate_window.ok_or(MdocEnvelopeError::InvalidSignature)?;
    if mso_signing_time_unix < certificate_not_before_unix
        || mso_signing_time_unix > certificate_not_after_unix
    {
        return Err(MdocEnvelopeError::InvalidSignature);
    }
    Ok(ValidatedX5ChainIssuerAuth {
        payload: verified.payload,
        x5chain_der: verified.x5chain_der,
        certificate_not_before_unix,
        certificate_not_after_unix,
    })
}

fn unverified_mso_signing_time(issuer_auth: &[u8]) -> Result<u64, MdocEnvelopeError> {
    let issuer_auth = crate::cbor::cbor_bytes_to_value(issuer_auth)
        .map_err(|_| MdocEnvelopeError::InvalidSignature)?;
    let body = match issuer_auth.as_value() {
        Value::Tag(18, body) => body.as_ref(),
        value => value,
    };
    let Value::Array(fields) = body else {
        return Err(MdocEnvelopeError::InvalidSignature);
    };
    let [_, _, Value::Bytes(payload), _] = fields.as_slice() else {
        return Err(MdocEnvelopeError::InvalidSignature);
    };
    let mso =
        crate::cbor::decode_mso_cbor(payload).map_err(|_| MdocEnvelopeError::InvalidSignature)?;
    Ok(mso.validity_info.signed)
}
