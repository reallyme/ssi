// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
}

/// Validate an ES256 issuerAuth using its RFC 9360 certificate path.
///
/// The resolver is responsible for certificate parsing, path validation,
/// document-signer profile policy, and returning the leaf P-256 public key.
pub fn validate_x5chain_issuer_auth(
    issuer_auth: &[u8],
    trust_resolver: impl FnOnce(&[Vec<u8>]) -> Option<Vec<u8>>,
) -> Result<ValidatedX5ChainIssuerAuth, MdocEnvelopeError> {
    let policy = CosePolicy::new().allow_cose_algorithm(CoseSignatureAlgorithm::Es256);
    let verified = cose_verify1_with_x5chain(issuer_auth, &policy, |algorithm, certificates| {
        (algorithm == Algorithm::P256)
            .then(|| trust_resolver(certificates))
            .flatten()
    })
    .map_err(|_| MdocEnvelopeError::InvalidSignature)?;
    Ok(ValidatedX5ChainIssuerAuth {
        payload: verified.payload,
        x5chain_der: verified.x5chain_der,
    })
}
