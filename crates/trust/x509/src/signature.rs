// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::{
    p256::{compress_public_key, verify_p256_der_prehash},
    rsa::{verify_rsa_pkcs1v15, RsaHash, RsaPublicKeyDerEncoding},
};
use x509_parser::prelude::FromDer;

use crate::{
    X509Chain, X509Error, X509ResourceLimit, X509SignatureFailure, MAX_X509_CHAIN_CERTIFICATES,
};

const OID_SHA256_WITH_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.11";
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";

pub struct PureRustSignatureVerifier;

impl PureRustSignatureVerifier {
    pub const fn new() -> Self {
        Self
    }

    pub fn verify_chain(&self, chain: &X509Chain) -> Result<(), X509Error> {
        verify_chain_signatures_pure_rust(chain)
    }
}

impl Default for PureRustSignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

pub fn verify_chain_signatures_pure_rust(chain: &X509Chain) -> Result<(), X509Error> {
    if chain.certs.len() > MAX_X509_CHAIN_CERTIFICATES {
        return Err(X509Error::ResourceLimitExceeded(
            X509ResourceLimit::CertificateChainTooLong,
        ));
    }

    if chain.certs.len() < 2 {
        return Err(X509Error::SignatureFailed(
            X509SignatureFailure::ChainTooShort,
        ));
    }

    for pair in chain.certs.windows(2) {
        let child = pair.first().ok_or(X509Error::SignatureFailed(
            X509SignatureFailure::BackendFailure,
        ))?;
        let issuer = pair.get(1).ok_or(X509Error::SignatureFailed(
            X509SignatureFailure::BackendFailure,
        ))?;
        if child.issuer != issuer.subject {
            return Err(X509Error::SignatureFailed(
                X509SignatureFailure::ChainIssuerMismatch,
            ));
        }
        verify_child_signed_by_issuer(child.der.as_slice(), issuer.der.as_slice())?;
    }

    Ok(())
}

fn verify_child_signed_by_issuer(child_der: &[u8], issuer_der: &[u8]) -> Result<(), X509Error> {
    let (_, child) = x509_parser::prelude::X509Certificate::from_der(child_der)
        .map_err(|_| X509Error::SignatureFailed(X509SignatureFailure::BackendFailure))?;
    let (_, issuer) = x509_parser::prelude::X509Certificate::from_der(issuer_der)
        .map_err(|_| X509Error::SignatureFailed(X509SignatureFailure::BackendFailure))?;
    let issuer_spki = issuer.public_key();
    let tbs = child.tbs_certificate.as_ref();
    let signature = child.signature_value.data;

    match child.signature_algorithm.algorithm.to_id_string().as_str() {
        OID_SHA256_WITH_RSA_ENCRYPTION => verify_rsa_pkcs1v15(
            issuer_spki.raw,
            RsaPublicKeyDerEncoding::Spki,
            RsaHash::Sha256,
            tbs,
            signature.as_ref(),
        )
        .map_err(|_| X509Error::SignatureFailed(X509SignatureFailure::InvalidSignature)),
        OID_ECDSA_WITH_SHA256 => {
            let public_key = issuer_spki.subject_public_key.data.as_ref();
            // Validate the SEC1 point separately so malformed issuer keys remain
            // distinguishable from an otherwise well-formed invalid signature.
            compress_public_key(public_key)
                .map_err(|_| X509Error::SignatureFailed(X509SignatureFailure::BackendFailure))?;
            verify_p256_der_prehash(signature.as_ref(), tbs, public_key)
                .map_err(|_| X509Error::SignatureFailed(X509SignatureFailure::InvalidSignature))
        }
        _ => Err(X509Error::SignatureFailed(
            X509SignatureFailure::UnsupportedAlgorithm,
        )),
    }
}
