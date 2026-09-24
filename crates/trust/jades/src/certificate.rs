// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::{
    parse_cert_der, parse_subject_public_key_info_der, SubjectPublicKeyAlgorithm,
    SubjectPublicKeyInfo, X509Certificate, MAX_X509_CERTIFICATE_DER_BYTES,
    MAX_X509_CHAIN_CERTIFICATES,
};
use reallyme_codec::{
    base64::{base64_to_bytes, bytes_to_base64},
    base64url::base64url_to_bytes,
};
use reallyme_crypto::{core::HashAlgorithm, operations::hash::digest};
use zeroize::Zeroizing;

use crate::header::{DigestReferenceJson, ProtectedHeader};
use crate::{JadesError, JadesErrorReason, JadesSignatureAlgorithm, JadesVerificationKey};

const MAX_X5C_BASE64_BYTES: usize = 87_384;
const SHA256_DIGEST_BYTES: usize = 32;

pub(crate) fn resolve_presented_certificates(
    header: &ProtectedHeader,
    supplied: &[X509Certificate],
) -> Result<Vec<X509Certificate>, JadesError> {
    if supplied.len() > MAX_X509_CHAIN_CERTIFICATES {
        return Err(JadesError::new(JadesErrorReason::ResourceLimit));
    }

    let Some(encoded_chain) = header.x5c.as_ref() else {
        if supplied.is_empty() {
            return Err(JadesError::new(JadesErrorReason::InvalidSigningCertificate));
        }
        return reparse_supplied_certificates(supplied);
    };

    if encoded_chain.is_empty() || encoded_chain.len() > MAX_X509_CHAIN_CERTIFICATES {
        return Err(JadesError::new(JadesErrorReason::ResourceLimit));
    }

    let mut parsed = Vec::new();
    parsed
        .try_reserve_exact(encoded_chain.len())
        .map_err(|_| JadesError::new(JadesErrorReason::ResourceLimit))?;
    for encoded in encoded_chain {
        if encoded.is_empty() || encoded.len() > MAX_X5C_BASE64_BYTES {
            return Err(JadesError::new(JadesErrorReason::ResourceLimit));
        }
        let der = Zeroizing::new(
            base64_to_bytes(encoded)
                .map_err(|_| JadesError::new(JadesErrorReason::InvalidCertificateReference))?,
        );
        // RFC 7515 §4.1.6 uses the RFC 4648 base64 alphabet. Re-encoding
        // rejects whitespace, missing padding, and other non-canonical forms
        // before any certificate identity comparison is made.
        if bytes_to_base64(der.as_slice()) != *encoded {
            return Err(JadesError::new(
                JadesErrorReason::InvalidCertificateReference,
            ));
        }
        if der.len() > MAX_X509_CERTIFICATE_DER_BYTES {
            return Err(JadesError::new(JadesErrorReason::ResourceLimit));
        }
        parsed.push(
            parse_cert_der(der.as_slice())
                .map_err(|_| JadesError::new(JadesErrorReason::InvalidSigningCertificate))?,
        );
    }

    if !supplied.is_empty()
        && (supplied.len() != parsed.len()
            || supplied
                .iter()
                .zip(parsed.iter())
                .any(|(left, right)| left.der != right.der))
    {
        return Err(JadesError::new(
            JadesErrorReason::SigningCertificateMismatch,
        ));
    }

    Ok(parsed)
}

fn reparse_supplied_certificates(
    supplied: &[X509Certificate],
) -> Result<Vec<X509Certificate>, JadesError> {
    let mut reparsed = Vec::new();
    reparsed
        .try_reserve_exact(supplied.len())
        .map_err(|_| JadesError::new(JadesErrorReason::ResourceLimit))?;
    for certificate in supplied {
        if certificate.der.is_empty() || certificate.der.len() > MAX_X509_CERTIFICATE_DER_BYTES {
            return Err(JadesError::new(JadesErrorReason::ResourceLimit));
        }
        // X.509 projections are deliberately public across the trust stack.
        // RFC 5280 policy must nevertheless be evaluated over fields parsed
        // from the exact DER bound by the protected JAdES certificate
        // identifier, never over caller-mutated convenience projections.
        reparsed.push(
            parse_cert_der(certificate.der.as_slice())
                .map_err(|_| JadesError::new(JadesErrorReason::InvalidSigningCertificate))?,
        );
    }
    Ok(reparsed)
}

pub(crate) fn validate_certificate_references(
    header: &ProtectedHeader,
    certificates: &[X509Certificate],
) -> Result<(), JadesError> {
    if !header.has_certificate_reference() {
        return Err(JadesError::new(
            JadesErrorReason::MissingSigningCertificateReference,
        ));
    }
    let leaf = certificates
        .first()
        .ok_or_else(|| JadesError::new(JadesErrorReason::InvalidSigningCertificate))?;

    if let Some(encoded) = header.x5t_s256.as_deref() {
        let expected = decode_reference_value(encoded)?;
        if expected.len() != SHA256_DIGEST_BYTES
            || expected.as_slice() != sha256(leaf.der.as_slice()).as_slice()
        {
            return Err(JadesError::new(
                JadesErrorReason::SigningCertificateMismatch,
            ));
        }
    }

    if let Some(reference) = header.x5t_o.as_ref() {
        if reference.algorithm == "sha-256" {
            return Err(JadesError::new(
                JadesErrorReason::InvalidCertificateReference,
            ));
        }
        validate_digest_reference(reference, leaf, false)?;
    }

    if let Some(references) = header.sig_x5ts.as_ref() {
        if references.len() < 2 || references.len() > certificates.len() {
            return Err(JadesError::new(
                JadesErrorReason::InvalidCertificateReference,
            ));
        }

        // TS 119 182-1 v1.2.1 clause 5.2.2.3 requires the first sigX5ts
        // entry to identify the signer, while later entries may identify a
        // subset of certificates in the certification path. Match every
        // later digest to one distinct supplied path certificate; requiring
        // the array to cover the whole path would reject conforming input.
        validate_digest_reference(&references[0], &certificates[0], true)?;
        let mut matched = [false; MAX_X509_CHAIN_CERTIFICATES];
        matched[0] = true;
        for reference in references.iter().skip(1) {
            let mut matched_index = None;
            for (index, certificate) in certificates.iter().enumerate().skip(1) {
                if !matched[index] && digest_reference_matches(reference, certificate, true)? {
                    if matched_index.is_some() {
                        return Err(JadesError::new(
                            JadesErrorReason::InvalidCertificateReference,
                        ));
                    }
                    matched_index = Some(index);
                }
            }
            let index = matched_index
                .ok_or_else(|| JadesError::new(JadesErrorReason::SigningCertificateMismatch))?;
            matched[index] = true;
        }
    }

    Ok(())
}

pub(crate) fn verification_key(
    certificate: &X509Certificate,
    algorithm: JadesSignatureAlgorithm,
) -> Result<SubjectPublicKeyInfo, JadesError> {
    let key = parse_subject_public_key_info_der(certificate.spki_der.as_slice())
        .map_err(|_| JadesError::new(JadesErrorReason::InvalidSigningCertificate))?;
    let matches = matches!(
        (algorithm, key.algorithm),
        (
            JadesSignatureAlgorithm::Es256,
            SubjectPublicKeyAlgorithm::P256
        ) | (
            JadesSignatureAlgorithm::EdDsa,
            SubjectPublicKeyAlgorithm::Ed25519
        )
    );
    if !matches {
        return Err(JadesError::new(JadesErrorReason::InvalidSigningCertificate));
    }
    Ok(key)
}

pub(crate) fn borrowed_verification_key(
    key: &SubjectPublicKeyInfo,
) -> Result<JadesVerificationKey<'_>, JadesError> {
    match key.algorithm {
        SubjectPublicKeyAlgorithm::P256 => Ok(JadesVerificationKey::P256Sec1(&key.public_key)),
        SubjectPublicKeyAlgorithm::Ed25519 => Ok(JadesVerificationKey::Ed25519(&key.public_key)),
        _ => Err(JadesError::new(JadesErrorReason::InvalidSigningCertificate)),
    }
}

fn validate_digest_reference(
    reference: &DigestReferenceJson,
    certificate: &X509Certificate,
    allow_sha256: bool,
) -> Result<(), JadesError> {
    if !digest_reference_matches(reference, certificate, allow_sha256)? {
        return Err(JadesError::new(
            JadesErrorReason::SigningCertificateMismatch,
        ));
    }
    Ok(())
}

fn digest_reference_matches(
    reference: &DigestReferenceJson,
    certificate: &X509Certificate,
    allow_sha256: bool,
) -> Result<bool, JadesError> {
    let algorithm = parse_digest_algorithm(reference.algorithm.as_str(), allow_sha256)?;
    let expected = decode_reference_value(reference.value.as_str())?;
    let actual = Zeroizing::new(
        digest(algorithm, certificate.der.as_slice())
            .map_err(|_| JadesError::new(JadesErrorReason::UnsupportedDigestAlgorithm))?,
    );
    Ok(expected.as_slice() == actual.as_slice())
}

fn parse_digest_algorithm(value: &str, allow_sha256: bool) -> Result<HashAlgorithm, JadesError> {
    let algorithm = match value {
        "sha-256" if allow_sha256 => HashAlgorithm::Sha2_256,
        "sha-384" => HashAlgorithm::Sha2_384,
        "sha-512" => HashAlgorithm::Sha2_512,
        "sha3-256" => HashAlgorithm::Sha3_256,
        "sha3-384" => HashAlgorithm::Sha3_384,
        "sha3-512" => HashAlgorithm::Sha3_512,
        _ => {
            return Err(JadesError::new(
                JadesErrorReason::UnsupportedDigestAlgorithm,
            ));
        }
    };
    Ok(algorithm)
}

fn decode_reference_value(value: &str) -> Result<Zeroizing<Vec<u8>>, JadesError> {
    let decoded = base64url_to_bytes(value)
        .map_err(|_| JadesError::new(JadesErrorReason::InvalidCertificateReference))?;
    Ok(Zeroizing::new(decoded))
}

fn sha256(value: &[u8]) -> [u8; SHA256_DIGEST_BYTES] {
    *reallyme_crypto::sha2::digest(value).as_bytes()
}
