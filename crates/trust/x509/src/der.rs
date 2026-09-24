// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded DER projections for consumers that must not own an X.509 parser.

use x509_parser::prelude::FromDer;

use crate::X509Error;

const MAX_DER_INPUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SubjectPublicKeyAlgorithm {
    Ed25519,
    X25519,
    P256,
    Secp256k1,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    MlKem768,
    MlKem1024,
    Unsupported,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: SubjectPublicKeyAlgorithm,
    pub public_key: Vec<u8>,
}

#[must_use]
pub fn validate_x509_name_der(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > MAX_DER_INPUT_BYTES {
        return false;
    }
    x509_parser::x509::X509Name::from_der(value).is_ok_and(|(remaining, _)| remaining.is_empty())
}

#[must_use]
pub fn validate_certificate_der(value: &[u8]) -> bool {
    parse_certificate(value).is_ok()
}

pub fn parse_subject_public_key_info_der(value: &[u8]) -> Result<SubjectPublicKeyInfo, X509Error> {
    if value.is_empty() || value.len() > MAX_DER_INPUT_BYTES {
        return Err(X509Error::InvalidDer);
    }
    let (remaining, value) = x509_parser::x509::SubjectPublicKeyInfo::from_der(value)
        .map_err(|_| X509Error::InvalidDer)?;
    if !remaining.is_empty() {
        return Err(X509Error::InvalidDer);
    }
    Ok(project_subject_public_key_info(&value))
}

pub fn certificate_subject_public_key_info(
    value: &[u8],
) -> Result<SubjectPublicKeyInfo, X509Error> {
    let certificate = parse_certificate(value)?;
    Ok(project_subject_public_key_info(certificate.public_key()))
}

fn parse_certificate(
    value: &[u8],
) -> Result<x509_parser::certificate::X509Certificate<'_>, X509Error> {
    if value.is_empty() || value.len() > MAX_DER_INPUT_BYTES {
        return Err(X509Error::InvalidDer);
    }
    let (remaining, certificate) = x509_parser::certificate::X509Certificate::from_der(value)
        .map_err(|_| X509Error::InvalidDer)?;
    if !remaining.is_empty() {
        return Err(X509Error::InvalidDer);
    }
    Ok(certificate)
}

fn project_subject_public_key_info(
    value: &x509_parser::x509::SubjectPublicKeyInfo<'_>,
) -> SubjectPublicKeyInfo {
    let algorithm_oid = value.algorithm.algorithm.to_id_string();
    let parameter_oid = value
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameter| parameter.as_oid().ok())
        .map(|oid| oid.to_id_string());
    let algorithm = match (algorithm_oid.as_str(), parameter_oid.as_deref()) {
        ("1.3.101.112", _) => SubjectPublicKeyAlgorithm::Ed25519,
        ("1.3.101.110", _) => SubjectPublicKeyAlgorithm::X25519,
        ("1.2.840.10045.2.1", Some("1.2.840.10045.3.1.7")) => SubjectPublicKeyAlgorithm::P256,
        ("1.2.840.10045.2.1", Some("1.3.132.0.10")) => SubjectPublicKeyAlgorithm::Secp256k1,
        ("2.16.840.1.101.3.4.3.17", _) => SubjectPublicKeyAlgorithm::MlDsa44,
        ("2.16.840.1.101.3.4.3.18", _) => SubjectPublicKeyAlgorithm::MlDsa65,
        ("2.16.840.1.101.3.4.3.19", _) => SubjectPublicKeyAlgorithm::MlDsa87,
        ("2.16.840.1.101.3.4.4.2", _) => SubjectPublicKeyAlgorithm::MlKem768,
        ("2.16.840.1.101.3.4.4.3", _) => SubjectPublicKeyAlgorithm::MlKem1024,
        _ => SubjectPublicKeyAlgorithm::Unsupported,
    };
    SubjectPublicKeyInfo {
        algorithm,
        public_key: value.subject_public_key.data.to_vec(),
    }
}
