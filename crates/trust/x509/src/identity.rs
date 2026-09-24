// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded certificate identity projection for trusted-list consumers.

use asn1_rs::FromDer;
use sha1::{Digest, Sha1};
use x509_parser::extensions::ParsedExtension;
use x509_parser::nom::Parser;
use x509_parser::prelude::X509CertificateParser;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{X509Error, X509ResourceLimit, MAX_X509_CERTIFICATE_DER_BYTES};

const DERIVED_SUBJECT_KEY_IDENTIFIER_BYTES: usize = 20;

/// Certificate facts needed to prove equivalent ETSI TSL key representations.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CertificateIdentityFacts {
    pub subject_public_key_info_der: Vec<u8>,
    pub subject_key_identifier: Option<Vec<u8>>,
    pub derived_subject_key_identifier: [u8; DERIVED_SUBJECT_KEY_IDENTIFIER_BYTES],
    pub organization_identifiers: Vec<String>,
    pub certificate_authority: bool,
    pub rsa_modulus: Option<Vec<u8>>,
    pub rsa_exponent: Option<Vec<u8>>,
    pub dsa_p: Option<Vec<u8>>,
    pub dsa_q: Option<Vec<u8>>,
    pub dsa_g: Option<Vec<u8>>,
    pub dsa_y: Option<Vec<u8>>,
    pub ec_curve_oid: Option<String>,
    pub ec_public_key: Option<Vec<u8>>,
}

impl core::fmt::Debug for CertificateIdentityFacts {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CertificateIdentityFacts")
            .field("certificate_authority", &self.certificate_authority)
            .field("values", &"<redacted>")
            .finish()
    }
}

struct DsaPublicKeyParameters {
    p: Vec<u8>,
    q: Vec<u8>,
    g: Vec<u8>,
}

/// Parse one complete DER certificate into the identity facts used by TSL.
pub fn certificate_identity_facts(
    certificate_der: &[u8],
) -> Result<CertificateIdentityFacts, X509Error> {
    if certificate_der.len() > MAX_X509_CERTIFICATE_DER_BYTES {
        return Err(X509Error::ResourceLimitExceeded(
            X509ResourceLimit::CertificateDerTooLarge,
        ));
    }
    if certificate_der.is_empty() {
        return Err(X509Error::InvalidDer);
    }
    let (remaining, certificate) = X509CertificateParser::new()
        .parse(certificate_der)
        .map_err(|_| X509Error::InvalidDer)?;
    if !remaining.is_empty() {
        return Err(X509Error::InvalidDer);
    }

    let mut subject_key_identifier = None;
    for extension in certificate.extensions() {
        if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension() {
            if subject_key_identifier.is_some() || identifier.0.is_empty() {
                return Err(X509Error::InvalidDer);
            }
            subject_key_identifier = Some(identifier.0.to_vec());
        }
    }

    let organization_identifier_oid =
        asn1_rs::Oid::from(&[2, 5, 4, 97]).map_err(|_| X509Error::InvalidDer)?;
    let organization_identifiers = certificate
        .subject()
        .iter_by_oid(&organization_identifier_oid)
        .map(|attribute| {
            attribute
                .as_str()
                .map(str::to_owned)
                .map_err(|_| X509Error::InvalidDer)
        })
        .collect::<Result<Vec<_>, X509Error>>()?;
    // XMLDSig X509SKI names the extension. Some deployed lists instead carry
    // RFC 5280 method-1 SHA-1 over subjectPublicKey bits when the extension is
    // absent. This compatibility identifier never authorizes a signature.
    let derived_subject_key_identifier =
        Sha1::digest(certificate.public_key().subject_public_key.data.as_ref()).into();
    let (rsa_modulus, rsa_exponent, dsa_p, dsa_q, dsa_g, dsa_y, ec_curve_oid, ec_public_key) =
        match certificate.public_key().parsed() {
            Ok(PublicKey::RSA(key)) => (
                Some(key.modulus.to_vec()),
                Some(key.exponent.to_vec()),
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            Ok(PublicKey::DSA(y)) => {
                let parameters = parse_dsa_parameters(certificate.public_key())?;
                (
                    None,
                    None,
                    Some(parameters.p),
                    Some(parameters.q),
                    Some(parameters.g),
                    Some(y.to_vec()),
                    None,
                    None,
                )
            }
            Ok(PublicKey::EC(key)) => {
                let parameters = certificate
                    .public_key()
                    .algorithm
                    .parameters
                    .as_ref()
                    .ok_or(X509Error::InvalidDer)?;
                let curve = asn1_rs::Oid::try_from(parameters.clone())
                    .map_err(|_| X509Error::InvalidDer)?;
                (
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(curve.to_id_string()),
                    Some(key.data().to_vec()),
                )
            }
            Ok(_) | Err(_) => (None, None, None, None, None, None, None, None),
        };

    Ok(CertificateIdentityFacts {
        subject_public_key_info_der: certificate.public_key().raw.to_vec(),
        subject_key_identifier,
        derived_subject_key_identifier,
        organization_identifiers,
        certificate_authority: certificate.is_ca(),
        rsa_modulus,
        rsa_exponent,
        dsa_p,
        dsa_q,
        dsa_g,
        dsa_y,
        ec_curve_oid,
        ec_public_key,
    })
}

fn parse_dsa_parameters(
    subject_public_key_info: &SubjectPublicKeyInfo<'_>,
) -> Result<DsaPublicKeyParameters, X509Error> {
    let parameters = subject_public_key_info
        .algorithm
        .parameters()
        .ok_or(X509Error::InvalidDer)?;
    let sequence = parameters
        .as_sequence()
        .map_err(|_| X509Error::InvalidDer)?;
    let (remaining, p) = parse_positive_der_integer(sequence.content.as_ref())?;
    let (remaining, q) = parse_positive_der_integer(remaining)?;
    let (remaining, g) = parse_positive_der_integer(remaining)?;
    if !remaining.is_empty() {
        return Err(X509Error::InvalidDer);
    }
    Ok(DsaPublicKeyParameters { p, q, g })
}

fn parse_positive_der_integer(input: &[u8]) -> Result<(&[u8], Vec<u8>), X509Error> {
    let (remaining, value) = asn1_rs::Any::from_der(input).map_err(|_| X509Error::InvalidDer)?;
    let integer = value.as_integer().map_err(|_| X509Error::InvalidDer)?;
    let bytes = integer.as_ref();
    if bytes.is_empty() || bytes.first().is_some_and(|first| first & 0x80 != 0) {
        return Err(X509Error::InvalidDer);
    }
    Ok((remaining, bytes.to_vec()))
}
