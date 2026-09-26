// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use asn1_rs::{Any, Class, FromDer, Tag};

use crate::{X509Error, X509SignatureFailure};

/// Context-specific tag number of the explicit TBSCertificate `version` field.
const TBS_VERSION_TAG: Tag = Tag(0);

/// Enforce RFC 5280 Section 4.1.1.2: the `signature` field inside
/// TBSCertificate must contain the same algorithm identifier as the outer
/// `signatureAlgorithm` field.
///
/// The comparison is over the exact DER encodings of both AlgorithmIdentifier
/// values, parameters included, so an issuer-signed identifier cannot differ
/// from the identifier the verifier dispatches on.
pub(super) fn require_matching_signature_algorithm_identifiers(
    certificate_der: &[u8],
) -> Result<(), X509Error> {
    let (tbs_identifier, outer_identifier) = signature_algorithm_identifiers(certificate_der)
        .ok_or(X509Error::SignatureFailed(
            X509SignatureFailure::BackendFailure,
        ))?;
    if tbs_identifier != outer_identifier {
        return Err(X509Error::SignatureFailed(
            X509SignatureFailure::AlgorithmIdentifierMismatch,
        ));
    }
    Ok(())
}

/// Return the raw DER of `(tbsCertificate.signature, signatureAlgorithm)`.
fn signature_algorithm_identifiers(certificate_der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (remaining, certificate) = Any::from_der(certificate_der).ok()?;
    if !remaining.is_empty() || certificate.header.tag() != Tag::Sequence {
        return None;
    }

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (tbs_der, after_tbs) = next_element(certificate.data)?;
    let (outer_identifier, _) = next_element(after_tbs)?;

    let (remaining, tbs) = Any::from_der(tbs_der).ok()?;
    if !remaining.is_empty() || tbs.header.tag() != Tag::Sequence {
        return None;
    }

    // TBSCertificate ::= SEQUENCE { [0] EXPLICIT version OPTIONAL,
    //                               serialNumber, signature, ... }
    let (first, after_first) = next_element(tbs.data)?;
    let after_serial = if is_explicit_version(first)? {
        let (_serial, after_serial) = next_element(after_first)?;
        after_serial
    } else {
        after_first
    };
    let (tbs_identifier, _) = next_element(after_serial)?;

    Some((tbs_identifier, outer_identifier))
}

/// Split one complete DER element from the front of `input`.
fn next_element(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (remaining, _) = Any::from_der(input).ok()?;
    let consumed = input.len().checked_sub(remaining.len())?;
    let element = input.get(..consumed)?;
    if element.is_empty() {
        return None;
    }
    Some((element, remaining))
}

fn is_explicit_version(element: &[u8]) -> Option<bool> {
    let (_, value) = Any::from_der(element).ok()?;
    Some(value.header.class() == Class::ContextSpecific && value.header.tag() == TBS_VERSION_TAG)
}
