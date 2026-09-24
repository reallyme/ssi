// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_revocation_ocsp_core::{OcspCertStatus, OcspError, ParsedOcspResponse};

use openssl::hash::MessageDigest;
use openssl::ocsp::{
    OcspBasicResponseRef, OcspCertId, OcspCertStatus as OpenSslCertStatus, OcspFlag, OcspResponse,
    OcspResponseStatus,
};
use openssl::sha::sha1;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;

/// Parse an OCSP response (DER) using OpenSSL.
///
/// - Validates response status
/// - Builds RFC 6960 CertID (SHA-1)
/// - Extracts per-certificate OCSP status
pub fn parse_ocsp_response_der(
    der: &[u8],
    cert: &X509,
    issuer: &X509,
    extra_certs: &[X509],
    _now_unix: u64,
) -> Result<ParsedOcspResponse, OcspError> {
    // Decode response
    let resp = OcspResponse::from_der(der).map_err(|_| OcspError::InvalidResponse)?;

    // Check top-level response status
    if resp.status() != OcspResponseStatus::SUCCESSFUL {
        return Err(OcspError::InvalidResponse);
    }

    // Extract basic response
    let basic = resp.basic().map_err(|_| OcspError::InvalidResponse)?;

    // Verify signature + responder authorization against issuing CA.
    //
    // We treat the issuer as the trust anchor for responder authorization, which matches
    // the common "OCSP must chain to issuing CA" requirement.
    verify_basic_response(&basic, issuer, extra_certs)
        .map_err(|_| OcspError::UntrustedResponder)?;

    // Build CertID (RFC 6960 requires SHA-1)
    let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer)
        .map_err(|_| OcspError::InvalidResponse)?;

    // Find status entry
    let status = basic.find_status(&cert_id).ok_or(OcspError::Unavailable)?;

    // Map certificate status
    let mapped_status = match status.status {
        OpenSslCertStatus::GOOD => OcspCertStatus::Good,
        OpenSslCertStatus::REVOKED => OcspCertStatus::Revoked,
        OpenSslCertStatus::UNKNOWN => OcspCertStatus::Unknown,
        _ => OcspCertStatus::Unknown,
    };

    // Issuer key identifier for matching with leaf's AuthorityKeyIdentifier.
    //
    // Prefer SubjectKeyIdentifier extension when present, otherwise fall back to the
    // common SHA-1(public key DER) construction to avoid rejecting otherwise-valid chains.
    let issuer_key = issuer_key_identifier(issuer)?;

    // Extract serial
    let serial = cert
        .serial_number()
        .to_bn()
        .map_err(|_| OcspError::InvalidResponse)?
        .to_vec();

    // Parse timestamps (GeneralizedTime → unix)
    let this_update =
        parse_generalized_time(status.this_update).ok_or(OcspError::InvalidResponse)?;

    let next_update = status.next_update().and_then(parse_generalized_time);
    if let Some(next) = next_update {
        if next < this_update {
            return Err(OcspError::InvalidResponse);
        }
    }

    Ok(ParsedOcspResponse {
        issuer_key,
        serial,
        status: mapped_status,
        this_update,
        next_update,
        signature_valid: Some(true),
        responder_authorized: Some(true),
        responder_eku_ocsp_signing: Some(true),
        extensions: None,
    })
}

/// Convert ASN.1 GeneralizedTime → unix seconds.
///
/// OpenSSL exposes generalized time through a stable, normalized display form.
fn parse_generalized_time(t: &openssl::asn1::Asn1GeneralizedTimeRef) -> Option<u64> {
    // Parsing OpenSSL's normalized display avoids depending on a foreign-types
    // ABI version solely to access an internal ASN.1 pointer. The display form
    // is `Mon D HH:MM:SS YYYY GMT`; every component remains strictly checked.
    let displayed = t.to_string();
    let mut parts = displayed.split_ascii_whitespace();
    let month = parse_openssl_month(parts.next()?)?;
    let day = parts.next()?.parse::<u8>().ok()?;
    let mut clock = parts.next()?.split(':');
    let hour = clock.next()?.parse::<u8>().ok()?;
    let minute = clock.next()?.parse::<u8>().ok()?;
    let second = clock.next()?.parse::<u8>().ok()?;
    if clock.next().is_some() {
        return None;
    }
    let year = parts.next()?.parse::<i32>().ok()?;
    if parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }

    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let time = time::Time::from_hms(hour, minute, second).ok()?;
    u64::try_from(date.with_time(time).assume_utc().unix_timestamp()).ok()
}

const fn parse_openssl_month(value: &str) -> Option<time::Month> {
    match value.as_bytes() {
        b"Jan" => Some(time::Month::January),
        b"Feb" => Some(time::Month::February),
        b"Mar" => Some(time::Month::March),
        b"Apr" => Some(time::Month::April),
        b"May" => Some(time::Month::May),
        b"Jun" => Some(time::Month::June),
        b"Jul" => Some(time::Month::July),
        b"Aug" => Some(time::Month::August),
        b"Sep" => Some(time::Month::September),
        b"Oct" => Some(time::Month::October),
        b"Nov" => Some(time::Month::November),
        b"Dec" => Some(time::Month::December),
        _ => None,
    }
}

fn issuer_key_identifier(issuer: &X509) -> Result<Vec<u8>, OcspError> {
    if let Some(ski) = issuer.subject_key_id() {
        return Ok(ski.as_slice().to_vec());
    }

    let pkey = issuer
        .public_key()
        .map_err(|_| OcspError::InvalidResponse)?;
    let pk_der = pkey
        .public_key_to_der()
        .map_err(|_| OcspError::InvalidResponse)?;

    Ok(sha1(&pk_der).to_vec())
}

fn verify_basic_response(
    basic: &OcspBasicResponseRef,
    issuer: &X509,
    extra_certs: &[X509],
) -> Result<(), openssl::error::ErrorStack> {
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(issuer.to_owned())?;
    for c in extra_certs {
        store.add_cert(c.to_owned())?;
    }
    let store = store.build();

    let mut certs = Stack::new()?;
    // Help OpenSSL locate the signer: include issuer and any provided intermediates.
    certs.push(issuer.to_owned())?;
    for c in extra_certs {
        certs.push(c.to_owned())?;
    }

    basic.verify(&certs, &store, OcspFlag::empty())
}
