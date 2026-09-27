// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::parse_cert_der;
use identity_revocation_ocsp_core::{
    bind_response_to_certificates_with_nonce, OcspCertStatus, OcspError, ParsedOcspResponse,
    UnverifiedOcspResponse,
};

use openssl::hash::MessageDigest;
use openssl::ocsp::{
    OcspBasicResponseRef, OcspCertId, OcspCertStatus as OpenSslCertStatus, OcspFlag, OcspResponse,
    OcspResponseStatus,
};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::X509;

use crate::cert_id_match::{
    response_nonce_for_request, unique_matching_digest, validated_response_produced_at,
    MatchingDigest,
};

const MAX_OCSP_RESPONSE_DER_BYTES: usize = 1_048_576;
const MAX_OCSP_EXTRA_CERTIFICATES: usize = 16;
const MAX_OCSP_PRODUCED_AT_FUTURE_SKEW_SECONDS: u64 = 300;
const OID_EKU_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

/// Parse an OCSP response (DER) using OpenSSL.
///
/// - Validates response status
/// - Verifies the response signature and responder chain at `now_unix`
/// - Selects exactly one SHA-256 or legacy SHA-1 RFC 6960 CertID
/// - Extracts per-certificate OCSP status
pub fn parse_ocsp_response_der(
    der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    extra_certs_der: &[Vec<u8>],
    now_unix: u64,
) -> Result<ParsedOcspResponse, OcspError> {
    if der.is_empty()
        || der.len() > MAX_OCSP_RESPONSE_DER_BYTES
        || extra_certs_der.len() > MAX_OCSP_EXTRA_CERTIFICATES
    {
        return Err(OcspError::InvalidResponse);
    }
    parse_ocsp_response_der_with_nonce(der, cert_der, issuer_der, extra_certs_der, now_unix, None)
}

/// Parse and verify an OCSP response and bind its signed nonce to the request.
pub fn parse_ocsp_response_der_with_nonce(
    der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    extra_certs_der: &[Vec<u8>],
    now_unix: u64,
    expected_nonce: Option<&[u8]>,
) -> Result<ParsedOcspResponse, OcspError> {
    let cert = X509::from_der(cert_der).map_err(|_| OcspError::InvalidResponse)?;
    let issuer = X509::from_der(issuer_der).map_err(|_| OcspError::InvalidResponse)?;
    let mut extra_certs = Vec::new();
    extra_certs
        .try_reserve_exact(extra_certs_der.len())
        .map_err(|_| OcspError::InvalidResponse)?;
    for extra_der in extra_certs_der {
        validate_delegated_responder_key_usage(extra_der)?;
        extra_certs.push(X509::from_der(extra_der).map_err(|_| OcspError::InvalidResponse)?);
    }
    // Decode response
    let resp = OcspResponse::from_der(der).map_err(|_| OcspError::InvalidResponse)?;

    // Check top-level response status
    if resp.status() != OcspResponseStatus::SUCCESSFUL {
        return Err(OcspError::InvalidResponse);
    }

    // Extract basic response
    let basic = resp.basic().map_err(|_| OcspError::InvalidResponse)?;

    // Select the matching entry before accepting any result. OpenSSL's
    // `find_status` returns the first match, so an explicit DER pass rejects
    // duplicate or conflicting SingleResponse values for the same certificate.
    let matching_digest = unique_matching_digest(der, cert_der, issuer_der)?;
    let produced_at = parse_der_generalized_time(validated_response_produced_at(der)?)
        .ok_or(OcspError::InvalidResponse)?;
    let latest_produced_at = now_unix
        .checked_add(MAX_OCSP_PRODUCED_AT_FUTURE_SKEW_SECONDS)
        .ok_or(OcspError::InvalidResponse)?;
    if produced_at > latest_produced_at {
        return Err(OcspError::InvalidResponse);
    }
    // A nonce is an optional, non-critical response extension. If the request
    // did not carry one, malformed nonce contents cannot weaken binding and
    // are ignored. Signature verification below still authenticates the
    // complete response.
    let response_nonce = response_nonce_for_request(der, expected_nonce.is_some())?;
    identity_revocation_ocsp_core::validate_response_nonce(
        response_nonce.as_deref(),
        expected_nonce,
    )?;

    // Responder authorization terminates at the issuing CA, so the issuer is
    // the trust anchor for this OCSP-specific path validation.
    verify_basic_response(&basic, &issuer, &extra_certs, now_unix)?;

    let digest = match matching_digest {
        MatchingDigest::Sha256 => MessageDigest::sha256(),
        MatchingDigest::Sha1 => MessageDigest::sha1(),
    };
    let cert_id =
        OcspCertId::from_cert(digest, &cert, &issuer).map_err(|_| OcspError::InvalidResponse)?;

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
    // Prefer SubjectKeyIdentifier when present. Otherwise bind to either RFC
    // 5280 key-identifier derivation used by the certificate's AKI.
    let issuer_projection = parse_cert_der(issuer_der).map_err(|_| OcspError::InvalidResponse)?;
    let cert_projection = parse_cert_der(cert_der).map_err(|_| OcspError::InvalidResponse)?;
    let computed_issuer_key = issuer_projection
        .rfc5280_method_one_key_identifier()
        .ok_or(OcspError::InvalidResponse)?;
    // Pool matching must use the key-derived RFC 5280 method-1 identifier,
    // never a self-asserted SKI extension. The exact leaf fingerprint below
    // additionally prevents a response parsed for one issuer/leaf pair from
    // being replayed against a different certificate with colliding metadata.
    let issuer_key = computed_issuer_key.to_vec();
    // Extract serial
    let serial = cert_projection.serial.clone();

    // Parse timestamps (GeneralizedTime → unix)
    let this_update =
        parse_generalized_time(status.this_update).ok_or(OcspError::InvalidResponse)?;

    // A present but unparseable nextUpdate must not be mistaken for an absent
    // one: absence can weaken freshness policy.
    let next_update = status
        .next_update()
        .map(|next| parse_generalized_time(next).ok_or(OcspError::InvalidResponse))
        .transpose()?;
    if let Some(next) = next_update {
        if next < this_update {
            return Err(OcspError::InvalidResponse);
        }
    }

    let projected = UnverifiedOcspResponse::new(
        issuer_key,
        serial,
        mapped_status,
        this_update,
        next_update,
        response_nonce,
        None,
    );
    bind_response_to_certificates_with_nonce(projected, cert_der, issuer_der, expected_nonce)
}

/// Convert ASN.1 GeneralizedTime → unix seconds.
///
/// OpenSSL exposes generalized time through a stable, normalized display form.
fn parse_generalized_time(t: &openssl::asn1::Asn1GeneralizedTimeRef) -> Option<u64> {
    // Parsing OpenSSL's normalized display avoids depending on a foreign-types
    // ABI version solely to access an internal ASN.1 pointer. The display form
    // is `Mon D HH:MM:SS[.fff] YYYY GMT`; every component remains strictly
    // checked. Fractional seconds (permitted by X.680 GeneralizedTime) are
    // truncated toward the enclosing whole second.
    let displayed = t.to_string();
    let mut parts = displayed.split_ascii_whitespace();
    let month = parse_openssl_month(parts.next()?)?;
    let day = parse_decimal_u8(parts.next()?)?;
    let mut clock = parts.next()?.split(':');
    let hour = parse_decimal_u8(clock.next()?)?;
    let minute = parse_decimal_u8(clock.next()?)?;
    let second = parse_seconds(clock.next()?)?;
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

fn parse_der_generalized_time(value: &[u8]) -> Option<u64> {
    let text = core::str::from_utf8(value).ok()?;
    let body = text.strip_suffix('Z')?;
    let (whole, fraction) = body
        .split_once('.')
        .map_or((body, None), |(whole, fraction)| (whole, Some(fraction)));
    if whole.len() != 14
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_some_and(|digits| {
            digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }
    let year = whole.get(0..4)?.parse::<i32>().ok()?;
    let month = time::Month::try_from(whole.get(4..6)?.parse::<u8>().ok()?).ok()?;
    let day = whole.get(6..8)?.parse::<u8>().ok()?;
    let hour = whole.get(8..10)?.parse::<u8>().ok()?;
    let minute = whole.get(10..12)?.parse::<u8>().ok()?;
    let second = whole.get(12..14)?.parse::<u8>().ok()?;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let time = time::Time::from_hms(hour, minute, second).ok()?;
    u64::try_from(date.with_time(time).assume_utc().unix_timestamp()).ok()
}

fn validate_delegated_responder_key_usage(cert_der: &[u8]) -> Result<(), OcspError> {
    let certificate = parse_cert_der(cert_der).map_err(|_| OcspError::InvalidResponse)?;
    let is_ocsp_responder = certificate
        .extended_key_usage
        .as_ref()
        .is_some_and(|purposes| {
            purposes
                .iter()
                .any(|purpose| purpose == OID_EKU_OCSP_SIGNING)
        });
    if is_ocsp_responder
        && certificate
            .key_usage
            .as_ref()
            .is_some_and(|usage| !usage.digital_signature)
    {
        return Err(OcspError::UntrustedResponder);
    }
    Ok(())
}

fn parse_decimal_u8(value: &str) -> Option<u8> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u8>().ok()
}

fn parse_seconds(value: &str) -> Option<u8> {
    match value.split_once('.') {
        Some((whole, fraction)) => {
            if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            parse_decimal_u8(whole)
        }
        None => parse_decimal_u8(value),
    }
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

fn verify_basic_response(
    basic: &OcspBasicResponseRef,
    issuer: &X509,
    extra_certs: &[X509],
    now_unix: u64,
) -> Result<(), OcspError> {
    // Responder chain validity is evaluated at the caller's verification time,
    // not the host wall clock, so historical and future checks are
    // deterministic and consistent with the portable freshness policy.
    let verification_time = now_unix
        .try_into()
        .map_err(|_| OcspError::InvalidResponse)?;
    let mut param = X509VerifyParam::new().map_err(|_| OcspError::UntrustedResponder)?;
    param.set_time(verification_time);
    // The caller-supplied issuing certificate is the deliberate trust
    // boundary even when it is an intermediate CA rather than a self-signed
    // root. PARTIAL_CHAIN makes that boundary explicit without promoting any
    // response-supplied certificate to a trust anchor.
    param
        .set_flags(X509VerifyFlags::PARTIAL_CHAIN)
        .map_err(|_| OcspError::UntrustedResponder)?;

    build_and_verify(basic, issuer, extra_certs, &param).map_err(|_| OcspError::UntrustedResponder)
}

fn build_and_verify(
    basic: &OcspBasicResponseRef,
    issuer: &X509,
    extra_certs: &[X509],
    param: &X509VerifyParam,
) -> Result<(), openssl::error::ErrorStack> {
    let mut store = X509StoreBuilder::new()?;
    store.set_param(param)?;
    store.add_cert(issuer.to_owned())?;
    let store = store.build();

    let mut certs = Stack::new()?;
    // Help OpenSSL locate the signer: include issuer and any provided intermediates.
    certs.push(issuer.to_owned())?;
    for c in extra_certs {
        certs.push(c.to_owned())?;
    }

    // Intermediates supplied alongside the response are untrusted chain
    // material. Only the configured issuer is a trust anchor, and
    // NOEXPLICIT prevents an unrelated explicitly trusted responder from
    // bypassing delegated-responder authorization checks.
    basic.verify(&certs, &store, OcspFlag::NO_EXPLICIT)
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;
