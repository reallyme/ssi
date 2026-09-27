// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cmp::Ordering;

use openssl::x509::{X509Crl, X509};
use x509_parser::certificate::X509Certificate as ParsedX509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::time::ASN1Time;
use x509_parser::x509::ReasonCode;

use crate::inspect_extensions::{inspect_crl_extensions, inspect_entry_extensions};
use crate::parsed_crl::ParsedOpenSslCrl;
use crate::CrlError;

/// Maximum DER size accepted for one CRL.
pub const MAX_CRL_DER_BYTES: usize = 8 * 1024 * 1024;
/// Maximum PEM size accepted for one CRL.
pub const MAX_CRL_PEM_BYTES: usize = 12 * 1024 * 1024;
/// Maximum number of revoked-certificate entries accepted in one CRL.
pub const MAX_CRL_REVOKED_ENTRIES: usize = 262_144;

/// Parse CRL from DER bytes WITH issuer certificate (required).
pub fn parse_crl_der_with_env_issuer(
    der: &[u8],
    issuer_cert: X509,
) -> Result<ParsedOpenSslCrl, CrlError> {
    check_encoded_len(der.len(), MAX_CRL_DER_BYTES)?;
    parse_crl(der, issuer_cert)
}

/// Parse CRL from PEM bytes WITH issuer certificate (required).
pub fn parse_crl_pem_with_env_issuer(
    pem: &[u8],
    issuer_cert: X509,
) -> Result<ParsedOpenSslCrl, CrlError> {
    check_encoded_len(pem.len(), MAX_CRL_PEM_BYTES)?;
    let der = X509Crl::from_pem(pem)
        .and_then(|crl| crl.to_der())
        .map_err(|_| CrlError::InvalidCrl)?;
    check_encoded_len(der.len(), MAX_CRL_DER_BYTES)?;
    parse_crl(&der, issuer_cert)
}

fn check_encoded_len(len: usize, max: usize) -> Result<(), CrlError> {
    if len == 0 {
        return Err(CrlError::InvalidCrl);
    }
    if len > max {
        return Err(CrlError::TooLarge);
    }
    Ok(())
}

/// Internal shared CRL parser.
///
/// Performs, over one DER encoding:
/// - CRL signature verification and issuer-name binding
/// - issuer key extraction
/// - RFC 5280 Section 5.2/5.3 extension screening (delta, scoped, indirect,
///   and unrecognized critical extensions are rejected)
/// - mandatory `thisUpdate`/`nextUpdate` extraction
/// - bounded revoked serial extraction
fn parse_crl(der: &[u8], issuer_cert: X509) -> Result<ParsedOpenSslCrl, CrlError> {
    // Inspect and cap the CRL before asking a second parser to allocate its own
    // representation. This keeps a syntactically valid oversized entry set
    // from paying both parser costs before the resource boundary is applied.
    let (remaining, parsed) =
        CertificateRevocationList::from_der(der).map_err(|_| CrlError::InvalidCrl)?;
    if !remaining.is_empty() {
        return Err(CrlError::InvalidCrl);
    }
    let entry_count = parsed.iter_revoked_certificates().count();
    if entry_count > MAX_CRL_REVOKED_ENTRIES {
        return Err(CrlError::TooLarge);
    }
    inspect_crl_extensions(parsed.extensions())?;
    // Screen entry extensions before OpenSSL parses the same encoding. Some
    // OpenSSL releases reject certificateIssuer themselves, but doing this
    // first preserves our stable UnsupportedScope result across backends.
    for entry in parsed.iter_revoked_certificates() {
        inspect_entry_extensions(entry.extensions())?;
    }

    let issuer_der = issuer_cert.to_der().map_err(|_| CrlError::InvalidCrl)?;
    let (issuer_remaining, parsed_issuer) =
        ParsedX509Certificate::from_der(&issuer_der).map_err(|_| CrlError::InvalidCrl)?;
    let issuer_key_usage = parsed_issuer
        .key_usage()
        .map_err(|_| CrlError::InvalidCrl)?;
    let issuer_basic_constraints = parsed_issuer
        .basic_constraints()
        .map_err(|_| CrlError::InvalidCrl)?;
    // RFC 5280 §6.3 requires cRLSign when KeyUsage is present. Certificates
    // that omit the optional extension remain eligible; their CA profile and
    // signature are checked independently below.
    if !issuer_remaining.is_empty()
        || !issuer_basic_constraints.is_some_and(|constraints| constraints.value.ca)
        || issuer_key_usage.is_some_and(|usage| !usage.value.crl_sign())
    {
        return Err(CrlError::IssuerMismatch);
    }

    let crl = X509Crl::from_der(der).map_err(|_| CrlError::InvalidCrl)?;

    // ------------------------------------------------------------
    // 1) Verify CRL signature and bind the CRL issuer to the issuer cert
    // ------------------------------------------------------------
    let issuer_pubkey = issuer_cert.public_key().map_err(|_| CrlError::InvalidCrl)?;
    // `X509_CRL_verify` reports a mismatching signature as `Ok(false)`, so the
    // boolean must be checked explicitly.
    let signature_valid = crl
        .verify(&issuer_pubkey)
        .map_err(|_| CrlError::BadSignature)?;
    if !signature_valid {
        return Err(CrlError::BadSignature);
    }
    let issuer_matches = crl
        .issuer_name()
        .try_cmp(issuer_cert.subject_name())
        .map_err(|_| CrlError::InvalidCrl)?;
    if issuer_matches != Ordering::Equal {
        return Err(CrlError::IssuerMismatch);
    }

    // ------------------------------------------------------------
    // 2) Issuer key identifier (SKI required)
    // ------------------------------------------------------------
    let issuer_key = issuer_cert
        .subject_key_id()
        .ok_or(CrlError::InvalidCrl)?
        .as_slice()
        .to_vec();

    // ------------------------------------------------------------
    // 3) Structural inspection of the verified encoding
    // ------------------------------------------------------------
    let authority_key_identifier = parsed
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(identifier) => {
                identifier.key_identifier.as_ref()
            }
            _ => None,
        });
    if authority_key_identifier.is_some_and(|identifier| identifier.0 != issuer_key.as_slice()) {
        return Err(CrlError::IssuerMismatch);
    }

    // ------------------------------------------------------------
    // 4) Validity window: RFC 5280 Section 5.1.2.5 requires nextUpdate.
    // ------------------------------------------------------------
    let this_update_unix = unix_seconds(parsed.last_update())?;
    let next_update_unix = unix_seconds(parsed.next_update().ok_or(CrlError::InvalidTime)?)?;
    if next_update_unix < this_update_unix {
        return Err(CrlError::InvalidTime);
    }

    // ------------------------------------------------------------
    // 5) Revoked serials (bounded)
    // ------------------------------------------------------------
    let mut revoked_serials = Vec::with_capacity(entry_count);
    let mut suspended_serials = Vec::new();
    for entry in parsed.iter_revoked_certificates() {
        let serial = normalize_serial(entry.raw_serial()).to_vec();
        match entry.reason_code().map(|(_, reason)| reason) {
            Some(ReasonCode::CertificateHold) => suspended_serials.push(serial),
            // removeFromCRL is meaningful only in a delta CRL. This parser
            // deliberately accepts complete CRLs only, so treating it as a
            // revocation would invert the status transition.
            Some(ReasonCode::RemoveFromCRL) => return Err(CrlError::UnsupportedScope),
            _ => revoked_serials.push(serial),
        }
    }

    Ok(ParsedOpenSslCrl {
        issuer_key,
        _crl: crl,
        revoked_serials,
        suspended_serials,
        this_update_unix,
        next_update_unix,
        _issuer_cert: issuer_cert,
    })
}

fn unix_seconds(time: ASN1Time) -> Result<u64, CrlError> {
    u64::try_from(time.timestamp()).map_err(|_| CrlError::InvalidTime)
}

/// Normalize serial bytes (strip leading zero sign padding).
fn normalize_serial(serial: &[u8]) -> &[u8] {
    let start = serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(serial.len());
    serial.get(start..).unwrap_or_default()
}
