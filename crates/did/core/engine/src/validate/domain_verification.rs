// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_types::DomainVerification;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;
use zeroize::Zeroizing;

/// Domain verification failures exposed by the core validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DomainVerificationError {
    /// DNS verification was requested but the DID document omitted its DNS binding.
    #[error("dns binding missing")]
    MissingDnsBinding,

    /// Well-known verification was requested but the DID document omitted its well-known binding.
    #[error("well-known binding missing")]
    MissingWellKnownBinding,

    /// DNS verification was requested without a DNS TXT resolver.
    #[error("dns resolver not provided")]
    ResolveTxtUnavailable,

    /// Well-known verification was requested without an HTTP body fetcher.
    #[error("well-known fetcher not provided")]
    FetchUrlUnavailable,

    /// The caller-supplied DNS TXT resolver failed.
    #[error("dns resolver failed")]
    ResolveTxtFailed,

    /// The caller-supplied HTTP body fetcher failed.
    #[error("well-known fetcher failed")]
    FetchUrlFailed,

    /// Caller-supplied domain responses did not include DNS TXT data for the requested domain.
    #[error("dns response missing")]
    MissingDnsResponse,

    /// Caller-supplied domain responses did not include the requested well-known body.
    #[error("well-known response missing")]
    MissingWellKnownResponse,

    /// The well-known body was not valid JSON.
    #[error("well-known body is not valid json")]
    InvalidWellKnownJson,

    /// The well-known binding was not an absolute path or HTTPS URL.
    #[error("well-known binding uri is invalid")]
    InvalidWellKnownUri,

    /// The DID document requested a domain-verification method this engine does not support.
    #[error("unsupported domain verification method")]
    UnsupportedMethod,

    /// The claimed domain is not a canonical lowercase DNS host name.
    #[error("domain is not a valid dns host name")]
    InvalidDomain,

    /// The binding is not bound to the DID or uses a non-standard record or path.
    #[error("domain binding is not bound to the did")]
    BindingMismatch,
}

impl From<DomainVerificationError> for IdentityCoreErrorReason {
    fn from(error: DomainVerificationError) -> Self {
        match error {
            DomainVerificationError::MissingDnsBinding
            | DomainVerificationError::MissingWellKnownBinding
            | DomainVerificationError::MissingDnsResponse
            | DomainVerificationError::MissingWellKnownResponse => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOMAIN
            }
            DomainVerificationError::ResolveTxtUnavailable
            | DomainVerificationError::FetchUrlUnavailable
            | DomainVerificationError::ResolveTxtFailed
            | DomainVerificationError::FetchUrlFailed => {
                Self::IDENTITY_CORE_ERROR_REASON_BACKEND_UNAVAILABLE
            }
            DomainVerificationError::InvalidWellKnownJson => {
                Self::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING
            }
            DomainVerificationError::InvalidWellKnownUri => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOMAIN
            }
            DomainVerificationError::UnsupportedMethod => {
                Self::IDENTITY_CORE_ERROR_REASON_UNSUPPORTED_FORMAT
            }
            DomainVerificationError::InvalidDomain | DomainVerificationError::BindingMismatch => {
                Self::IDENTITY_CORE_ERROR_REASON_DID_INVALID_DOMAIN
            }
        }
    }
}

/// Caller-supplied DNS TXT resolver used by domain verification.
pub type ResolveTxtFn<'a> = dyn Fn(&str) -> Result<Vec<String>, DomainVerificationError> + 'a;

/// Caller-supplied HTTP fetcher used by well-known domain verification.
pub type FetchUrlFn<'a> = dyn Fn(&str) -> Result<String, DomainVerificationError> + 'a;

/// Environment for domain verification.
/// External resolution is injected by the caller.
pub struct DomainVerificationEnv<'a> {
    /// Resolve DNS TXT records for a domain
    pub resolve_txt: Option<&'a ResolveTxtFn<'a>>,

    /// Fetch a remote URL and return raw text
    pub fetch_url: Option<&'a FetchUrlFn<'a>>,
}

/// Minimal document view required for verification
pub struct DidDocumentViewForDV<'a> {
    /// DID Document id expected by the domain binding.
    pub id: &'a str,
}

/// DNS TXT record label that carries a did:me domain binding.
pub const DID_DNS_RECORD_NAME: &str = "_did";

/// Well-known path that carries a did:me domain binding.
pub const DID_WELL_KNOWN_PATH: &str = "/.well-known/did-configuration.json";

const MAX_DOMAIN_LEN: usize = 253;
const MAX_DOMAIN_LABEL_LEN: usize = 63;

/// Validate *one* DomainVerification entry.
/// May perform I/O via injected callbacks.
///
/// The claimed domain must be a canonical lowercase DNS host name and the
/// binding must name this DID. Only fixed, derived targets are dereferenced:
/// the DNS TXT record `_did.{domain}` and the URL
/// `https://{domain}/.well-known/did-configuration.json`. Nothing is fetched
/// for an entry that fails these checks.
pub fn validate_domain_entry(
    dv: &DomainVerification,
    doc: &DidDocumentViewForDV<'_>,
    env: &DomainVerificationEnv<'_>,
) -> Result<bool, DomainVerificationError> {
    if !is_valid_dns_host_name(&dv.domain) {
        return Err(DomainVerificationError::InvalidDomain);
    }

    match dv.method.as_str() {
        // ------------------------------------------------------------
        // DNS TXT verification
        // ------------------------------------------------------------
        "dns" => {
            let dns = dv
                .dns
                .as_ref()
                .ok_or(DomainVerificationError::MissingDnsBinding)?;

            if dns.record_name != DID_DNS_RECORD_NAME || dns.txt_value != doc.id {
                return Err(DomainVerificationError::BindingMismatch);
            }

            let resolve = env
                .resolve_txt
                .ok_or(DomainVerificationError::ResolveTxtUnavailable)?;

            let record_name = Zeroizing::new(format!("{DID_DNS_RECORD_NAME}.{}", dv.domain));
            let records = Zeroizing::new(resolve(&record_name)?);
            Ok(records.iter().any(|r| r.trim() == dns.txt_value))
        }

        // ------------------------------------------------------------
        // HTTPS well-known verification
        // ------------------------------------------------------------
        "wellknown" => {
            let wk = dv
                .wellknown
                .as_ref()
                .ok_or(DomainVerificationError::MissingWellKnownBinding)?;

            if wk.uri != DID_WELL_KNOWN_PATH {
                return Err(DomainVerificationError::InvalidWellKnownUri);
            }
            if wk.content != doc.id {
                return Err(DomainVerificationError::BindingMismatch);
            }

            // DIF Domain Linkage requires a signed Domain Linkage Credential.
            // Treating an unsigned JSON object as equivalent creates a false
            // authentication signal, so this legacy method fails closed until
            // a proof-suite verifier is injected at this boundary.
            let _unused_fetcher = env.fetch_url;
            Err(DomainVerificationError::UnsupportedMethod)
        }

        _ => Err(DomainVerificationError::UnsupportedMethod),
    }
}

/// Return true for a canonical lowercase, fully qualified ASCII DNS host name.
///
/// IP literals, single-label names, trailing dots, uppercase, and any URL
/// syntax (ports, paths, userinfo) are rejected so a domain claim cannot
/// redirect a verification lookup to an unintended target.
#[must_use]
pub fn is_valid_dns_host_name(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
        return false;
    }

    let mut label_count = 0usize;
    let mut last_label = "";
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > MAX_DOMAIN_LABEL_LEN
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return false;
        }
        label_count = label_count.saturating_add(1);
        last_label = label;
    }

    // A numeric final label would make the name an IPv4-like literal.
    label_count >= 2 && !last_label.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
#[path = "domain_verification_proto_error_tests.rs"]
mod proto_error_tests;
