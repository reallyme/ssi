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

/// Validate *one* DomainVerification entry.
/// May perform I/O via injected callbacks.
pub fn validate_domain_entry(
    dv: &DomainVerification,
    _doc: &DidDocumentViewForDV<'_>,
    env: &DomainVerificationEnv<'_>,
) -> Result<bool, DomainVerificationError> {
    match dv.method.as_str() {
        // ------------------------------------------------------------
        // DNS TXT verification
        // ------------------------------------------------------------
        "dns" => {
            let dns = dv
                .dns
                .as_ref()
                .ok_or(DomainVerificationError::MissingDnsBinding)?;

            let resolve = env
                .resolve_txt
                .ok_or(DomainVerificationError::ResolveTxtUnavailable)?;

            let records = Zeroizing::new(resolve(&dv.domain)?);
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

            let fetch = env
                .fetch_url
                .ok_or(DomainVerificationError::FetchUrlUnavailable)?;

            // For did:me, `wk.uri` is typically a path.
            // The actual fetch target must include the domain.
            let url = Zeroizing::new(if wk.uri.starts_with("https://") {
                wk.uri.clone()
            } else if wk.uri.starts_with('/') {
                format!("https://{}{}", dv.domain, wk.uri)
            } else {
                return Err(DomainVerificationError::InvalidWellKnownUri);
            });

            let body = Zeroizing::new(fetch(&url)?);
            let json: serde_json::Value = serde_json::from_str(&body)
                .map_err(|_| DomainVerificationError::InvalidWellKnownJson)?;

            if json.get("domain").and_then(|v| v.as_str()) != Some(&dv.domain) {
                return Ok(false);
            }

            if json.get("did").and_then(|v| v.as_str()) != Some(&wk.content) {
                return Ok(false);
            }

            Ok(true)
        }

        _ => Err(DomainVerificationError::UnsupportedMethod),
    }
}

#[cfg(test)]
#[path = "domain_verification_proto_error_tests.rs"]
mod proto_error_tests;
