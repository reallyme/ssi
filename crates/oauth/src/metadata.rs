// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8414 Authorization Server metadata.

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{OauthError, OauthResult, Reason};
use crate::par::GrantType;
use crate::sensitive::{zeroize_option, zeroize_string_list};
use crate::strict_json::validate_strict_json;
use crate::validation::{
    validate_issuer_identifier, validate_optional_https_url, validate_optional_string_list,
    validate_token, MAX_JSON_BYTES,
};

/// Authorization Server metadata fetcher injected by HTTP adapters.
pub trait MetadataFetcher {
    /// Fetches metadata JSON from the RFC 8414 well-known URL for an issuer.
    fn fetch_metadata_json(&self, issuer: &str) -> OauthResult<String>;
}

/// Fetches and validates RFC 8414 Authorization Server metadata.
pub fn fetch_authorization_server_metadata(
    fetcher: &dyn MetadataFetcher,
    issuer: &str,
) -> OauthResult<AuthorizationServerMetadata> {
    validate_issuer_identifier(issuer)?;
    let body = fetcher.fetch_metadata_json(issuer)?;
    let metadata = AuthorizationServerMetadata::parse_json(&body)?;
    if metadata.issuer != issuer {
        return Err(OauthError::new(Reason::AuthorizationServerIssuerMismatch));
    }
    Ok(metadata)
}

/// OAuth Authorization Server Metadata.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// Authorization Server issuer identifier.
    pub issuer: String,
    /// Authorization endpoint URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    /// Token endpoint URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    /// RFC 9126 PAR endpoint URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
    /// Attestation-based client authentication challenge endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_endpoint: Option<String>,
    /// Supported grant types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<GrantType>>,
    /// Supported response types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types_supported: Option<Vec<String>>,
    /// Supported PKCE methods. OpenID4VCI accepts S256 only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    /// Supported DPoP proof signing algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// PAR requirement flag from RFC 9126 metadata extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,
    /// Supported token endpoint authentication methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// FAPI/OAuth metadata flag indicating authorization responses include `iss`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_response_iss_parameter_supported: Option<bool>,
    /// Supported wallet client attestation JWT signing algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_attestation_signing_alg_values_supported: Option<Vec<String>>,
    /// Supported wallet client attestation PoP JWT signing algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_attestation_pop_signing_alg_values_supported: Option<Vec<String>>,
}

impl fmt::Debug for AuthorizationServerMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationServerMetadata([REDACTED])")
    }
}

impl Zeroize for AuthorizationServerMetadata {
    fn zeroize(&mut self) {
        self.issuer.zeroize();
        zeroize_option(&mut self.authorization_endpoint);
        zeroize_option(&mut self.token_endpoint);
        zeroize_option(&mut self.pushed_authorization_request_endpoint);
        zeroize_option(&mut self.challenge_endpoint);
        self.grant_types_supported = None;
        zeroize_string_list(&mut self.response_types_supported);
        zeroize_string_list(&mut self.code_challenge_methods_supported);
        zeroize_string_list(&mut self.dpop_signing_alg_values_supported);
        zeroize_string_list(&mut self.token_endpoint_auth_methods_supported);
        zeroize_string_list(&mut self.client_attestation_signing_alg_values_supported);
        zeroize_string_list(&mut self.client_attestation_pop_signing_alg_values_supported);
    }
}

impl Drop for AuthorizationServerMetadata {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AuthorizationServerMetadata {}

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;

impl AuthorizationServerMetadata {
    /// Parses and validates metadata JSON.
    pub fn parse_json(body: &str) -> OauthResult<Self> {
        if body.len() > MAX_JSON_BYTES {
            return Err(OauthError::new(Reason::InvalidJson));
        }
        validate_strict_json(body.as_bytes())?;
        let metadata: Self =
            serde_json::from_str(body).map_err(|_| OauthError::new(Reason::InvalidJson))?;
        metadata.validate()?;
        Ok(metadata)
    }

    /// Serializes validated metadata JSON.
    pub fn to_json(&self) -> OauthResult<String> {
        self.validate()?;
        serde_json::to_string(self).map_err(|_| OauthError::new(Reason::InvalidJson))
    }

    /// Validates RFC 8414 metadata plus PAR/DPoP/PKCE extensions used here.
    pub fn validate(&self) -> OauthResult<()> {
        validate_issuer_identifier(&self.issuer)?;
        validate_optional_https_url(&self.authorization_endpoint)?;
        validate_optional_https_url(&self.token_endpoint)?;
        validate_optional_https_url(&self.pushed_authorization_request_endpoint)?;
        validate_optional_https_url(&self.challenge_endpoint)?;
        if let Some(grants) = &self.grant_types_supported {
            if grants.is_empty() {
                return Err(OauthError::new(Reason::MissingRequiredValue));
            }
        }
        validate_optional_string_list(&self.response_types_supported)?;
        validate_optional_string_list(&self.code_challenge_methods_supported)?;
        if let Some(methods) = &self.code_challenge_methods_supported {
            for method in methods {
                if method != "S256" {
                    return Err(OauthError::new(Reason::InvalidPkce));
                }
            }
        }
        validate_optional_string_list(&self.dpop_signing_alg_values_supported)?;
        validate_optional_string_list(&self.token_endpoint_auth_methods_supported)?;
        validate_optional_string_list(&self.client_attestation_signing_alg_values_supported)?;
        validate_optional_string_list(&self.client_attestation_pop_signing_alg_values_supported)?;
        if let Some(endpoint) = &self.pushed_authorization_request_endpoint {
            validate_token(endpoint)?;
        }
        Ok(())
    }
}
