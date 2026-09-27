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
    validate_https_url, validate_issuer_identifier, validate_optional_string_list,
    validate_public_https_url, MAX_JSON_BYTES,
};

#[path = "metadata_transport.rs"]
mod transport;
pub use transport::{
    fetch_authorization_server_metadata, fetch_authorization_server_metadata_with_policy,
    MetadataAddressPolicy, MetadataConnectionEvidence, MetadataFetchRequest, MetadataFetchResponse,
    MetadataFetcher,
};

fn validate_metadata_issuer(
    issuer: &str,
    address_policy: MetadataAddressPolicy,
) -> OauthResult<()> {
    match address_policy {
        MetadataAddressPolicy::PublicInternet => validate_issuer_identifier(issuer),
        MetadataAddressPolicy::LoopbackOnly => {
            validate_https_url(issuer, false)?;
            let parsed =
                url::Url::parse(issuer).map_err(|_| OauthError::new(Reason::InvalidUrl))?;
            if parsed.query().is_some() || parsed.fragment().is_some() {
                return Err(OauthError::new(Reason::InvalidUrl));
            }
            Ok(())
        }
    }
}

/// OAuth Authorization Server Metadata.
#[derive(PartialEq, Eq, Serialize)]
#[non_exhaustive]
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
    /// Authorization-server JSON Web Key Set URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
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

#[derive(Deserialize)]
struct AuthorizationServerMetadataWire {
    issuer: String,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    pushed_authorization_request_endpoint: Option<String>,
    challenge_endpoint: Option<String>,
    jwks_uri: Option<String>,
    grant_types_supported: Option<Vec<GrantType>>,
    response_types_supported: Option<Vec<String>>,
    code_challenge_methods_supported: Option<Vec<String>>,
    dpop_signing_alg_values_supported: Option<Vec<String>>,
    require_pushed_authorization_requests: Option<bool>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    authorization_response_iss_parameter_supported: Option<bool>,
    client_attestation_signing_alg_values_supported: Option<Vec<String>>,
    client_attestation_pop_signing_alg_values_supported: Option<Vec<String>>,
}

impl From<AuthorizationServerMetadataWire> for AuthorizationServerMetadata {
    fn from(wire: AuthorizationServerMetadataWire) -> Self {
        Self {
            issuer: wire.issuer,
            authorization_endpoint: wire.authorization_endpoint,
            token_endpoint: wire.token_endpoint,
            pushed_authorization_request_endpoint: wire.pushed_authorization_request_endpoint,
            challenge_endpoint: wire.challenge_endpoint,
            jwks_uri: wire.jwks_uri,
            grant_types_supported: wire.grant_types_supported,
            response_types_supported: wire.response_types_supported,
            code_challenge_methods_supported: wire.code_challenge_methods_supported,
            dpop_signing_alg_values_supported: wire.dpop_signing_alg_values_supported,
            require_pushed_authorization_requests: wire.require_pushed_authorization_requests,
            token_endpoint_auth_methods_supported: wire.token_endpoint_auth_methods_supported,
            authorization_response_iss_parameter_supported: wire
                .authorization_response_iss_parameter_supported,
            client_attestation_signing_alg_values_supported: wire
                .client_attestation_signing_alg_values_supported,
            client_attestation_pop_signing_alg_values_supported: wire
                .client_attestation_pop_signing_alg_values_supported,
        }
    }
}

impl<'de> Deserialize<'de> for AuthorizationServerMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AuthorizationServerMetadataWire::deserialize(deserializer)?;
        let metadata = Self::from(wire);
        metadata
            .validate()
            .map_err(|_| serde::de::Error::custom("invalid authorization server metadata"))?;
        Ok(metadata)
    }
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
        zeroize_option(&mut self.jwks_uri);
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
    /// Creates metadata for an issuer with all optional capabilities absent.
    pub fn new(issuer: String) -> OauthResult<Self> {
        let metadata = Self {
            issuer,
            authorization_endpoint: None,
            token_endpoint: None,
            pushed_authorization_request_endpoint: None,
            challenge_endpoint: None,
            jwks_uri: None,
            grant_types_supported: None,
            response_types_supported: None,
            code_challenge_methods_supported: None,
            dpop_signing_alg_values_supported: None,
            require_pushed_authorization_requests: None,
            token_endpoint_auth_methods_supported: None,
            authorization_response_iss_parameter_supported: None,
            client_attestation_signing_alg_values_supported: None,
            client_attestation_pop_signing_alg_values_supported: None,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Parses and validates metadata JSON.
    pub fn parse_json(body: &str) -> OauthResult<Self> {
        Self::parse_json_with_address_policy(body, MetadataAddressPolicy::PublicInternet)
    }

    fn parse_json_with_address_policy(
        body: &str,
        address_policy: MetadataAddressPolicy,
    ) -> OauthResult<Self> {
        if body.len() > MAX_JSON_BYTES {
            return Err(OauthError::new(Reason::InvalidJson));
        }
        validate_strict_json(body.as_bytes())?;
        // Parse the wire shape directly so domain-validation failures retain
        // their stable reason instead of being flattened into a serde error.
        let wire: AuthorizationServerMetadataWire =
            serde_json::from_str(body).map_err(|_| OauthError::new(Reason::InvalidJson))?;
        let metadata = Self::from(wire);
        metadata.validate_with_address_policy(address_policy)?;
        Ok(metadata)
    }

    /// Serializes validated metadata JSON.
    pub fn to_json(&self) -> OauthResult<String> {
        self.validate()?;
        serde_json::to_string(self).map_err(|_| OauthError::new(Reason::InvalidJson))
    }

    /// Validates RFC 8414 metadata plus PAR/DPoP/PKCE extensions used here.
    pub fn validate(&self) -> OauthResult<()> {
        self.validate_with_address_policy(MetadataAddressPolicy::PublicInternet)
    }

    fn validate_with_address_policy(
        &self,
        address_policy: MetadataAddressPolicy,
    ) -> OauthResult<()> {
        validate_metadata_issuer(&self.issuer, address_policy)?;
        for endpoint in [
            self.authorization_endpoint.as_deref(),
            self.token_endpoint.as_deref(),
            self.pushed_authorization_request_endpoint.as_deref(),
            self.challenge_endpoint.as_deref(),
            self.jwks_uri.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_metadata_endpoint(endpoint, &self.issuer, address_policy)?;
        }
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
        Ok(())
    }
}

fn validate_metadata_endpoint(
    endpoint: &str,
    issuer: &str,
    address_policy: MetadataAddressPolicy,
) -> OauthResult<()> {
    if address_policy == MetadataAddressPolicy::PublicInternet {
        return validate_public_https_url(endpoint);
    }
    validate_https_url(endpoint, false)?;
    let endpoint_url =
        url::Url::parse(endpoint).map_err(|_| OauthError::new(Reason::InvalidUrl))?;
    let issuer_url = url::Url::parse(issuer).map_err(|_| OauthError::new(Reason::InvalidUrl))?;
    // The exceptional local lane must not turn metadata validation into a
    // general private-network URL allowlist. Endpoint ports may legitimately
    // differ, but the authenticated issuer hostname remains the boundary.
    if endpoint_url.host_str() != issuer_url.host_str() {
        return Err(OauthError::new(Reason::InvalidUrl));
    }
    Ok(())
}
