// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9126 Pushed Authorization Request support.

use core::fmt;
use std::collections::BTreeMap;

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::attestation_client_auth::AttestationClientAuthentication;
use crate::error::{OauthError, OauthResult, Reason};
use crate::pkce::{CodeChallengeMethod, PkceChallenge};
use crate::sensitive::{zeroize_option, zeroize_string_map};
use crate::validation::{validate_https_url, validate_token};

const FORM_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');
const RESERVED_PAR_PARAMETERS: &[&str] = &[
    "client_id",
    "response_type",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "dpop_jkt",
    "request_uri",
];

/// OAuth grant type values relevant to OpenID4VCI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantType {
    /// OAuth Authorization Code grant.
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
    /// OAuth Refresh Token grant.
    #[serde(rename = "refresh_token")]
    RefreshToken,
    /// OpenID4VCI Pre-Authorized Code grant.
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode,
}

/// PAR request body as form parameters.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct ParRequest {
    /// OAuth client identifier.
    pub client_id: String,
    /// OAuth response type.
    pub response_type: String,
    /// Redirect URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// OAuth scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// CSRF state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// PKCE S256 challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkce: Option<PkceChallenge>,
    /// DPoP JWK thumbprint binding parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_jkt: Option<String>,
    /// Optional wallet attestation client authentication headers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_client_authentication: Option<AttestationClientAuthentication>,
    /// Extra authorization request parameters.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional_parameters: BTreeMap<String, String>,
}

impl fmt::Debug for ParRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParRequest([REDACTED])")
    }
}

impl Zeroize for ParRequest {
    fn zeroize(&mut self) {
        self.client_id.zeroize();
        self.response_type.zeroize();
        zeroize_option(&mut self.redirect_uri);
        zeroize_option(&mut self.scope);
        zeroize_option(&mut self.state);
        if let Some(pkce) = &mut self.pkce {
            pkce.zeroize();
        }
        self.pkce = None;
        zeroize_option(&mut self.dpop_jkt);
        if let Some(authentication) = &mut self.attestation_client_authentication {
            authentication.zeroize();
        }
        self.attestation_client_authentication = None;
        zeroize_string_map(&mut self.additional_parameters);
    }
}

impl Drop for ParRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ParRequest {}

impl ParRequest {
    /// Creates an authorization-code PAR request.
    pub fn authorization_code(
        client_id: String,
        redirect_uri: String,
        pkce: PkceChallenge,
    ) -> OauthResult<Self> {
        let request = Self {
            client_id,
            response_type: "code".to_owned(),
            redirect_uri: Some(redirect_uri),
            scope: None,
            state: None,
            pkce: Some(pkce),
            dpop_jkt: None,
            attestation_client_authentication: None,
            additional_parameters: BTreeMap::new(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates RFC 9126 and local OpenID4VCI PAR constraints.
    pub fn validate(&self) -> OauthResult<()> {
        validate_token(&self.client_id)?;
        validate_token(&self.response_type)?;
        if self.response_type == "code" && (self.redirect_uri.is_none() || self.pkce.is_none()) {
            return Err(OauthError::new(Reason::InvalidParRequest));
        }
        if let Some(redirect_uri) = &self.redirect_uri {
            validate_https_url(redirect_uri, false)?;
        }
        if let Some(scope) = &self.scope {
            validate_token(scope)?;
        }
        if let Some(state) = &self.state {
            validate_token(state)?;
        }
        if let Some(pkce) = &self.pkce {
            if pkce.code_challenge_method != CodeChallengeMethod::S256 {
                return Err(OauthError::new(Reason::InvalidPkce));
            }
            pkce.validate()?;
        }
        if let Some(dpop_jkt) = &self.dpop_jkt {
            validate_token(dpop_jkt)?;
        }
        if self
            .additional_parameters
            .keys()
            .any(|key| RESERVED_PAR_PARAMETERS.contains(&key.as_str()))
        {
            return Err(OauthError::new(Reason::InvalidParRequest));
        }
        for (key, value) in &self.additional_parameters {
            validate_token(key)?;
            validate_token(value)?;
        }
        if let Some(auth) = &self.attestation_client_authentication {
            auth.validate()?;
        }
        Ok(())
    }

    /// Serializes the request into `application/x-www-form-urlencoded` form.
    pub fn to_form_body(&self) -> OauthResult<String> {
        self.validate()?;
        let mut pairs = Vec::new();
        push_pair(&mut pairs, "client_id", &self.client_id);
        push_pair(&mut pairs, "response_type", &self.response_type);
        if let Some(redirect_uri) = &self.redirect_uri {
            push_pair(&mut pairs, "redirect_uri", redirect_uri);
        }
        if let Some(scope) = &self.scope {
            push_pair(&mut pairs, "scope", scope);
        }
        if let Some(state) = &self.state {
            push_pair(&mut pairs, "state", state);
        }
        if let Some(pkce) = &self.pkce {
            push_pair(&mut pairs, "code_challenge", &pkce.code_challenge);
            push_pair(&mut pairs, "code_challenge_method", "S256");
        }
        if let Some(dpop_jkt) = &self.dpop_jkt {
            push_pair(&mut pairs, "dpop_jkt", dpop_jkt);
        }
        for (key, value) in &self.additional_parameters {
            push_pair(&mut pairs, key, value);
        }
        Ok(pairs.join("&"))
    }
}

/// Successful RFC 9126 PAR response.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct ParResponse {
    /// Request URI reference for the authorization endpoint.
    pub request_uri: String,
    /// Lifetime in seconds.
    pub expires_in: u64,
}

impl fmt::Debug for ParResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParResponse([REDACTED])")
    }
}

impl Zeroize for ParResponse {
    fn zeroize(&mut self) {
        self.request_uri.zeroize();
    }
}

impl Drop for ParResponse {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ParResponse {}

impl ParResponse {
    /// Validates the PAR response.
    pub fn validate(&self) -> OauthResult<()> {
        validate_token(&self.request_uri)?;
        if self.expires_in == 0 {
            return Err(OauthError::new(Reason::InvalidParRequest));
        }
        Ok(())
    }
}

fn push_pair(pairs: &mut Vec<String>, key: &str, value: &str) {
    let encoded_key = utf8_percent_encode(key, FORM_ENCODE_SET).to_string();
    let encoded_value = utf8_percent_encode(value, FORM_ENCODE_SET).to_string();
    pairs.push([encoded_key.as_str(), "=", encoded_value.as_str()].concat());
}
