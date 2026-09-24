// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8414 Authorization Server Metadata URL derivation.

use url::Url;

use crate::{OauthError, OauthResult, Reason};

const AUTHORIZATION_SERVER_WELL_KNOWN_PATH: &str = "/.well-known/oauth-authorization-server";
const MAX_ISSUER_IDENTIFIER_BYTES: usize = 8_192;

/// Derive the RFC 8414 well-known URL for an Authorization Server issuer.
pub fn authorization_server_metadata_url(issuer: &str) -> OauthResult<String> {
    if issuer.is_empty() || issuer.len() > MAX_ISSUER_IDENTIFIER_BYTES {
        return Err(invalid_metadata());
    }
    let mut url = Url::parse(issuer).map_err(|_| invalid_metadata())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid_metadata());
    }

    let issuer_path = url.path().strip_suffix('/').unwrap_or(url.path());
    let mut metadata_path = AUTHORIZATION_SERVER_WELL_KNOWN_PATH.to_owned();
    metadata_path.push_str(issuer_path);
    url.set_path(&metadata_path);
    Ok(url.into())
}

const fn invalid_metadata() -> OauthError {
    OauthError::new(Reason::InvalidMetadata)
}
