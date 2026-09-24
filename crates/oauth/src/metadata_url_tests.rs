// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8414 Authorization Server Metadata URL derivation tests.

use crate::{authorization_server_metadata_url, OauthResult, Reason};

#[test]
fn derives_root_and_path_issuer_urls() -> OauthResult<()> {
    assert_eq!(
        authorization_server_metadata_url("https://issuer.example")?,
        "https://issuer.example/.well-known/oauth-authorization-server"
    );
    assert_eq!(
        authorization_server_metadata_url("https://issuer.example/")?,
        "https://issuer.example/.well-known/oauth-authorization-server"
    );
    assert_eq!(
        authorization_server_metadata_url("https://issuer.example/tenant/a/")?,
        "https://issuer.example/.well-known/oauth-authorization-server/tenant/a"
    );
    Ok(())
}

#[test]
fn rejects_ambient_authority_and_non_https_issuers() {
    for issuer in [
        "http://issuer.example",
        "https://user:password@issuer.example",
        "https://issuer.example?tenant=a",
        "https://issuer.example#fragment",
    ] {
        let result = authorization_server_metadata_url(issuer);
        assert!(matches!(
            result,
            Err(error) if error.reason() == Reason::InvalidMetadata
        ));
    }
}
