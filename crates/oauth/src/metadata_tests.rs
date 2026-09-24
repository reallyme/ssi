// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{fetch_authorization_server_metadata, MetadataFetcher};
use crate::{OauthResult, Reason};

struct StaticMetadata(&'static str);

impl MetadataFetcher for StaticMetadata {
    fn fetch_metadata_json(&self, _issuer: &str) -> OauthResult<String> {
        Ok(self.0.to_owned())
    }
}

#[test]
fn distinguishes_an_authenticated_metadata_issuer_mismatch() {
    let result = fetch_authorization_server_metadata(
        &StaticMetadata(r#"{"issuer":"https://other.example"}"#),
        "https://issuer.example",
    );
    assert!(matches!(
        result,
        Err(error) if error.reason() == Reason::AuthorizationServerIssuerMismatch
    ));
}

#[test]
fn preserves_other_metadata_validation_failures() {
    let result = fetch_authorization_server_metadata(
        &StaticMetadata(r#"{"issuer":"http://issuer.example"}"#),
        "https://issuer.example",
    );
    assert!(matches!(
        result,
        Err(error) if error.reason() == Reason::InvalidUrl
    ));
}
