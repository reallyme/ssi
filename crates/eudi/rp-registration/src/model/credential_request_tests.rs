// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::CredentialRequest;
use crate::RegistrationError;

const REGISTERED: &[u8] = br#"{"format":"dc+sd-jwt","meta":{"vct_values":["urn:example:pid","urn:example:age"]},"claims":[{"path":"[\"family_name\"]"},{"path":"[\"birth_date\"]"}]}"#;
const REQUESTED: &[u8] = br#"{"format":"dc+sd-jwt","meta":{"vct_values":["urn:example:pid"]},"claims":[{"path":"[\"family_name\"]"}]}"#;
const EXTRA_CLAIM: &[u8] = br#"{"format":"dc+sd-jwt","meta":{"vct_values":["urn:example:pid"]},"claims":[{"path":"[\"portrait\"]"}]}"#;
const OTHER_TYPE: &[u8] = br#"{"format":"dc+sd-jwt","meta":{"vct_values":["urn:example:unrelated"]},"claims":[{"path":"[\"family_name\"]"}]}"#;

#[test]
fn authenticated_scope_covers_only_registered_metadata_and_claims() -> Result<(), RegistrationError>
{
    let registered = CredentialRequest::from_json(REGISTERED)?;
    let requested = CredentialRequest::from_json(REQUESTED)?;
    let extra_claim = CredentialRequest::from_json(EXTRA_CLAIM)?;
    let other_type = CredentialRequest::from_json(OTHER_TYPE)?;
    assert!(registered.authorizes_requested(&requested));
    assert!(!registered.authorizes_requested(&extra_claim));
    assert!(!registered.authorizes_requested(&other_type));
    assert!(!requested.authorizes_requested(&registered));
    Ok(())
}

#[test]
fn rejects_duplicate_members_unknown_fields_and_noncanonical_claim_paths() {
    let duplicate = br#"{"format":"dc+sd-jwt","format":"dc+sd-jwt","meta":{"vct_values":["urn:example:pid"]},"claims":[{"path":"[\"family_name\"]"}]}"#;
    let unknown = br#"{"format":"dc+sd-jwt","meta":{"vct_values":["urn:example:pid"]},"claims":[{"path":"[\"family_name\"]"}],"extra":true}"#;
    let malformed_path = br#"{"format":"dc+sd-jwt","meta":{"vct_values":["urn:example:pid"]},"claims":[{"path":"{}"}]}"#;
    assert!(CredentialRequest::from_json(duplicate).is_err());
    assert!(CredentialRequest::from_json(unknown).is_err());
    assert!(CredentialRequest::from_json(malformed_path).is_err());
}

#[test]
fn rejects_oversized_and_deeply_nested_requests() {
    let oversized = vec![b' '; super::MAX_CREDENTIAL_REQUEST_JSON_BYTES + 1];
    let nested = format!(
        "{{\"format\":\"dc+sd-jwt\",\"meta\":{{\"vct_values\":[{}\"urn:example:pid\"{}]}},\"claims\":[]}}",
        "[".repeat(30),
        "]".repeat(30)
    );
    assert!(CredentialRequest::from_json(&oversized).is_err());
    assert!(CredentialRequest::from_json(nested.as_bytes()).is_err());
}
