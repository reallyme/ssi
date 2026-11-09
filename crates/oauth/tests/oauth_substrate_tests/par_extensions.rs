// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn par_serializes_managed_openid4vci_parameters_separately_from_extensions(
) -> Result<(), OauthError> {
    let verifier = PkceVerifier::new(SecretString::from(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
    ))?;
    let mut request = ParRequest::authorization_code(
        "client".to_owned(),
        "https://wallet.example/cb".to_owned(),
        verifier.challenge(),
    )?;
    request.authorization_details =
        Some(r#"[{"type":"openid_credential","credential_configuration_id":"pid"}]"#.to_owned());
    request.resource = Some("https://issuer.example".to_owned());
    request.issuer_state = Some("issuer-state".to_owned());
    request.request = Some("header.payload.signature".to_owned());
    request
        .additional_parameters
        .try_insert("prompt".to_owned(), "login".to_owned())?;

    let body = request.to_form_body()?;
    assert!(body.contains("authorization_details="));
    assert!(body.contains("resource=https%3A%2F%2Fissuer.example"));
    assert!(body.contains("issuer_state=issuer-state"));
    assert!(body.contains("request=header.payload.signature"));
    assert!(body.contains("prompt=login"));
    assert_eq!(body.matches("authorization_details=").count(), 1);
    assert_eq!(body.matches("issuer_state=").count(), 1);
    assert_eq!(body.matches("request=").count(), 1);
    Ok(())
}

#[test]
fn par_extensions_reject_managed_and_malformed_parameters() {
    for managed in [
        "client_id",
        "client_assertion",
        "client_assertion_type",
        "client_secret",
        "response_type",
        "response_mode",
        "redirect_uri",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
        "authorization_details",
        "resource",
        "dpop_jkt",
        "issuer_state",
        "request",
        "request_uri",
    ] {
        let mut parameters = AdditionalAuthorizationParameters::new();
        assert_eq!(
            parameters
                .try_insert(managed.to_owned(), "attacker-controlled".to_owned())
                .err()
                .map(|error| error.reason()),
            Some(Reason::InvalidParRequest)
        );
    }

    let mut parameters = AdditionalAuthorizationParameters::new();
    assert_eq!(
        parameters
            .try_insert("prompt\n".to_owned(), "login".to_owned())
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidString)
    );
    assert_eq!(
        parameters
            .try_insert("prompt".to_owned(), "x".repeat(MAX_TOKEN_BYTES + 1))
            .err()
            .map(|error| error.reason()),
        Some(Reason::InvalidString)
    );
}

#[test]
fn par_rejects_empty_control_bearing_and_oversized_request_objects() -> Result<(), OauthError> {
    let oversized_length = MAX_TOKEN_BYTES
        .checked_add(1)
        .ok_or_else(|| OauthError::new(Reason::InvalidString))?;
    for invalid_request in [
        String::new(),
        "header.payload.\nsignature".to_owned(),
        "a".repeat(oversized_length),
    ] {
        let verifier = PkceVerifier::new(SecretString::from(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        ))?;
        let mut request = ParRequest::authorization_code(
            "client".to_owned(),
            "https://wallet.example/cb".to_owned(),
            verifier.challenge(),
        )?;
        request.request = Some(invalid_request);

        assert_eq!(
            request.validate().err().map(|error| error.reason()),
            Some(Reason::InvalidString)
        );
    }
    Ok(())
}
