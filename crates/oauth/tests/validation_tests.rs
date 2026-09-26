// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! URL and PKCE challenge validation tests.

use reallyme_openid_oauth::validation::{validate_https_url, validate_issuer_identifier};
use reallyme_openid_oauth::{CodeChallengeMethod, OauthError, PkceChallenge, PkceVerifier, Reason};
use secrecy::SecretString;

fn reason<T>(result: Result<T, OauthError>) -> Option<Reason> {
    result.err().map(|error| error.reason())
}

#[test]
fn loopback_http_accepts_bracketed_ipv6_and_rejects_lookalikes() {
    for accepted in [
        "http://localhost:8080/cb",
        "http://127.0.0.1:8080/cb",
        "http://[::1]:8080/cb",
    ] {
        assert!(validate_https_url(accepted, true).is_ok(), "{accepted}");
        assert_eq!(
            reason(validate_https_url(accepted, false)),
            Some(Reason::InvalidUrl),
            "{accepted}"
        );
    }

    for rejected in [
        "http://localhost.evil.example/cb",
        "http://127.0.0.2/cb",
        "http://[::2]/cb",
        "http://example.com/cb",
    ] {
        assert_eq!(
            reason(validate_https_url(rejected, true)),
            Some(Reason::InvalidUrl),
            "{rejected}"
        );
    }
}

#[test]
fn https_urls_reject_userinfo() {
    for rejected in [
        "https://user@as.example/.well-known/oauth-authorization-server",
        "https://user:secret@as.example/token",
        "https://:secret@as.example/token",
        "http://user@localhost/cb",
    ] {
        assert_eq!(
            reason(validate_https_url(rejected, true)),
            Some(Reason::InvalidUrl),
            "{rejected}"
        );
    }
    assert_eq!(
        reason(validate_issuer_identifier("https://user@as.example")),
        Some(Reason::InvalidUrl)
    );
    assert!(validate_issuer_identifier("https://as.example").is_ok());
}

#[test]
fn pkce_challenge_requires_canonical_s256_encoding() -> Result<(), OauthError> {
    let verifier = PkceVerifier::new(SecretString::from(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
    ))?;
    verifier.challenge().validate()?;

    let challenge = |value: &str| PkceChallenge {
        code_challenge: value.to_owned(),
        code_challenge_method: CodeChallengeMethod::S256,
    };
    let valid = verifier.challenge().code_challenge.clone();
    let mut non_canonical_tail = valid.clone();
    non_canonical_tail.pop();
    // Only 16 of the 64 alphabet symbols are canonical in the final position.
    non_canonical_tail.push(if valid.ends_with('B') { 'C' } else { 'B' });

    for invalid in [
        "short".to_owned(),
        format!("{valid}A"),
        format!("{}=", &valid[..42]),
        format!("{}+", &valid[..42]),
        format!("{}/", &valid[..42]),
        non_canonical_tail,
    ] {
        assert_eq!(
            reason(challenge(&invalid).validate()),
            Some(Reason::InvalidPkce),
            "{invalid}"
        );
    }
    Ok(())
}
