// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for this crate.

#![allow(missing_docs)]

use envelopes_profiles::{
    enforce_did_me_profile, enforce_eu_pid_profile, enforce_openid4vc_profile, CredentialProfile,
    EnvelopeFormat, EnvelopeProfileError, EnvelopeProfileInput, EnvelopeProfileInvalidReason,
};

fn valid_input() -> EnvelopeProfileInput<'static> {
    EnvelopeProfileInput {
        format: EnvelopeFormat::DcSdJwt,
        credential_profile: CredentialProfile::EuPid,
        claimset_id: "eu.pid.v1",
        issuer: "did:me:issuer",
        subject: "did:me:subject",
        vct: Some("eu.europa.ec.eudi.pid.1"),
        valid_from_unix: Some(1_700_000_000),
        valid_until_unix: Some(1_800_000_000),
        status_present: true,
        qeaa_metadata_present: false,
        did_method: Some("did:me"),
        proof_cryptosuite: None,
    }
}

#[test]
fn openid4vc_accepts_supported_sd_jwt_vc_metadata() {
    let input = EnvelopeProfileInput {
        credential_profile: CredentialProfile::OpenId4Vc,
        ..valid_input()
    };

    assert!(enforce_openid4vc_profile(&input).is_ok());
}

#[test]
fn openid4vc_rejects_sd_jwt_without_vct() {
    let input = EnvelopeProfileInput {
        credential_profile: CredentialProfile::OpenId4Vc,
        vct: None,
        ..valid_input()
    };

    assert_eq!(
        enforce_openid4vc_profile(&input),
        Err(EnvelopeProfileError::InvalidInput(
            EnvelopeProfileInvalidReason::MissingVct
        ))
    );
}

#[test]
fn eu_pid_accepts_pid_with_status_metadata() {
    let input = valid_input();

    assert!(enforce_eu_pid_profile(&input).is_ok());
}

#[test]
fn eu_pid_rejects_missing_status_metadata() {
    let input = EnvelopeProfileInput {
        status_present: false,
        ..valid_input()
    };

    assert_eq!(
        enforce_eu_pid_profile(&input),
        Err(EnvelopeProfileError::InvalidInput(
            EnvelopeProfileInvalidReason::MissingStatusMetadata
        ))
    );
}

#[test]
fn eu_pid_rejects_wrong_claimset() {
    let input = EnvelopeProfileInput {
        claimset_id: "other.claimset.v1",
        ..valid_input()
    };

    assert_eq!(
        enforce_eu_pid_profile(&input),
        Err(EnvelopeProfileError::InvalidInput(
            EnvelopeProfileInvalidReason::UnsupportedClaimset
        ))
    );
}

#[test]
fn eu_pid_rejects_wrong_profile_family() {
    let input = EnvelopeProfileInput {
        credential_profile: CredentialProfile::OpenId4Vc,
        ..valid_input()
    };

    assert_eq!(
        enforce_eu_pid_profile(&input),
        Err(EnvelopeProfileError::InvalidInput(
            EnvelopeProfileInvalidReason::UnsupportedCredentialProfile
        ))
    );
}

#[test]
fn eu_pid_rejects_unsupported_format() {
    let input = EnvelopeProfileInput {
        format: EnvelopeFormat::DataIntegrity,
        ..valid_input()
    };

    assert_eq!(
        enforce_eu_pid_profile(&input),
        Err(EnvelopeProfileError::InvalidInput(
            EnvelopeProfileInvalidReason::UnsupportedEnvelopeFormat
        ))
    );
}

#[test]
fn eu_pid_rejects_invalid_validity_window() {
    let input = EnvelopeProfileInput {
        valid_until_unix: Some(1_700_000_000),
        ..valid_input()
    };

    assert_eq!(
        enforce_eu_pid_profile(&input),
        Err(EnvelopeProfileError::InvalidInput(
            EnvelopeProfileInvalidReason::InvalidValidityWindow
        ))
    );
}

#[test]
fn eu_qeaa_requires_qeaa_metadata() {
    let input = EnvelopeProfileInput {
        credential_profile: CredentialProfile::EuQeaa,
        ..valid_input()
    };

    assert_eq!(
        enforce_eu_pid_profile(&input),
        Err(EnvelopeProfileError::InvalidInput(
            EnvelopeProfileInvalidReason::MissingQeaaMetadata
        ))
    );
}

#[test]
fn eu_qeaa_accepts_qeaa_metadata() {
    let input = EnvelopeProfileInput {
        credential_profile: CredentialProfile::EuQeaa,
        qeaa_metadata_present: true,
        ..valid_input()
    };

    assert!(enforce_eu_pid_profile(&input).is_ok());
}

#[test]
fn did_me_accepts_data_integrity_profile() {
    let input = EnvelopeProfileInput {
        format: EnvelopeFormat::DataIntegrity,
        credential_profile: CredentialProfile::DidMe,
        claimset_id: "did.me.v1",
        proof_cryptosuite: Some("es256-jws-cid-2025"),
        ..valid_input()
    };

    assert!(enforce_did_me_profile(&input).is_ok());
}

#[test]
fn did_me_rejects_non_did_me_binding() {
    let input = EnvelopeProfileInput {
        format: EnvelopeFormat::DataIntegrity,
        credential_profile: CredentialProfile::DidMe,
        claimset_id: "did.me.v1",
        issuer: "did:web:issuer.example",
        subject: "did:me:subject",
        proof_cryptosuite: Some("es256-jws-cid-2025"),
        ..valid_input()
    };

    assert_eq!(
        enforce_did_me_profile(&input),
        Err(EnvelopeProfileError::InvalidInput(
            EnvelopeProfileInvalidReason::InvalidDidMeBinding
        ))
    );
}

#[test]
fn did_me_rejects_wrong_cryptosuite() {
    let input = EnvelopeProfileInput {
        format: EnvelopeFormat::DataIntegrity,
        credential_profile: CredentialProfile::DidMe,
        claimset_id: "did.me.v1",
        proof_cryptosuite: Some("other-suite"),
        ..valid_input()
    };

    assert_eq!(
        enforce_did_me_profile(&input),
        Err(EnvelopeProfileError::InvalidInput(
            EnvelopeProfileInvalidReason::UnsupportedDidMeCryptosuite
        ))
    );
}

fn did_me_input() -> EnvelopeProfileInput<'static> {
    EnvelopeProfileInput {
        format: EnvelopeFormat::DataIntegrity,
        credential_profile: CredentialProfile::DidMe,
        claimset_id: "did.me.v1",
        proof_cryptosuite: Some("es256-jws-cid-2025"),
        ..valid_input()
    }
}

fn did_me_error(reason: EnvelopeProfileInvalidReason) -> Result<(), EnvelopeProfileError> {
    Err(EnvelopeProfileError::InvalidInput(reason))
}

#[test]
fn did_me_rejects_identifiers_that_only_share_the_method_prefix() {
    for (issuer, subject) in [
        ("did:meevil:issuer", "did:me:subject"),
        ("did:me:issuer", "did:meevil:subject"),
        ("did:me", "did:me:subject"),
        ("did:me:", "did:me:subject"),
        ("did:me:issuer", "did:me:"),
    ] {
        let input = EnvelopeProfileInput {
            issuer,
            subject,
            ..did_me_input()
        };

        assert_eq!(
            enforce_did_me_profile(&input),
            did_me_error(EnvelopeProfileInvalidReason::InvalidDidMeBinding),
            "issuer {issuer:?} subject {subject:?} must be rejected"
        );
    }
}

#[test]
fn did_me_rejects_missing_did_method() {
    let input = EnvelopeProfileInput {
        did_method: None,
        ..did_me_input()
    };

    assert_eq!(
        enforce_did_me_profile(&input),
        did_me_error(EnvelopeProfileInvalidReason::MissingDidMethod)
    );
}

#[test]
fn did_me_rejects_wrong_did_method() {
    let input = EnvelopeProfileInput {
        did_method: Some("did:meevil"),
        ..did_me_input()
    };

    assert_eq!(
        enforce_did_me_profile(&input),
        did_me_error(EnvelopeProfileInvalidReason::InvalidDidMeBinding)
    );
}

#[test]
fn did_me_rejects_data_integrity_without_cryptosuite() {
    let input = EnvelopeProfileInput {
        proof_cryptosuite: None,
        ..did_me_input()
    };

    assert_eq!(
        enforce_did_me_profile(&input),
        did_me_error(EnvelopeProfileInvalidReason::MissingDidMeCryptosuite)
    );
}

#[test]
fn did_me_accepts_jwt_envelope_without_data_integrity_cryptosuite() {
    let input = EnvelopeProfileInput {
        format: EnvelopeFormat::JwtVcJson,
        proof_cryptosuite: None,
        ..did_me_input()
    };

    assert!(enforce_did_me_profile(&input).is_ok());
}

#[test]
fn did_me_rejects_jwt_envelope_with_wrong_cryptosuite() {
    let input = EnvelopeProfileInput {
        format: EnvelopeFormat::JwtVcJson,
        proof_cryptosuite: Some("other-suite"),
        ..did_me_input()
    };

    assert_eq!(
        enforce_did_me_profile(&input),
        did_me_error(EnvelopeProfileInvalidReason::UnsupportedDidMeCryptosuite)
    );
}

#[test]
fn eu_dedicated_profiles_reject_mismatched_claimset() {
    for (credential_profile, claimset_id) in [
        (CredentialProfile::EuPid, "eu.age.v1"),
        (CredentialProfile::EuPid, "eu.tax.v1"),
        (CredentialProfile::EuAge, "eu.pid.v1"),
        (CredentialProfile::EuPassport, "eu.pid.v1"),
    ] {
        let input = EnvelopeProfileInput {
            credential_profile,
            claimset_id,
            ..valid_input()
        };

        assert_eq!(
            enforce_eu_pid_profile(&input),
            Err(EnvelopeProfileError::InvalidInput(
                EnvelopeProfileInvalidReason::UnsupportedClaimset
            )),
            "{credential_profile:?} with {claimset_id} must be rejected"
        );
    }
}

#[test]
fn eu_dedicated_profiles_accept_matching_claimset() {
    for (credential_profile, claimset_id) in [
        (CredentialProfile::EuPid, "eu.pid.v1"),
        (CredentialProfile::EuAge, "eu.age.v1"),
        (CredentialProfile::EuPassport, "eu.passport.v1"),
        (CredentialProfile::EuEaa, "eu.tax.v1"),
    ] {
        let input = EnvelopeProfileInput {
            credential_profile,
            claimset_id,
            ..valid_input()
        };

        assert!(
            enforce_eu_pid_profile(&input).is_ok(),
            "{credential_profile:?} with {claimset_id} must be accepted"
        );
    }
}
