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
