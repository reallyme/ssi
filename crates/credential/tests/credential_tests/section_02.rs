// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn generated_dispatch_entry_validates_owned_envelopes_without_dto_conversion() {
    let result = validate_credential_envelope_command(
        sample_envelope(CredentialKind::Pid),
        None,
        None,
        CredentialVerificationContext {
            now_unix: 1_755_000_000,
            audience: None,
            nonce: None,
        },
        CredentialValidationPolicy {
            require_signature: false,
            require_status: false,
            require_holder_binding: false,
            require_trust_chain: false,
            require_policy: false,
        },
        Vec::new(),
    );

    assert!(result.valid);
    assert_eq!(result.decision, CredentialDecision::Allow);

    let expired = validate_credential_envelope_command(
        sample_envelope(CredentialKind::Pid),
        None,
        None,
        CredentialVerificationContext {
            now_unix: 1_760_000_000,
            audience: None,
            nonce: None,
        },
        CredentialValidationPolicy {
            require_signature: false,
            require_status: false,
            require_holder_binding: false,
            require_trust_chain: false,
            require_policy: false,
        },
        Vec::new(),
    );
    assert!(!expired.valid);
    assert_eq!(expired.decision, CredentialDecision::Deny);
    assert!(expired.checks.iter().any(|check| {
        check.name == CredentialCheckName::Expiration
            && check.outcome == CredentialCheckOutcome::Fail
            && check.code == CredentialCheckCode::Expired
    }));
}

#[test]
fn generated_dispatch_entry_rejects_malformed_owned_envelopes() {
    let mut malformed = sample_envelope(CredentialKind::Pid);
    malformed.issuer_reference = PartyReference::Absent;

    let result = validate_credential_envelope_command(
        malformed,
        None,
        None,
        CredentialVerificationContext {
            now_unix: 1_755_000_000,
            audience: None,
            nonce: None,
        },
        CredentialValidationPolicy::default(),
        Vec::new(),
    );

    assert!(!result.valid);
    assert_eq!(result.decision, CredentialDecision::Deny);
    assert_eq!(result.checks.len(), 1);
    assert_eq!(result.checks[0].name, CredentialCheckName::Structure);
    assert_eq!(result.checks[0].outcome, CredentialCheckOutcome::Fail);
    assert_eq!(
        result.checks[0].code,
        CredentialCheckCode::InvalidCredential
    );
}

#[test]
fn generated_status_entry_derives_time_state_without_ambient_evidence() {
    let active = check_credential_envelope_status_command(
        sample_envelope(CredentialKind::Pid),
        CredentialVerificationContext {
            now_unix: 1_755_000_000,
            audience: None,
            nonce: None,
        },
    );
    assert!(active.is_ok());
    let Ok(active) = active else {
        return;
    };
    assert_eq!(
        active.status,
        reallyme_credential::CredentialStatusValue::Valid
    );
    assert!(active.checks.iter().any(|check| {
        check.name == CredentialCheckName::Status
            && check.outcome == CredentialCheckOutcome::Skipped
            && !check.mandatory
    }));

    let expired = check_credential_envelope_status_command(
        sample_envelope(CredentialKind::Pid),
        CredentialVerificationContext {
            now_unix: 1_760_000_000,
            audience: None,
            nonce: None,
        },
    );
    assert!(expired.is_ok());
    let Ok(expired) = expired else {
        return;
    };
    assert_eq!(
        expired.status,
        reallyme_credential::CredentialStatusValue::Expired
    );

    let mut malformed = sample_envelope(CredentialKind::Pid);
    malformed.status.status_list_url.clear();
    assert!(check_credential_envelope_status_command(
        malformed,
        CredentialVerificationContext {
            now_unix: 1_755_000_000,
            audience: None,
            nonce: None,
        },
    )
    .is_err());
}

#[test]
fn evidence_backed_credential_validation_allows_valid_credential() {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    let status_list = sample_status_list(vec![0]);
    reallyme_credential::sign_credential_envelope(&mut envelope, &test_signer()).unwrap();

    let result = validate_credential_with_evidence(&CredentialEvidenceValidationInput {
        envelope: &envelope,
        subject_bundle: None,
        issuer_verifier: &TestVerifier {
            expected_method: "did:web:issuer.example#key-1",
        },
        status_list: &status_list,
        status_verifier: &TestStatusVerifier,
        now_unix: 1_750_000_000,
        policy: CredentialValidationPolicy::default(),
    });

    assert!(result.valid);
    assert_eq!(result.decision, CredentialDecision::Allow);
    assert!(result.checks.iter().any(|check| {
        check.name == CredentialCheckName::Signature
            && check.outcome == CredentialCheckOutcome::Pass
    }));
    assert!(result.checks.iter().any(|check| {
        check.name == CredentialCheckName::Status && check.outcome == CredentialCheckOutcome::Pass
    }));
}

#[test]
fn credential_status_policy_verifies_statuslist_source() {
    let envelope = sample_envelope(CredentialKind::Pid);
    let status_list = sample_status_list(vec![0]);
    let cert = sample_certificate();

    reallyme_credential::verify_credential_status_with_policy(
        &CredentialStatusListPolicyStatusInput {
            envelope: &envelope,
            policy: vc_statuslist(instant(2)),
            ocsp_checker: None,
            crl_checker: None,
            status_list: &status_list,
            status_verifier: &TestStatusVerifier,
            certificate: &cert,
        },
    )
    .unwrap();
}

#[test]
fn credential_revocation_policy_falls_back_to_available_source() {
    let envelope = sample_envelope(CredentialKind::Pid);
    let status_list = sample_status_list(vec![0]);
    let cert = sample_certificate();
    let ocsp = StaticStatusChecker {
        result: Err(StatusCheckError::Unavailable),
    };
    let crl = StaticStatusChecker { result: Ok(()) };

    reallyme_credential::verify_credential_status_with_policy(
        &CredentialStatusListPolicyStatusInput {
            envelope: &envelope,
            policy: hybrid_fallback(instant(2)),
            ocsp_checker: Some(&ocsp),
            crl_checker: Some(&crl),
            status_list: &status_list,
            status_verifier: &TestStatusVerifier,
            certificate: &cert,
        },
    )
    .unwrap();
}

#[test]
fn credential_revocation_policy_maps_unavailable_sources() {
    let envelope = sample_envelope(CredentialKind::Pid);
    let cert = sample_certificate();
    let checker = StaticStatusChecker {
        result: Err(StatusCheckError::Unavailable),
    };

    let err = reallyme_credential::verify_credential_revocation_status(
        &envelope,
        &checker,
        &cert,
        1_750_000_000,
    )
    .unwrap_err();

    assert_eq!(
        err,
        CredentialError::Status(CredentialStatusReason::Unavailable)
    );
}

#[test]
fn verify_credential_composes_signature_and_revocation_policy() {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    reallyme_credential::sign_credential_envelope(&mut envelope, &test_signer()).unwrap();
    let cert = sample_certificate();
    let checker = StaticStatusChecker { result: Ok(()) };

    reallyme_credential::verify_credential_with_revocation(
        &CredentialRevocationVerificationInput {
            envelope: &envelope,
            issuer_verifier: &TestVerifier {
                expected_method: "did:web:issuer.example#key-1",
            },
            status_checker: &checker,
            certificate: &cert,
            now_unix: 1_750_000_000,
        },
    )
    .unwrap();
}

#[test]
fn verify_credential_composes_signature_and_statuslist_policy() {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    let status_list = sample_status_list(vec![0]);
    reallyme_credential::sign_credential_envelope(&mut envelope, &test_signer()).unwrap();
    let cert = sample_certificate();

    reallyme_credential::verify_credential_with_statuslist_policy(
        &CredentialStatusListPolicyInput {
            envelope: &envelope,
            issuer_verifier: &TestVerifier {
                expected_method: "did:web:issuer.example#key-1",
            },
            policy: vc_statuslist(instant(2)),
            ocsp_checker: None,
            crl_checker: None,
            status_list: &status_list,
            status_verifier: &TestStatusVerifier,
            certificate: &cert,
        },
    )
    .unwrap();
}

#[cfg(feature = "dispatch-signatures")]
#[test]
fn dispatch_signer_and_verifier_roundtrip_ed25519() {
    let (public_key, private_key) =
        reallyme_crypto::dispatch::generate_keypair(reallyme_crypto::core::Algorithm::Ed25519)
            .unwrap();
    let mut envelope = sample_envelope(CredentialKind::Pid);
    envelope.issuer_signature.raw_rs.clear();

    reallyme_credential::sign_credential_envelope(
        &mut envelope,
        &reallyme_credential::DispatchCredentialIssuerSigner {
            private_key: private_key.as_slice(),
            verification_key: &sample_signature(0).verification_key,
        },
    )
    .unwrap();

    reallyme_credential::verify_credential_issuer_signature(
        &envelope,
        &reallyme_credential::DispatchCredentialIssuerVerifier {
            public_key: public_key.as_slice(),
            expected_verification_key: &sample_signature(0).verification_key,
        },
    )
    .unwrap();
}

#[cfg(feature = "proto")]
#[test]
fn credential_proto_roundtrip_preserves_semantics() {
    let envelope = sample_envelope(CredentialKind::Pid);

    let proto = credential_envelope_to_proto(&envelope).unwrap();
    let roundtrip = credential_envelope_from_proto(&proto).unwrap();

    assert_eq!(roundtrip, envelope);
}

#[cfg(feature = "proto")]
#[test]
fn credential_proto_rejects_missing_claims_commitment() {
    let envelope = sample_envelope(CredentialKind::Pid);
    let mut proto = credential_envelope_to_proto(&envelope).unwrap();
    proto.claims_commitment = MessageField::none();

    let err = credential_envelope_from_proto(&proto).unwrap_err();

    assert_eq!(
        err,
        CredentialError::Proto(
            reallyme_credential::CredentialProtoReason::MissingField(
                reallyme_credential::CredentialProtoField::ClaimsCommitment,
            )
        )
    );
}
