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
            policy: vc_statuslist(instant(2)).unwrap(),
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
            policy: hybrid_fallback(instant(2)).unwrap(),
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

    let mut policy = vc_statuslist(instant(2)).unwrap();
    policy.now_unix = 1_750_000_000;

    reallyme_credential::verify_credential_with_statuslist_policy(
        &CredentialStatusListPolicyInput {
            envelope: &envelope,
            issuer_verifier: &TestVerifier {
                expected_method: "did:web:issuer.example#key-1",
            },
            policy,
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
        CredentialError::Proto(reallyme_credential::CredentialProtoReason::MissingField(
            reallyme_credential::CredentialProtoField::ClaimsCommitment,
        ))
    );
}

fn signed_sample_envelope() -> CredentialEnvelope {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    reallyme_credential::sign_credential_envelope(&mut envelope, &test_signer()).unwrap();
    envelope
}

fn verify_credential_at(
    envelope: &CredentialEnvelope,
    now_unix: u64,
) -> Result<(), CredentialError> {
    let status_list = sample_status_list(vec![0]);
    reallyme_credential::verify_credential(&CredentialVerificationInput {
        envelope,
        issuer_verifier: &TestVerifier {
            expected_method: "did:web:issuer.example#key-1",
        },
        status_list: &status_list,
        status_verifier: &TestStatusVerifier,
        now_unix,
    })
}

#[test]
fn verify_credential_rejects_not_yet_valid_credential() {
    let envelope = signed_sample_envelope();
    assert_eq!(
        verify_credential_at(&envelope, 1_749_999_999),
        Err(CredentialError::Validity(
            CredentialValidityReason::NotYetValid
        ))
    );
}

#[test]
fn verify_credential_rejects_expired_credential_at_exclusive_end() {
    let envelope = signed_sample_envelope();
    assert_eq!(
        verify_credential_at(&envelope, 1_760_000_000),
        Err(CredentialError::Validity(CredentialValidityReason::Expired))
    );
    assert_eq!(verify_credential_at(&envelope, 1_759_999_999), Ok(()));
}

#[test]
fn verify_credential_checks_signature_before_validity_window() {
    let mut envelope = signed_sample_envelope();
    envelope.issuer_signature = sample_signature(9);
    assert_eq!(
        verify_credential_at(&envelope, 1_760_000_000),
        Err(CredentialError::Signature(
            CredentialSignatureReason::VerificationFailed
        ))
    );
}

#[test]
fn verify_credential_with_revocation_rejects_credential_outside_window() {
    let envelope = signed_sample_envelope();
    let cert = sample_certificate();
    let checker = StaticStatusChecker { result: Ok(()) };
    let verify_at = |now_unix| {
        reallyme_credential::verify_credential_with_revocation(
            &CredentialRevocationVerificationInput {
                envelope: &envelope,
                issuer_verifier: &TestVerifier {
                    expected_method: "did:web:issuer.example#key-1",
                },
                status_checker: &checker,
                certificate: &cert,
                now_unix,
            },
        )
    };

    assert_eq!(
        verify_at(1_749_999_999),
        Err(CredentialError::Validity(
            CredentialValidityReason::NotYetValid
        ))
    );
    assert_eq!(
        verify_at(1_760_000_000),
        Err(CredentialError::Validity(CredentialValidityReason::Expired))
    );
}

#[test]
fn verify_credential_with_statuslist_policy_uses_policy_time_for_validity() {
    let envelope = signed_sample_envelope();
    let status_list = sample_status_list(vec![0]);
    let cert = sample_certificate();
    let verify_at = |now_unix| {
        let mut policy = vc_statuslist(instant(2)).unwrap();
        policy.now_unix = now_unix;
        reallyme_credential::verify_credential_with_statuslist_policy(
            &CredentialStatusListPolicyInput {
                envelope: &envelope,
                issuer_verifier: &TestVerifier {
                    expected_method: "did:web:issuer.example#key-1",
                },
                policy,
                ocsp_checker: None,
                crl_checker: None,
                status_list: &status_list,
                status_verifier: &TestStatusVerifier,
                certificate: &cert,
            },
        )
    };

    assert_eq!(
        verify_at(1_749_999_999),
        Err(CredentialError::Validity(
            CredentialValidityReason::NotYetValid
        ))
    );
    assert_eq!(
        verify_at(1_760_000_000),
        Err(CredentialError::Validity(CredentialValidityReason::Expired))
    );
}

fn permissive_local_policy() -> CredentialValidationPolicy {
    CredentialValidationPolicy {
        require_signature: false,
        require_status: false,
        require_holder_binding: false,
        require_trust_chain: false,
        require_policy: false,
    }
}

#[test]
fn requested_check_filter_never_drops_failed_mandatory_checks() {
    let expired = validate_credential_envelope_command(
        sample_envelope(CredentialKind::Pid),
        None,
        None,
        CredentialVerificationContext {
            now_unix: 1_760_000_000,
            audience: None,
            nonce: None,
        },
        permissive_local_policy(),
        vec![CredentialCheckName::Structure],
    );

    assert!(!expired.valid);
    assert_eq!(expired.decision, CredentialDecision::Deny);
    assert!(expired.checks.iter().any(|check| {
        check.name == CredentialCheckName::Expiration
            && check.outcome == CredentialCheckOutcome::Fail
            && check.code == CredentialCheckCode::Expired
            && check.mandatory
    }));

    let not_yet_valid = validate_credential_envelope_command(
        sample_envelope(CredentialKind::Pid),
        None,
        None,
        CredentialVerificationContext {
            now_unix: 1_749_999_999,
            audience: None,
            nonce: None,
        },
        permissive_local_policy(),
        vec![CredentialCheckName::Structure],
    );
    assert_eq!(not_yet_valid.decision, CredentialDecision::Deny);
    assert!(not_yet_valid.checks.iter().any(|check| {
        check.name == CredentialCheckName::NotBefore
            && check.code == CredentialCheckCode::NotYetValid
    }));
}

#[test]
fn requested_check_filter_keeps_failed_mandatory_signature_check() {
    let mut envelope = sample_envelope(CredentialKind::Pid);
    envelope.issuer_signature = sample_signature(9);
    let verifier = TestVerifier {
        expected_method: "did:web:issuer.example#key-1",
    };
    let result = validate_credential_envelope_command(
        envelope,
        None,
        Some(&verifier),
        CredentialVerificationContext {
            now_unix: 1_755_000_000,
            audience: None,
            nonce: None,
        },
        permissive_local_policy(),
        vec![CredentialCheckName::Structure],
    );

    assert_eq!(result.decision, CredentialDecision::Deny);
    assert!(result.checks.iter().any(|check| {
        check.name == CredentialCheckName::Signature
            && check.outcome == CredentialCheckOutcome::Fail
            && check.code == CredentialCheckCode::InvalidSignature
    }));
}

#[test]
fn unevaluated_policy_checks_are_reported_as_skipped() {
    let result = validate_credential_envelope_command(
        sample_envelope(CredentialKind::Pid),
        None,
        None,
        CredentialVerificationContext {
            now_unix: 1_755_000_000,
            audience: None,
            nonce: None,
        },
        permissive_local_policy(),
        Vec::new(),
    );

    for name in [
        CredentialCheckName::AssuranceLevel,
        CredentialCheckName::CredentialType,
        CredentialCheckName::Algorithm,
    ] {
        assert!(result.checks.iter().any(|check| {
            check.name == name
                && check.outcome == CredentialCheckOutcome::Skipped
                && !check.mandatory
        }));
        assert!(!result
            .checks
            .iter()
            .any(|check| { check.name == name && check.outcome == CredentialCheckOutcome::Pass }));
    }

    let requested = validate_credential_envelope_command(
        sample_envelope(CredentialKind::Pid),
        None,
        None,
        CredentialVerificationContext {
            now_unix: 1_755_000_000,
            audience: None,
            nonce: None,
        },
        permissive_local_policy(),
        vec![CredentialCheckName::AssuranceLevel],
    );
    assert_eq!(requested.decision, CredentialDecision::Indeterminate);
}
