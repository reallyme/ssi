// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for SDK-facing presentation commands.

use identity_core_primitives::Algorithm;
use reallyme_disclosure_policy::eu_pid_policy;
use reallyme_vp_api::{
    create_presentation_request, present, verify_presentation, PresentationCheckCode,
    PresentationCheckName, PresentationCheckOutcome, PresentationDecision,
    PresentationDisclosureFact, PresentationExpected, PresentationPresentRequest,
    PresentationQeaaFact, PresentationRequestCreateRequest, PresentationStatusFact,
    PresentationVerificationContext, PresentationVerificationFacts, PresentationVerifyRequest,
    VpApiError,
};
use reallyme_vp_core::{DisclosureMode, Presentation, PresentationBinding, SdJwtVcPresentation};
use zeroize::Zeroize;

fn disclosure() -> PresentationDisclosureFact {
    PresentationDisclosureFact {
        claim_path: "/given_name".to_owned(),
        mode: DisclosureMode::Reveal,
    }
}

fn presentation() -> Presentation {
    Presentation::SdJwtVc(Box::new(SdJwtVcPresentation {
        sd_jwt: "header.payload.signature".to_owned(),
        disclosures: vec!["disclosure".to_owned()],
        kb_jwt: Some("kb.header.payload.signature".to_owned()),
        vct: Some("eu.pid.v1".to_owned()),
        envelope_hash: Some([3u8; 32]),
    }))
}

fn facts() -> PresentationVerificationFacts {
    PresentationVerificationFacts {
        binding_ok: true,
        proof_verified: true,
        key_binding_ok: Some(true),
        issuer_trust_ok: Some(true),
        wallet_trust_ok: Some(true),
        transaction_data_ok: None,
        age_over_attestation_ok: None,
        issuer_algorithm: Algorithm::P256,
        holder_algorithm: Algorithm::P256,
        claimset_id: "eu.pid.v1".to_owned(),
        disclosures: vec![disclosure()],
        status: Some(PresentationStatusFact {
            checked: true,
            revoked: false,
            suspended: false,
            age_seconds: Some(60),
        }),
        qeaa: Some(PresentationQeaaFact {
            verified: true,
            profile: Some("QEAA-ETSI-1.0".to_owned()),
            identity_proofing_rank: Some(3),
        }),
    }
}

#[test]
fn create_presentation_request_validates_binding_and_claims() {
    let request = PresentationRequestCreateRequest {
        nonce: [1u8; 32],
        state: "state-1".to_owned(),
        audience: "did:web:verifier.example".to_owned(),
        response_uri: Some("https://verifier.example/response".to_owned()),
        required_claims: vec![disclosure()],
        expires_at_unix: 1_800_000_000,
        purpose: Some("login".to_owned()),
    };

    let record = create_presentation_request(request, 1_700_000_000).unwrap();

    assert_eq!(record.created_at_unix, 1_700_000_000);
    assert_eq!(record.request.required_claims[0].claim_path, "/given_name");
}

#[test]
fn create_presentation_request_rejects_invalid_disclosure() {
    let request = PresentationRequestCreateRequest {
        nonce: [1u8; 32],
        state: "state-1".to_owned(),
        audience: "did:web:verifier.example".to_owned(),
        response_uri: None,
        required_claims: vec![PresentationDisclosureFact {
            claim_path: "/given_name".to_owned(),
            mode: DisclosureMode::Hidden,
        }],
        expires_at_unix: 1_800_000_000,
        purpose: None,
    };

    let error = create_presentation_request(request, 1_700_000_000).unwrap_err();

    assert!(matches!(error, VpApiError::InvalidCommand(_)));
}

#[test]
fn presentation_request_owner_clears_binding_and_claim_material() {
    let mut request = PresentationRequestCreateRequest {
        nonce: [1u8; 32],
        state: "state-1".to_owned(),
        audience: "did:web:verifier.example".to_owned(),
        response_uri: Some("https://verifier.example/response".to_owned()),
        required_claims: vec![disclosure()],
        expires_at_unix: 1_800_000_000,
        purpose: Some("login".to_owned()),
    };

    request.zeroize();

    assert_eq!(request.nonce, [0u8; 32]);
    assert!(request.state.is_empty());
    assert!(request.audience.is_empty());
    assert!(request.response_uri.is_none());
    assert!(request.required_claims.is_empty());
    assert_eq!(request.expires_at_unix, 0);
    assert!(request.purpose.is_none());
}

#[test]
fn present_records_valid_protocol_neutral_presentation() {
    let record = present(PresentationPresentRequest {
        presentation: presentation(),
        selected_credentials: vec!["credential-1".to_owned()],
        selected_claims: vec![disclosure()],
        holder_binding: PresentationBinding {
            nonce: [1u8; 32],
            audience_hash: [2u8; 32],
            expiry_unix: 1_800_000_000,
        },
        now_unix: 1_700_000_000,
    })
    .unwrap();

    assert_eq!(record.selected_credentials, vec!["credential-1"]);
    assert_eq!(record.selected_claims[0].claim_path, "/given_name");
}

#[test]
fn present_rejects_duplicate_credential_and_claim_selections() {
    let duplicate_credentials = present(PresentationPresentRequest {
        presentation: presentation(),
        selected_credentials: vec!["credential-1".to_owned(), "credential-1".to_owned()],
        selected_claims: vec![disclosure()],
        holder_binding: PresentationBinding {
            nonce: [1u8; 32],
            audience_hash: [2u8; 32],
            expiry_unix: 1_800_000_000,
        },
        now_unix: 1_700_000_000,
    });
    assert!(matches!(
        duplicate_credentials,
        Err(VpApiError::InvalidCommand(_))
    ));

    let duplicate_claims = present(PresentationPresentRequest {
        presentation: presentation(),
        selected_credentials: vec!["credential-1".to_owned()],
        selected_claims: vec![disclosure(), disclosure()],
        holder_binding: PresentationBinding {
            nonce: [1u8; 32],
            audience_hash: [2u8; 32],
            expiry_unix: 1_800_000_000,
        },
        now_unix: 1_700_000_000,
    });
    assert!(matches!(
        duplicate_claims,
        Err(VpApiError::InvalidCommand(_))
    ));
}

#[test]
fn presentation_record_owner_clears_selection_and_binding_material() {
    let record = present(PresentationPresentRequest {
        presentation: presentation(),
        selected_credentials: vec!["credential-1".to_owned()],
        selected_claims: vec![disclosure()],
        holder_binding: PresentationBinding {
            nonce: [1u8; 32],
            audience_hash: [2u8; 32],
            expiry_unix: 1_800_000_000,
        },
        now_unix: 1_700_000_000,
    });
    assert!(record.is_ok());
    let Ok(mut record) = record else {
        return;
    };
    record.zeroize();
    assert!(record.selected_credentials.is_empty());
    assert!(record.selected_claims.is_empty());
    assert_eq!(record.holder_binding.nonce, [0_u8; 32]);
    assert_eq!(record.holder_binding.audience_hash, [0_u8; 32]);
}

#[test]
fn verify_presentation_allows_policy_satisfying_facts() {
    let result = verify_presentation(PresentationVerifyRequest {
        presentation: presentation(),
        expected: PresentationExpected::default(),
        verification_context: PresentationVerificationContext {
            evaluation_time_unix: 1_700_000_000,
            presentation_time_unix: 1_700_000_000,
        },
        policy: eu_pid_policy().require_claim("/given_name", DisclosureMode::Reveal),
        facts: facts(),
        checks: Vec::new(),
    });

    assert!(result.valid);
    assert_eq!(result.decision, PresentationDecision::Allow);
    assert!(result.presentation_checks.iter().any(|check| {
        check.name == PresentationCheckName::VerifierPolicy
            && check.outcome == PresentationCheckOutcome::Pass
    }));
}

#[test]
fn verify_presentation_is_indeterminate_for_requested_missing_evidence() {
    let result = verify_presentation(PresentationVerifyRequest {
        presentation: presentation(),
        expected: PresentationExpected::default(),
        verification_context: PresentationVerificationContext {
            evaluation_time_unix: 1_700_000_000,
            presentation_time_unix: 1_700_000_000,
        },
        policy: eu_pid_policy().require_claim("/given_name", DisclosureMode::Reveal),
        facts: facts(),
        checks: vec![PresentationCheckName::TransactionData],
    });

    assert!(!result.valid);
    assert_eq!(result.decision, PresentationDecision::Indeterminate);
    assert_eq!(result.presentation_checks.len(), 1);
    assert_eq!(
        result.presentation_checks[0].code,
        PresentationCheckCode::EvidenceRequired
    );
}

#[test]
fn presentation_verification_result_owner_clears_disclosed_identity_material() {
    let mut result = verify_presentation(PresentationVerifyRequest {
        presentation: presentation(),
        expected: PresentationExpected::default(),
        verification_context: PresentationVerificationContext {
            evaluation_time_unix: 1_700_000_000,
            presentation_time_unix: 1_700_000_000,
        },
        policy: eu_pid_policy().require_claim("/given_name", DisclosureMode::Reveal),
        facts: facts(),
        checks: Vec::new(),
    });

    result.zeroize();

    assert!(!result.valid);
    assert_eq!(result.decision, PresentationDecision::Indeterminate);
    assert!(result.presentation_checks.is_empty());
    assert!(result.credential_results.is_empty());
    assert!(result.disclosed_claims.is_empty());
}
