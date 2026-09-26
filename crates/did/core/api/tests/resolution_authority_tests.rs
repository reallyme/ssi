// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Regression coverage for history-authenticated resolution, freshness, and version windows.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_api::{
    create::create_did,
    error::DidApiError,
    profile::DidProfile,
    resolve::{
        validate_resolution_result, DidDeactivationStatus, DidDocumentMetadata,
        DidResolutionErrorCode, DidResolutionFreshness, DidResolutionMetadata, DidResolutionResult,
        DidResolveRequest, MAX_DID_RESOLUTION_CLOCK_SKEW_SECONDS,
    },
    update::{update_did, UpdateConfig},
    validate::{validate_did_chain, DidValidationCode, DomainVerificationEnv},
    CreateConfig, KeySet,
};
use reallyme_did_types::DIDDocument;

/// 2026-02-01T00:00:00Z
const RETRIEVED: &str = "2026-02-01T00:00:00Z";
const RETRIEVED_UNIX_SECONDS: i64 = 1_769_904_000;

fn create(did: &str) -> (DIDDocument, KeySet) {
    create_did(
        CreateConfig {
            profile: Some(DidProfile::Messaging),
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            services: None,
            update_policy: None,
            domain_verification: None,
            verification_methods: None,
            authentication: None,
            assertion: None,
            invocation: None,
            key_agreement: None,
            created: None,
        },
        did,
    )
    .expect("create_did failed")
}

fn no_op_update(doc: &DIDDocument, ks: &KeySet) -> (DIDDocument, KeySet) {
    update_did(
        doc,
        ks,
        UpdateConfig {
            services: None,
            also_known_as: Some(vec!["https://example.com/profile".into()]),
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            allowed: None,
            threshold: None,
            deactivate: false,
            domain_verification: None,
            rotate_vms: None,
            authentication: None,
            assertion: None,
            invocation: None,
            key_agreement: None,
            created: None,
        },
    )
    .expect("update_did failed")
}

fn request(doc: &DIDDocument) -> DidResolveRequest {
    DidResolveRequest {
        did: doc.id.clone(),
        version_id: None,
        version_time: None,
        minimum_version_sequence: None,
        assurance: None,
        freshness: None,
    }
}

fn resolution(doc: DIDDocument, history: Vec<DIDDocument>) -> DidResolutionResult {
    DidResolutionResult {
        history,
        resolution_metadata: DidResolutionMetadata {
            content_type: Some("application/did+json".into()),
            retrieved_at: Some(RETRIEVED.into()),
            resolver: Some("test".into()),
            error: None,
            assurance_achieved: None,
            sequence: Some(doc.sequence),
            deactivation_status: DidDeactivationStatus::Active,
        },
        document_metadata: Some(DidDocumentMetadata {
            created: Some("2025-01-01T00:00:00Z".into()),
            updated: Some("2025-06-01T00:00:00Z".into()),
            deactivated: false,
            version_id: Some(doc.current_core.clone()),
            next_version_id: None,
            valid_from: None,
            valid_until: None,
        }),
        document: Some(doc),
    }
}

fn no_domain_env() -> DomainVerificationEnv<'static> {
    DomainVerificationEnv {
        resolve_txt: None,
        fetch_url: None,
    }
}

// -----------------------------------------------------------------------------
// H1: non-genesis resolution results must carry verifiable history
// -----------------------------------------------------------------------------

#[test]
fn updated_document_requires_verified_history() {
    let (doc1, ks1) = create("did:me:resolve-history");
    let (doc2, _) = no_op_update(&doc1, &ks1);
    let request = request(&doc2);

    assert_eq!(
        validate_resolution_result(&request, &resolution(doc2.clone(), Vec::new())),
        Err(DidApiError::ResolutionResultInvalid)
    );

    validate_resolution_result(&request, &resolution(doc2, vec![doc1]))
        .expect("history-authenticated resolution must validate");
}

#[test]
fn resolution_rejects_history_that_does_not_authorize_the_head() {
    let (doc1, ks1) = create("did:me:resolve-forged-history");
    let (doc2, _) = no_op_update(&doc1, &ks1);
    // Another DID's genesis cannot authorize this head.
    let (other, _) = create("did:me:resolve-other-history");
    let request = request(&doc2);

    assert_eq!(
        validate_resolution_result(&request, &resolution(doc2.clone(), vec![other])),
        Err(DidApiError::ResolutionResultInvalid)
    );

    // A genesis result must not smuggle in extra history.
    let genesis_request = self::request(&doc1);
    assert_eq!(
        validate_resolution_result(&genesis_request, &resolution(doc1.clone(), vec![doc1])),
        Err(DidApiError::ResolutionResultInvalid)
    );
}

#[test]
fn chain_validation_reports_stable_codes() {
    let (doc1, ks1) = create("did:me:chain-codes");
    let (doc2, _) = no_op_update(&doc1, &ks1);

    let empty = validate_did_chain(&[], no_domain_env());
    assert!(!empty.ok);
    assert!(empty
        .errors
        .iter()
        .any(|issue| issue.code == DidValidationCode::TransitionInvalid));

    let headless = validate_did_chain(std::slice::from_ref(&doc2), no_domain_env());
    assert!(!headless.ok);
    assert!(headless
        .errors
        .iter()
        .any(|issue| issue.code == DidValidationCode::TransitionAuthorityUnverified));

    let reversed = validate_did_chain(&[doc2.clone(), doc1.clone()], no_domain_env());
    assert!(!reversed.ok);

    let chain = validate_did_chain(&[doc1, doc2], no_domain_env());
    assert!(chain.ok, "{:?}", chain.errors);
}

// -----------------------------------------------------------------------------
// H2: freshness is enforced against a caller-trusted clock
// -----------------------------------------------------------------------------

#[test]
fn freshness_rejects_stale_and_future_observations() {
    let (doc, _) = create("did:me:resolve-freshness");
    let result = resolution(doc.clone(), Vec::new());
    let with_now = |now: i64, staleness: u64| {
        let mut selected = request(&doc);
        selected.freshness = Some(DidResolutionFreshness {
            maximum_staleness_seconds: staleness,
            trusted_now_unix_seconds: now,
        });
        selected
    };

    // Within the staleness bound.
    validate_resolution_result(&with_now(RETRIEVED_UNIX_SECONDS + 60, 60), &result)
        .expect("fresh observation must validate");

    // Older than the staleness bound.
    assert_eq!(
        validate_resolution_result(&with_now(RETRIEVED_UNIX_SECONDS + 61, 60), &result),
        Err(DidApiError::ResolutionResultInvalid)
    );

    // Too far in the future of the trusted clock.
    let skew = i64::try_from(MAX_DID_RESOLUTION_CLOCK_SKEW_SECONDS).unwrap();
    assert_eq!(
        validate_resolution_result(&with_now(RETRIEVED_UNIX_SECONDS - skew - 1, 60), &result),
        Err(DidApiError::ResolutionResultInvalid)
    );
    validate_resolution_result(&with_now(RETRIEVED_UNIX_SECONDS - skew, 60), &result)
        .expect("observation within clock skew must validate");

    // Absent results are subject to the same bound.
    let absent = DidResolutionResult {
        history: Vec::new(),
        document: None,
        document_metadata: None,
        resolution_metadata: DidResolutionMetadata {
            content_type: None,
            retrieved_at: Some(RETRIEVED.into()),
            resolver: None,
            error: Some(DidResolutionErrorCode::NotFound),
            assurance_achieved: None,
            sequence: None,
            deactivation_status: DidDeactivationStatus::Absent,
        },
    };
    assert_eq!(
        validate_resolution_result(&with_now(RETRIEVED_UNIX_SECONDS + 3_600, 60), &absent),
        Err(DidApiError::ResolutionResultInvalid)
    );
}

// -----------------------------------------------------------------------------
// H3: historical selection honours the registry validity window
// -----------------------------------------------------------------------------

#[test]
fn version_time_must_fall_within_validity_window() {
    let (doc, _) = create("did:me:resolve-version-window");
    let mut result = resolution(doc.clone(), Vec::new());
    if let Some(metadata) = result.document_metadata.as_mut() {
        metadata.updated = Some("2025-01-01T00:00:00Z".into());
        metadata.valid_from = Some("2025-06-01T00:00:00Z".into());
        metadata.valid_until = Some("2025-09-01T00:00:00Z".into());
        metadata.next_version_id = Some("next".into());
    }
    let at = |instant: &str| {
        let mut selected = request(&doc);
        selected.version_time = Some(instant.into());
        selected
    };

    validate_resolution_result(&at("2025-07-01T00:00:00Z"), &result)
        .expect("selected instant inside the window must validate");
    validate_resolution_result(&at("2025-06-01T00:00:00Z"), &result)
        .expect("the inclusive start bound must validate");
    for outside in [
        "2025-05-01T00:00:00Z",
        "2025-09-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
    ] {
        assert_eq!(
            validate_resolution_result(&at(outside), &result),
            Err(DidApiError::ResolutionResultInvalid)
        );
    }

    // A superseded version without its end bound cannot be selected.
    if let Some(metadata) = result.document_metadata.as_mut() {
        metadata.valid_until = None;
    }
    assert_eq!(
        validate_resolution_result(&at("2025-07-01T00:00:00Z"), &result),
        Err(DidApiError::ResolutionResultInvalid)
    );

    // Without a selector only the current version is acceptable.
    if let Some(metadata) = result.document_metadata.as_mut() {
        metadata.valid_until = Some("2025-09-01T00:00:00Z".into());
    }
    assert_eq!(
        validate_resolution_result(&request(&doc), &result),
        Err(DidApiError::ResolutionResultInvalid)
    );
}

// -----------------------------------------------------------------------------
// L1: the generic resolver validates did:me only
// -----------------------------------------------------------------------------

#[test]
fn generic_resolution_rejects_other_methods_as_unsupported() {
    let absent = DidResolutionResult {
        history: Vec::new(),
        document: None,
        document_metadata: None,
        resolution_metadata: DidResolutionMetadata {
            content_type: None,
            retrieved_at: None,
            resolver: None,
            error: Some(DidResolutionErrorCode::NotFound),
            assurance_achieved: None,
            sequence: None,
            deactivation_status: DidDeactivationStatus::Absent,
        },
    };
    for did in ["did:web:example.com", "did:ebsi:zub5ZZUfHLLptCduwEy8xRj"] {
        let request = DidResolveRequest {
            did: did.into(),
            version_id: None,
            version_time: None,
            minimum_version_sequence: None,
            assurance: None,
            freshness: None,
        };
        assert_eq!(
            validate_resolution_result(&request, &absent),
            Err(DidApiError::UnsupportedDidMethod)
        );
    }
}
