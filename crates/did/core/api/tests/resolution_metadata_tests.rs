// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Field-level DID resolution metadata boundary coverage.
#![allow(missing_docs, clippy::expect_used)]

use reallyme_did_api::{
    create::create_did,
    error::DidApiError,
    profile::DidProfile,
    resolve::{
        validate_resolution_result, DidDeactivationStatus, DidDocumentMetadata,
        DidResolutionAssurance, DidResolutionErrorCode, DidResolutionFreshness,
        DidResolutionMetadata, DidResolutionResult, DidResolveRequest,
    },
    CreateConfig,
};
use reallyme_did_types::DIDDocument;

const CREATED: &str = "2025-01-01T00:00:00Z";
const UPDATED: &str = "2025-06-01T00:00:00Z";
const RETRIEVED: &str = "2026-09-14T12:00:00Z";

fn document() -> DIDDocument {
    let config = CreateConfig {
        profile: Some(DidProfile::CoreIdentity),
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
        created: Some(CREATED.into()),
    };
    create_did(config, "did:me:resolution-metadata")
        .expect("fixture creation must succeed")
        .0
}

fn request(doc: &DIDDocument) -> DidResolveRequest {
    DidResolveRequest {
        did: doc.id.clone(),
        version_id: Some(doc.current_core.clone()),
        version_time: None,
        minimum_version_sequence: None,
        assurance: Some(DidResolutionAssurance::ChainVerified),
        freshness: Some(DidResolutionFreshness {
            maximum_staleness_seconds: 60,
        }),
    }
}

fn complete_result(doc: DIDDocument) -> DidResolutionResult {
    DidResolutionResult {
        resolution_metadata: DidResolutionMetadata {
            content_type: Some("application/did+json".into()),
            retrieved_at: Some(RETRIEVED.into()),
            resolver: Some("did-me-history".into()),
            error: None,
            assurance_achieved: Some(DidResolutionAssurance::ChainVerified),
            sequence: Some(doc.sequence),
            deactivation_status: DidDeactivationStatus::Active,
        },
        document_metadata: Some(DidDocumentMetadata {
            created: Some(CREATED.into()),
            updated: Some(UPDATED.into()),
            deactivated: false,
            version_id: Some(doc.current_core.clone()),
            next_version_id: Some("next-version".into()),
            valid_from: None,
            valid_until: None,
        }),
        document: Some(doc),
    }
}

fn assert_invalid(request: &DidResolveRequest, result: &DidResolutionResult) {
    assert_eq!(
        validate_resolution_result(request, result),
        Err(DidApiError::ResolutionResultInvalid)
    );
}

#[test]
fn complete_resolution_metadata_crosses_the_validation_boundary() {
    let doc = document();
    let request = request(&doc);
    let result = complete_result(doc);

    validate_resolution_result(&request, &result)
        .expect("complete, correlated resolution metadata must validate");
}

#[test]
fn malformed_resolution_metadata_fields_fail_closed_independently() {
    let doc = document();
    let request = request(&doc);
    let valid = complete_result(doc);

    let mut result = valid.clone();
    result.resolution_metadata.content_type = Some("text/plain".into());
    assert_invalid(&request, &result);

    let mut result = valid.clone();
    result.resolution_metadata.retrieved_at = Some("not-a-timestamp".into());
    assert_invalid(&request, &result);

    let mut result = valid.clone();
    result.resolution_metadata.resolver = Some(String::new());
    assert_invalid(&request, &result);

    let mut result = valid.clone();
    result.resolution_metadata.error = Some(DidResolutionErrorCode::ResolverFailure);
    assert_invalid(&request, &result);

    let mut result = valid.clone();
    result.resolution_metadata.assurance_achieved =
        Some(DidResolutionAssurance::AttestationVerified);
    assert_invalid(&request, &result);

    let mut result = valid.clone();
    result.resolution_metadata.sequence = result
        .resolution_metadata
        .sequence
        .and_then(|value| value.checked_add(1));
    assert_invalid(&request, &result);
}

#[test]
fn malformed_document_metadata_fields_fail_closed_independently() {
    let doc = document();
    let request = request(&doc);
    let valid = complete_result(doc);

    let mut result = valid.clone();
    result
        .document_metadata
        .as_mut()
        .expect("fixture metadata must exist")
        .created = Some("not-a-timestamp".into());
    assert_invalid(&request, &result);

    let mut result = valid.clone();
    result
        .document_metadata
        .as_mut()
        .expect("fixture metadata must exist")
        .updated = Some("not-a-timestamp".into());
    assert_invalid(&request, &result);

    let mut result = valid.clone();
    result
        .document_metadata
        .as_mut()
        .expect("fixture metadata must exist")
        .deactivated = true;
    assert_invalid(&request, &result);

    let mut result = valid.clone();
    result
        .document_metadata
        .as_mut()
        .expect("fixture metadata must exist")
        .version_id = Some(String::new());
    assert_invalid(&request, &result);

    let mut result = valid;
    result
        .document_metadata
        .as_mut()
        .expect("fixture metadata must exist")
        .next_version_id = Some(String::new());
    assert_invalid(&request, &result);
}
