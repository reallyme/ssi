// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test coverage for DID parse, dereference, and resolver taxonomy commands.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use reallyme_did_api::{
    create::create_did,
    dereference::{dereference_did_url, DereferencedResource, DidDereferenceRequest},
    error::DidApiError,
    parse::{parse_did, DidParseRequest},
    profile::DidProfile,
    resolve::{
        resolve_did_with_provider, resolve_did_with_provider_owned, validate_resolution_result,
        DidDeactivationStatus, DidDocumentMetadata, DidProvider, DidResolutionAssurance,
        DidResolutionErrorCode, DidResolutionFreshness, DidResolutionMetadata, DidResolutionResult,
        DidResolveRequest, MAX_DID_RESOLUTION_IDENTIFIER_BYTES,
    },
    update::deactivate_did_validated,
    CreateConfig,
};
use reallyme_did_types::{DIDDocument, Service};
use serde_json::json;
use zeroize::Zeroize;

fn create_config() -> CreateConfig {
    CreateConfig {
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
        created: Some("2025-01-01T00:00:00Z".into()),
    }
}

fn active_resolution(doc: DIDDocument) -> DidResolutionResult {
    DidResolutionResult {
        resolution_metadata: DidResolutionMetadata {
            content_type: Some("application/did+json".into()),
            retrieved_at: None,
            resolver: Some("test".into()),
            error: None,
            assurance_achieved: Some(DidResolutionAssurance::AttestationVerified),
            sequence: Some(doc.sequence),
            deactivation_status: DidDeactivationStatus::Active,
        },
        document_metadata: Some(DidDocumentMetadata {
            created: None,
            updated: None,
            deactivated: false,
            version_id: Some(doc.current_core.clone()),
            next_version_id: None,
            valid_from: None,
            valid_until: None,
        }),
        document: Some(doc),
    }
}

#[test]
fn parse_valid_did_me_url_offline() {
    let (doc, _) = create_did(create_config(), "did:me:parse-valid").expect("create failed");
    let did_url = {
        let mut value = doc.id.clone();
        value.push_str("#ed25519");
        value
    };

    let parsed = parse_did(DidParseRequest { did_url }).expect("parse failed");

    assert_eq!(parsed.did, doc.id);
    assert_eq!(parsed.method, "me");
    assert_eq!(parsed.fragment, Some("ed25519".into()));
    assert!(parsed.is_did_url);
    assert!(parsed.method_supported);
}

#[test]
fn parse_rejects_invalid_did_me_method_identifier() {
    let err = parse_did(DidParseRequest {
        did_url: "did:me:ME1072E0A7MYHEE5DA50WT3TU2A9SDS44XV".into(),
    })
    .unwrap_err();

    assert_eq!(err, DidApiError::InvalidDid);
}

#[test]
fn dereference_returns_whole_document_without_fragment() {
    let (doc, _) = create_did(create_config(), "did:me:deref-doc").expect("create failed");

    let result = dereference_did_url(
        &doc,
        DidDereferenceRequest {
            did_url: doc.id.clone(),
        },
    )
    .expect("dereference failed");

    match result.resource {
        DereferencedResource::Document(document) => assert_eq!(document.id, doc.id),
        _ => panic!("expected DID document"),
    }
}

#[test]
fn dereference_returns_verification_method_fragment() {
    let (doc, _) = create_did(create_config(), "did:me:deref-vm").expect("create failed");
    let did_url = {
        let mut value = doc.id.clone();
        value.push_str("#ed25519");
        value
    };

    let result =
        dereference_did_url(&doc, DidDereferenceRequest { did_url }).expect("dereference failed");

    match result.resource {
        DereferencedResource::VerificationMethod(vm) => assert_eq!(vm.id, "#ed25519"),
        _ => panic!("expected verification method"),
    }
}

#[test]
fn dereference_returns_service_fragment() {
    let (mut doc, _) = create_did(create_config(), "did:me:deref-service").expect("create failed");
    doc.service = vec![Service {
        id: "#messaging".into(),
        service_type: "MessagingService".into(),
        service_endpoint: json!({
            "uri": "https://relay.example.com/inbox/7f3a",
            "preKeys": ["#x25519", "#mlkem768"]
        }),
    }];
    let did_url = {
        let mut value = doc.id.clone();
        value.push_str("#messaging");
        value
    };

    let result =
        dereference_did_url(&doc, DidDereferenceRequest { did_url }).expect("dereference failed");

    match result.resource {
        DereferencedResource::Service(service) => assert_eq!(service.id, "#messaging"),
        _ => panic!("expected service"),
    }
}

#[test]
fn dereference_fails_closed_for_path_or_query_without_provider() {
    let (doc, _) = create_did(create_config(), "did:me:deref-path").expect("create failed");
    let did_url = {
        let mut value = doc.id.clone();
        value.push_str("/credentials?service=issuer");
        value
    };

    let err = dereference_did_url(&doc, DidDereferenceRequest { did_url }).unwrap_err();

    assert_eq!(err, DidApiError::UnsupportedDidUrl);
}

#[test]
fn validate_resolution_result_accepts_active_document() {
    let (doc, _) = create_did(create_config(), "did:me:resolve-active").expect("create failed");
    let request = DidResolveRequest {
        did: doc.id.clone(),
        version_id: Some(doc.current_core.clone()),
        version_time: None,
        minimum_version_sequence: None,
        assurance: None,
        freshness: None,
    };
    let result = active_resolution(doc);

    validate_resolution_result(&request, &result).expect("resolution should validate");
}

#[test]
fn validate_resolution_result_rejects_absent_with_document() {
    let (doc, _) = create_did(create_config(), "did:me:resolve-absent").expect("create failed");
    let request = DidResolveRequest {
        did: doc.id.clone(),
        version_id: None,
        version_time: None,
        minimum_version_sequence: None,
        assurance: None,
        freshness: None,
    };
    let mut result = active_resolution(doc);
    result.resolution_metadata.deactivation_status = DidDeactivationStatus::Absent;
    result.resolution_metadata.error = Some(DidResolutionErrorCode::NotFound);

    let err = validate_resolution_result(&request, &result).unwrap_err();

    assert_eq!(err, DidApiError::ResolutionResultInvalid);
}

#[test]
fn validate_resolution_result_requires_typed_not_found_for_absent_result() {
    let (doc, _) =
        create_did(create_config(), "did:me:resolve-absent-error").expect("create failed");
    let request = DidResolveRequest {
        did: doc.id.clone(),
        version_id: None,
        version_time: None,
        minimum_version_sequence: None,
        assurance: None,
        freshness: None,
    };
    let result = DidResolutionResult {
        document: None,
        resolution_metadata: DidResolutionMetadata {
            content_type: None,
            retrieved_at: None,
            resolver: Some("test".into()),
            error: None,
            assurance_achieved: None,
            sequence: None,
            deactivation_status: DidDeactivationStatus::Absent,
        },
        document_metadata: None,
    };

    let err = validate_resolution_result(&request, &result).unwrap_err();

    assert_eq!(err, DidApiError::ResolutionResultInvalid);
}

#[test]
fn validate_resolution_result_rejects_oversized_request_before_provider_use() {
    let request = DidResolveRequest {
        did: "d".repeat(MAX_DID_RESOLUTION_IDENTIFIER_BYTES + 1),
        version_id: None,
        version_time: None,
        minimum_version_sequence: None,
        assurance: None,
        freshness: None,
    };
    let result = DidResolutionResult {
        document: None,
        resolution_metadata: DidResolutionMetadata {
            content_type: None,
            retrieved_at: None,
            resolver: None,
            error: Some(DidResolutionErrorCode::NotFound),
            assurance_achieved: None,
            sequence: None,
            deactivation_status: DidDeactivationStatus::Absent,
        },
        document_metadata: None,
    };

    let err = validate_resolution_result(&request, &result).unwrap_err();

    assert_eq!(err, DidApiError::InvalidDid);
}

#[test]
fn validate_resolution_result_rejects_unknown_requested_version() {
    let (doc, _) = create_did(create_config(), "did:me:resolve-version").expect("create failed");
    let request = DidResolveRequest {
        did: doc.id.clone(),
        version_id: Some("bafk-missing".into()),
        version_time: None,
        minimum_version_sequence: None,
        assurance: None,
        freshness: None,
    };
    let result = active_resolution(doc);

    let err = validate_resolution_result(&request, &result).unwrap_err();

    assert_eq!(err, DidApiError::ResolutionResultInvalid);
}

#[test]
fn validate_resolution_result_rejects_malformed_provider_timestamps() {
    let (doc, _) = create_did(create_config(), "did:me:resolve-timestamp").expect("create failed");
    let request = DidResolveRequest {
        did: doc.id.clone(),
        version_id: None,
        version_time: None,
        minimum_version_sequence: None,
        assurance: None,
        freshness: None,
    };
    let mut result = active_resolution(doc);
    result.resolution_metadata.retrieved_at = Some("not-a-timestamp".into());

    let err = validate_resolution_result(&request, &result).unwrap_err();

    assert_eq!(err, DidApiError::ResolutionResultInvalid);
}

#[test]
fn resolution_selectors_assurance_and_freshness_fail_closed() {
    let (doc, _) = create_did(create_config(), "did:me:resolve-policy").expect("create failed");
    let mut result = active_resolution(doc.clone());
    let ambiguous = DidResolveRequest {
        did: doc.id.clone(),
        version_id: Some(doc.current_core.clone()),
        version_time: Some("2026-02-01T00:00:00Z".into()),
        minimum_version_sequence: None,
        assurance: None,
        freshness: None,
    };
    assert_eq!(
        validate_resolution_result(&ambiguous, &result),
        Err(DidApiError::InvalidDid)
    );

    let policy = DidResolveRequest {
        did: doc.id.clone(),
        version_id: None,
        version_time: None,
        minimum_version_sequence: None,
        assurance: Some(DidResolutionAssurance::ChainVerified),
        freshness: Some(DidResolutionFreshness {
            maximum_staleness_seconds: 60,
        }),
    };
    assert_eq!(
        validate_resolution_result(&policy, &result),
        Err(DidApiError::ResolutionResultInvalid)
    );
    result.resolution_metadata.assurance_achieved = Some(DidResolutionAssurance::ChainVerified);
    result.resolution_metadata.retrieved_at = Some("2026-02-01T00:00:00Z".into());
    assert!(validate_resolution_result(&policy, &result).is_ok());
}

#[test]
fn validate_resolution_result_accepts_deactivation_document() {
    let (doc, ks) =
        create_did(create_config(), "did:me:resolve-deactivated").expect("create failed");
    let terminal = deactivate_did_validated(&doc, &ks)
        .expect("deactivate failed")
        .document;
    let request = DidResolveRequest {
        did: terminal.id.clone(),
        version_id: Some(terminal.current_core.clone()),
        version_time: None,
        minimum_version_sequence: None,
        assurance: None,
        freshness: None,
    };
    let result = DidResolutionResult {
        resolution_metadata: DidResolutionMetadata {
            content_type: Some("application/did+json".into()),
            retrieved_at: None,
            resolver: Some("test".into()),
            error: None,
            assurance_achieved: Some(DidResolutionAssurance::ChainVerified),
            sequence: Some(terminal.sequence),
            deactivation_status: DidDeactivationStatus::Deactivated,
        },
        document_metadata: Some(DidDocumentMetadata {
            created: None,
            updated: None,
            deactivated: true,
            version_id: Some(terminal.current_core.clone()),
            next_version_id: None,
            valid_from: None,
            valid_until: None,
        }),
        document: Some(terminal),
    };

    validate_resolution_result(&request, &result).expect("terminal result should validate");
}

struct StaticProvider {
    result: DidResolutionResult,
}

impl DidProvider for StaticProvider {
    fn resolve_did(&self, _request: DidResolveRequest) -> Result<DidResolutionResult, DidApiError> {
        Ok(self.result.clone())
    }
}

#[test]
fn resolve_did_with_provider_validates_provider_result() {
    let (doc, _) = create_did(create_config(), "did:me:resolve-provider").expect("create failed");
    let request = DidResolveRequest {
        did: doc.id.clone(),
        version_id: None,
        version_time: None,
        minimum_version_sequence: None,
        assurance: None,
        freshness: None,
    };
    let provider = StaticProvider {
        result: active_resolution(doc),
    };

    let result = resolve_did_with_provider(&provider, request).expect("resolve failed");

    assert_eq!(
        result.resolution_metadata.deactivation_status,
        DidDeactivationStatus::Active
    );
}

#[test]
fn owned_resolution_result_redacts_and_clears_provider_material() {
    let (doc, _) = create_did(create_config(), "did:me:resolve-owned").expect("create failed");
    let request = DidResolveRequest {
        did: doc.id.clone(),
        version_id: None,
        version_time: None,
        minimum_version_sequence: None,
        assurance: None,
        freshness: None,
    };
    assert_eq!(format!("{request:?}"), "DidResolveRequest(<redacted>)");
    let provider = StaticProvider {
        result: active_resolution(doc),
    };
    let mut result = resolve_did_with_provider_owned(&provider, request).expect("resolve failed");
    assert_eq!(
        format!("{result:?}"),
        "SensitiveDidResolutionResult(<redacted>)"
    );

    result.zeroize();

    assert!(result.as_result().document.is_none());
    assert!(result.as_result().document_metadata.is_none());
    assert!(result.as_result().resolution_metadata.resolver.is_none());
}
