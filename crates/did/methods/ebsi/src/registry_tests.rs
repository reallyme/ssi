// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::Cell;

use super::{
    write_did_ebsi_registry_document, AuthenticatedDidEbsiRegistryProvider,
    DidEbsiRegistryOperation, DidEbsiRegistryProviderError, DidEbsiRegistryWriteRequest,
    DidEbsiRegistryWriteResponse,
};
use crate::{DidEbsiDocumentLimits, DidEbsiErrorReason};

const DID: &str = "did:ebsi:zub5ZZUfHLLptCduwEy8xRj";
const KEY: &str = "did:ebsi:zub5ZZUfHLLptCduwEy8xRj#key-1";
const SECOND_KEY: &str = "did:ebsi:zub5ZZUfHLLptCduwEy8xRj#key-2";
const SECOND_CONTROLLER: &str = "did:ebsi:ztRBFfMCY7VAGHH1Ba8Q5o9";
const COORDINATE_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const COORDINATE_B: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE";

struct FixtureProvider {
    authenticated: bool,
    response_operation: DidEbsiRegistryOperation,
    called: Cell<bool>,
}

impl AuthenticatedDidEbsiRegistryProvider for FixtureProvider {
    fn is_authenticated_for(&self, _operation: DidEbsiRegistryOperation) -> bool {
        self.authenticated
    }

    fn execute(
        &self,
        request: DidEbsiRegistryWriteRequest<'_>,
    ) -> Result<DidEbsiRegistryWriteResponse, DidEbsiRegistryProviderError> {
        self.called.set(true);
        Ok(DidEbsiRegistryWriteResponse {
            operation: self.response_operation,
            version_id: "version-1".to_owned(),
            version_sequence: 1,
            valid_from: "2026-01-01T00:00:00Z".to_owned(),
            document_json: request.proposed_document.as_bytes().to_vec(),
        })
    }
}

fn active_document(coordinate: &str) -> Vec<u8> {
    format!(
        r#"{{"@context":["https://www.w3.org/ns/did/v1"],"id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{KEY}","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","key_ops":["verify"],"x":"{coordinate}","y":"{COORDINATE_A}"}}}}],"authentication":["{KEY}"],"assertionMethod":["{KEY}"],"capabilityInvocation":["{KEY}"]}}"#
    )
    .into_bytes()
}

fn inactive_document() -> Vec<u8> {
    format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":[],"verificationMethod":[],"authentication":[],"assertionMethod":[],"capabilityInvocation":[]}}"#
    )
    .into_bytes()
}

fn two_method_document(include_second: bool, relate_second: bool) -> Vec<u8> {
    let second_method = if include_second {
        format!(
            r#",{{"id":"{SECOND_KEY}","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","key_ops":["verify"],"x":"{COORDINATE_B}","y":"{COORDINATE_A}"}}}}"#
        )
    } else {
        String::new()
    };
    let second_relationship = if relate_second {
        format!(r#","{SECOND_KEY}""#)
    } else {
        String::new()
    };
    format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{KEY}","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","key_ops":["verify"],"x":"{COORDINATE_A}","y":"{COORDINATE_A}"}}}}{second_method}],"assertionMethod":["{KEY}"{second_relationship}],"capabilityInvocation":["{KEY}"]}}"#
    )
    .into_bytes()
}

fn controller_document(include_second: bool) -> Vec<u8> {
    let controllers = if include_second {
        format!(r#"["{DID}","{SECOND_CONTROLLER}"]"#)
    } else {
        format!(r#"["{DID}"]"#)
    };
    format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":{controllers},"verificationMethod":[{{"id":"{KEY}","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","key_ops":["verify"],"x":"{COORDINATE_A}","y":"{COORDINATE_A}"}}}}],"assertionMethod":["{KEY}"],"capabilityInvocation":["{KEY}"]}}"#
    )
    .into_bytes()
}

#[test]
fn registration_requires_injected_authenticated_provider_and_correlates_receipt() {
    let proposed = active_document(COORDINATE_A);
    let missing = write_did_ebsi_registry_document(
        None,
        DidEbsiRegistryOperation::RegisterDocument,
        DID,
        None,
        &proposed,
        KEY,
        None,
        None,
        DidEbsiDocumentLimits::default(),
    )
    .err()
    .map(|error| error.reason);
    assert_eq!(missing, Some(DidEbsiErrorReason::ProviderUnavailable));

    let unauthenticated = FixtureProvider {
        authenticated: false,
        response_operation: DidEbsiRegistryOperation::RegisterDocument,
        called: Cell::new(false),
    };
    let rejected = write_did_ebsi_registry_document(
        Some(&unauthenticated),
        DidEbsiRegistryOperation::RegisterDocument,
        DID,
        None,
        &proposed,
        KEY,
        None,
        None,
        DidEbsiDocumentLimits::default(),
    )
    .err()
    .map(|error| error.reason);
    assert_eq!(rejected, Some(DidEbsiErrorReason::ProviderUnauthenticated));
    assert!(!unauthenticated.called.get());

    let provider = FixtureProvider {
        authenticated: true,
        response_operation: DidEbsiRegistryOperation::RegisterDocument,
        called: Cell::new(false),
    };
    let result = write_did_ebsi_registry_document(
        Some(&provider),
        DidEbsiRegistryOperation::RegisterDocument,
        DID,
        None,
        &proposed,
        KEY,
        None,
        None,
        DidEbsiDocumentLimits::default(),
    );
    assert!(result.is_ok());
    assert!(provider.called.get());
}

#[test]
fn rotation_and_effective_deactivation_validate_exact_public_transitions() {
    let current = active_document(COORDINATE_A);
    let rotated = active_document(COORDINATE_B);
    let rotation_provider = FixtureProvider {
        authenticated: true,
        response_operation: DidEbsiRegistryOperation::RotateVerificationMethod,
        called: Cell::new(false),
    };
    let rotation = write_did_ebsi_registry_document(
        Some(&rotation_provider),
        DidEbsiRegistryOperation::RotateVerificationMethod,
        DID,
        Some(&current),
        &rotated,
        KEY,
        Some(KEY),
        Some("2026-01-01T00:00:00Z"),
        DidEbsiDocumentLimits::default(),
    );
    assert!(rotation.is_ok());

    let deactivation_provider = FixtureProvider {
        authenticated: true,
        response_operation: DidEbsiRegistryOperation::DeactivateKeys,
        called: Cell::new(false),
    };
    let deactivation = write_did_ebsi_registry_document(
        Some(&deactivation_provider),
        DidEbsiRegistryOperation::DeactivateKeys,
        DID,
        Some(&current),
        &inactive_document(),
        KEY,
        None,
        Some("2026-02-01T00:00:00Z"),
        DidEbsiDocumentLimits::default(),
    );
    assert!(deactivation.is_ok());
}

#[test]
fn rejects_unauthorized_malformed_and_mismatched_registry_writes() {
    let current = active_document(COORDINATE_A);
    let rotated = active_document(COORDINATE_B);
    let provider = FixtureProvider {
        authenticated: true,
        response_operation: DidEbsiRegistryOperation::UpdateDocument,
        called: Cell::new(false),
    };
    let cases = [
        write_did_ebsi_registry_document(
            Some(&provider),
            DidEbsiRegistryOperation::RotateVerificationMethod,
            DID,
            Some(&current),
            &rotated,
            "did:ebsi:zub5ZZUfHLLptCduwEy8xRj#missing",
            Some(KEY),
            Some("2026-01-01T00:00:00Z"),
            DidEbsiDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
        write_did_ebsi_registry_document(
            Some(&provider),
            DidEbsiRegistryOperation::RotateVerificationMethod,
            DID,
            Some(&current),
            &rotated,
            KEY,
            Some(KEY),
            Some("not-a-time"),
            DidEbsiDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
        write_did_ebsi_registry_document(
            Some(&provider),
            DidEbsiRegistryOperation::RotateVerificationMethod,
            DID,
            Some(&current),
            &rotated,
            KEY,
            Some(KEY),
            Some("2026-01-01T00:00:00Z"),
            DidEbsiDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
    ];
    assert_eq!(cases[0], Some(DidEbsiErrorReason::UnauthorizedWrite));
    assert_eq!(cases[1], Some(DidEbsiErrorReason::InvalidTimeline));
    assert_eq!(cases[2], Some(DidEbsiErrorReason::ProviderFailure));
}

#[test]
fn controller_method_and_relationship_operations_require_exact_transitions() {
    let cases = [
        (
            DidEbsiRegistryOperation::AddController,
            controller_document(false),
            controller_document(true),
            SECOND_CONTROLLER,
        ),
        (
            DidEbsiRegistryOperation::RevokeController,
            controller_document(true),
            controller_document(false),
            SECOND_CONTROLLER,
        ),
        (
            DidEbsiRegistryOperation::AddVerificationMethod,
            two_method_document(false, false),
            two_method_document(true, false),
            SECOND_KEY,
        ),
        (
            DidEbsiRegistryOperation::AddVerificationRelationship,
            two_method_document(true, false),
            two_method_document(true, true),
            SECOND_KEY,
        ),
        (
            DidEbsiRegistryOperation::RevokeVerificationRelationship,
            two_method_document(true, true),
            two_method_document(true, false),
            SECOND_KEY,
        ),
    ];
    for (operation, current, proposed, target) in cases {
        let provider = FixtureProvider {
            authenticated: true,
            response_operation: operation,
            called: Cell::new(false),
        };
        let result = write_did_ebsi_registry_document(
            Some(&provider),
            operation,
            DID,
            Some(&current),
            &proposed,
            KEY,
            Some(target),
            None,
            DidEbsiDocumentLimits::default(),
        );
        assert!(result.is_ok(), "operation {operation:?} was rejected");
    }
}

#[test]
fn expiration_and_revocation_remove_the_exact_key_and_relationships() {
    let current = two_method_document(true, true);
    let proposed = two_method_document(false, false);
    for operation in [
        DidEbsiRegistryOperation::ExpireVerificationMethod,
        DidEbsiRegistryOperation::RevokeVerificationMethod,
    ] {
        let provider = FixtureProvider {
            authenticated: true,
            response_operation: operation,
            called: Cell::new(false),
        };
        let result = write_did_ebsi_registry_document(
            Some(&provider),
            operation,
            DID,
            Some(&current),
            &proposed,
            KEY,
            Some(SECOND_KEY),
            Some("2026-02-15T00:00:00Z"),
            DidEbsiDocumentLimits::default(),
        );
        assert!(result.is_ok(), "operation {operation:?} was rejected");
    }
}
