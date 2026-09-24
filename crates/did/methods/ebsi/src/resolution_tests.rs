// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    validate_did_ebsi_resolution, DidEbsiRegistryMetadata, DidEbsiResolution,
    DidEbsiResolutionAssurance, DidEbsiResolutionStatus, DidEbsiResolveRequest,
};
use crate::{parse_and_validate_did_ebsi_document, DidEbsiDocumentLimits, DidEbsiErrorReason};

const DID: &str = "did:ebsi:zub5ZZUfHLLptCduwEy8xRj";
const COORDINATE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn document() -> Result<crate::DidEbsiDocument, crate::DidEbsiError> {
    let bytes = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":"{DID}","verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","key_ops":["verify"],"x":"{COORDINATE}","y":"{COORDINATE}"}}}}],"assertionMethod":["{DID}#key-1"],"capabilityInvocation":["{DID}#key-1"]}}"#
    );
    parse_and_validate_did_ebsi_document(DID, bytes.as_bytes(), DidEbsiDocumentLimits::default())
}

fn request(version_id: Option<&str>, version_time: Option<&str>) -> DidEbsiResolveRequest {
    DidEbsiResolveRequest {
        did: DID.to_owned(),
        version_id: version_id.map(str::to_owned),
        version_time: version_time.map(str::to_owned),
        minimum_version_sequence: None,
    }
}

fn active() -> Result<DidEbsiResolution, crate::DidEbsiError> {
    Ok(DidEbsiResolution {
        document: Some(document()?),
        registry_metadata: Some(DidEbsiRegistryMetadata {
            version_id: "version-7".to_owned(),
            version_sequence: 7,
            previous_version_id: Some("version-6".to_owned()),
            valid_from: "2026-01-01T00:00:00Z".to_owned(),
            valid_until: Some("2026-03-01T00:00:00Z".to_owned()),
        }),
        status: DidEbsiResolutionStatus::Active,
        retrieved_at: Some("2026-02-15T00:00:00Z".to_owned()),
        resolver: Some("registry".to_owned()),
        assurance_achieved: Some(DidEbsiResolutionAssurance::ChainVerified),
    })
}

#[test]
fn historical_time_and_version_selectors_are_correlated() -> Result<(), crate::DidEbsiError> {
    assert!(
        validate_did_ebsi_resolution(&request(None, Some("2026-02-01T00:00:00Z")), &active()?,)
            .is_ok()
    );
    assert!(validate_did_ebsi_resolution(&request(Some("version-7"), None), &active()?).is_ok());
    Ok(())
}

#[test]
fn ambiguous_or_out_of_interval_selection_fails_closed() -> Result<(), crate::DidEbsiError> {
    let cases = [
        request(Some("version-7"), Some("2026-02-01T00:00:00Z")),
        request(None, Some("2025-12-31T23:59:59Z")),
        request(Some("version-8"), None),
    ];
    for value in cases {
        let reason = validate_did_ebsi_resolution(&value, &active()?)
            .err()
            .map(|error| error.reason);
        assert!(matches!(
            reason,
            Some(
                DidEbsiErrorReason::InvalidVersionSelector
                    | DidEbsiErrorReason::HistoricalVersionMismatch
            )
        ));
    }
    Ok(())
}

#[test]
fn absent_and_present_result_shapes_cannot_be_conflated() -> Result<(), crate::DidEbsiError> {
    let malformed_absent = DidEbsiResolution {
        document: Some(document()?),
        registry_metadata: None,
        status: DidEbsiResolutionStatus::Absent,
        retrieved_at: None,
        resolver: None,
        assurance_achieved: None,
    };
    assert_eq!(
        validate_did_ebsi_resolution(&request(None, None), &malformed_absent)
            .err()
            .map(|error| error.reason),
        Some(DidEbsiErrorReason::ResolutionResultInvalid)
    );

    let missing_document = DidEbsiResolution {
        document: None,
        registry_metadata: Some(DidEbsiRegistryMetadata {
            version_id: "version-7".to_owned(),
            version_sequence: 7,
            previous_version_id: Some("version-6".to_owned()),
            valid_from: "2026-01-01T00:00:00Z".to_owned(),
            valid_until: None,
        }),
        status: DidEbsiResolutionStatus::Deactivated,
        retrieved_at: None,
        resolver: None,
        assurance_achieved: None,
    };
    assert_eq!(
        validate_did_ebsi_resolution(&request(None, None), &missing_document)
            .err()
            .map(|error| error.reason),
        Some(DidEbsiErrorReason::ResolutionResultInvalid)
    );
    Ok(())
}

#[test]
fn rejects_latest_substitution_unverified_history_and_registry_rollback(
) -> Result<(), crate::DidEbsiError> {
    let mut latest_substitution = active()?;
    if let Some(metadata) = latest_substitution.registry_metadata.as_mut() {
        metadata.valid_from = "2026-03-01T00:00:00Z".to_owned();
        metadata.valid_until = None;
    }
    assert_eq!(
        validate_did_ebsi_resolution(
            &request(None, Some("2026-02-01T00:00:00Z")),
            &latest_substitution,
        )
        .err()
        .map(|error| error.reason),
        Some(DidEbsiErrorReason::HistoricalVersionMismatch)
    );

    let mut unverified = active()?;
    unverified.assurance_achieved = Some(DidEbsiResolutionAssurance::AttestationVerified);
    assert_eq!(
        validate_did_ebsi_resolution(&request(None, Some("2026-02-01T00:00:00Z")), &unverified,)
            .err()
            .map(|error| error.reason),
        Some(DidEbsiErrorReason::HistoricalVersionMismatch)
    );

    let mut rollback_request = request(None, Some("2026-02-01T00:00:00Z"));
    rollback_request.minimum_version_sequence = Some(8);
    assert_eq!(
        validate_did_ebsi_resolution(&rollback_request, &active()?)
            .err()
            .map(|error| error.reason),
        Some(DidEbsiErrorReason::RollbackDetected)
    );
    Ok(())
}
