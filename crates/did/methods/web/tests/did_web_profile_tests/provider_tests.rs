// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::Cell;

use reallyme_did_method_web::{
    create_did_web_document, deactivate_did_web_document, parse_and_validate_did_web_document,
    parse_did_web, resolve_did_web_document, update_did_web_document, DidWebDocumentLimits,
    DidWebErrorReason, DidWebHostingOperation, DidWebResolutionPolicy,
    PublicInternetDestinationPolicy,
};

use super::{
    document_json, success_response, MockHostingProvider, MockNetwork, NeverCancelled, DID,
    PUBLIC_ADDRESS,
};

#[test]
fn authenticated_provider_supports_create_update_deactivate_and_round_trip(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = MockHostingProvider {
        authenticated: true,
        calls: Cell::new(0),
        wrong_receipt: false,
    };
    let document = document_json(DID);
    let created = create_did_web_document(
        Some(&provider),
        DID,
        &document,
        DidWebDocumentLimits::default(),
    )?;
    assert_eq!(created.document.id(), Some(DID));
    let updated = update_did_web_document(
        Some(&provider),
        DID,
        &document,
        DidWebDocumentLimits::default(),
    )?;
    assert_eq!(updated.receipt.operation, DidWebHostingOperation::Update);
    let receipt = deactivate_did_web_document(Some(&provider), DID)?;
    assert_eq!(receipt.operation, DidWebHostingOperation::Deactivate);
    assert_eq!(provider.calls.get(), 3);

    let network = MockNetwork::new(
        vec![vec![PUBLIC_ADDRESS]],
        vec![success_response(document, PUBLIC_ADDRESS)],
    );
    let resolved = resolve_did_web_document(
        &network,
        &PublicInternetDestinationPolicy,
        &NeverCancelled,
        DID,
        DidWebResolutionPolicy::default(),
    )?;
    assert_eq!(resolved.document.id(), created.document.id());
    Ok(())
}

#[test]
fn hosting_fails_closed_without_authenticated_provider() {
    let document = document_json(DID);
    assert_eq!(
        create_did_web_document(None, DID, &document, DidWebDocumentLimits::default())
            .err()
            .map(|error| error.reason),
        Some(DidWebErrorReason::ProviderUnavailable)
    );
    let provider = MockHostingProvider {
        authenticated: false,
        calls: Cell::new(0),
        wrong_receipt: false,
    };
    assert_eq!(
        update_did_web_document(
            Some(&provider),
            DID,
            &document,
            DidWebDocumentLimits::default()
        )
        .err()
        .map(|error| error.reason),
        Some(DidWebErrorReason::ProviderUnauthenticated)
    );
    assert_eq!(provider.calls.get(), 0);
}

#[test]
fn document_validation_rejects_resources_owned_by_other_dids(
) -> Result<(), Box<dyn std::error::Error>> {
    let requested = parse_did_web(DID)?;
    let foreign_method = format!(
        r#"{{"id":"{DID}","verificationMethod":[{{"id":"did:web:attacker.example#key-1","type":"Multikey","controller":"{DID}","publicKeyMultibase":"z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"}}],"authentication":["did:web:attacker.example#key-1"]}}"#
    );
    let foreign_service = format!(
        r#"{{"id":"{DID}","service":[{{"id":"did:web:attacker.example#inbox","type":"MessagingService","serviceEndpoint":"https://attacker.example/inbox"}}]}}"#
    );
    let foreign_embedded = format!(
        r#"{{"id":"{DID}","authentication":[{{"id":"did:web:attacker.example#key-2","type":"Multikey","controller":"{DID}","publicKeyMultibase":"z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"}}]}}"#
    );
    for document in [foreign_method, foreign_service, foreign_embedded] {
        assert_eq!(
            parse_and_validate_did_web_document(
                &requested,
                document.as_bytes(),
                DidWebDocumentLimits::default(),
            )
            .err()
            .map(|error| error.reason),
            Some(DidWebErrorReason::DocumentIdentifierMismatch)
        );
    }

    let external_reference =
        format!(r#"{{"id":"{DID}","authentication":["did:web:controller.example#key-1"]}}"#);
    assert_eq!(
        parse_and_validate_did_web_document(
            &requested,
            external_reference.as_bytes(),
            DidWebDocumentLimits::default(),
        )
        .err()
        .map(|error| error.reason),
        Some(DidWebErrorReason::UnresolvedRelationshipReference)
    );

    let base_did_method = format!(
        r#"{{"id":"{DID}","verificationMethod":[{{"id":"{DID}","type":"Multikey","controller":"{DID}","publicKeyMultibase":"z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"}}],"authentication":["{DID}"]}}"#
    );
    assert!(parse_and_validate_did_web_document(
        &requested,
        base_did_method.as_bytes(),
        DidWebDocumentLimits::default(),
    )
    .is_err());
    Ok(())
}

#[test]
fn document_validation_accepts_public_jwk_key_ops() -> Result<(), Box<dyn std::error::Error>> {
    let requested = parse_did_web(DID)?;
    let body = format!(
        r#"{{"id":"{DID}","verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","key_ops":["verify"]}}}}]}}"#
    );
    parse_and_validate_did_web_document(
        &requested,
        body.as_bytes(),
        DidWebDocumentLimits::default(),
    )?;
    Ok(())
}
