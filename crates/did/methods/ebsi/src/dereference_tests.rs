// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{dereference_did_ebsi_document, DidEbsiDereferenceKind};
use crate::{parse_and_validate_did_ebsi_document, DidEbsiDocumentLimits, DidEbsiErrorReason};

const DID: &str = "did:ebsi:zub5ZZUfHLLptCduwEy8xRj";
const P256_X: &str = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY";
const P256_Y: &str = "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU";

fn document() -> Result<crate::DidEbsiDocument, crate::DidEbsiError> {
    let bytes = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{DID}","controller":["{DID}"],"verificationMethod":[{{"id":"{DID}#key-1","type":"JsonWebKey2020","controller":"{DID}","publicKeyJwk":{{"kty":"EC","crv":"P-256","alg":"ES256","x":"{P256_X}","y":"{P256_Y}"}}}}],"capabilityInvocation":["{DID}#key-1"],"service":[{{"id":"{DID}#registry","type":"LinkedDomains","serviceEndpoint":"https://legal-entity.example.test"}}]}}"#
    );
    parse_and_validate_did_ebsi_document(DID, bytes.as_bytes(), DidEbsiDocumentLimits::default())
}

#[test]
fn dereferences_document_verification_method_and_service() -> Result<(), crate::DidEbsiError> {
    let document = document()?;
    let complete = dereference_did_ebsi_document(&document, DID);
    assert!(matches!(
        complete.as_ref().map(|value| value.kind),
        Ok(DidEbsiDereferenceKind::Document)
    ));
    let method = dereference_did_ebsi_document(&document, &format!("{DID}#key-1"));
    assert!(matches!(
        method.as_ref().map(|value| value.kind),
        Ok(DidEbsiDereferenceKind::Fragment)
    ));
    let service = dereference_did_ebsi_document(&document, &format!("{DID}#registry"));
    assert!(matches!(
        service.as_ref().map(|value| value.kind),
        Ok(DidEbsiDereferenceKind::Fragment)
    ));
    Ok(())
}

#[test]
fn rejects_relative_noncanonical_and_unresolved_did_urls() -> Result<(), crate::DidEbsiError> {
    let document = document()?;
    for did_url in [
        "#key-1",
        "did:ebsi:zub5ZZUfHLLptCduwEy8xRj/path",
        "did:ebsi:zub5ZZUfHLLptCduwEy8xRj?service=registry",
        "did:ebsi:zub5ZZUfHLLptCduwEy8xRj#key%2D1",
        "did:ebsi:zub5ZZUfHLLptCduwEy8xRj#missing",
    ] {
        assert_eq!(
            dereference_did_ebsi_document(&document, did_url)
                .err()
                .map(|error| error.reason),
            Some(DidEbsiErrorReason::InvalidDidUrl)
        );
    }
    Ok(())
}
