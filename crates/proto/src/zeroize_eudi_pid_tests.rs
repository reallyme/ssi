// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    pb, zeroize_eudi_catalogue_document, zeroize_eudi_legal_person_pid,
    zeroize_eudi_natural_person_pid, zeroize_eudi_pid_allocation, zeroize_eudi_pid_revocation,
};

#[test]
fn natural_person_cleanup_clears_biometric_and_identity_material() {
    let mut facts = pb::EudiNaturalPersonPidFacts::default();
    let claims = facts.claims.get_or_insert_default();
    claims.family_name = "Sensitive Family".to_owned();
    claims.given_name = "Sensitive Given".to_owned();
    claims.email = Some("sensitive@example.invalid".to_owned());
    claims.portrait.get_or_insert_default().value = Some(
        pb::__buffa::oneof::eudi_pid_portrait::Value::MdocJpeg(vec![1, 2, 3, 4]),
    );
    facts
        .provider_metadata
        .get_or_insert_default()
        .document_number = Some("SECRET-DOC".to_owned());

    zeroize_eudi_natural_person_pid(&mut facts);

    assert!(!facts.claims.is_set());
    assert!(!facts.provider_metadata.is_set());
    assert!(facts.format_facts.is_none());
}

#[test]
fn legal_allocation_revocation_and_catalogue_cleanup_clear_payloads() {
    let mut legal = pb::EudiLegalPersonPidFacts {
        current_legal_name: "Sensitive Entity".to_owned(),
        vat_registration_number: Some("VAT-SECRET".to_owned()),
        ..Default::default()
    };
    zeroize_eudi_legal_person_pid(&mut legal);
    assert!(legal.current_legal_name.is_empty());
    assert!(legal.vat_registration_number.is_none());

    let mut allocation = pb::EudiPidAllocationFacts::default();
    allocation
        .candidate
        .get_or_insert_default()
        .subject_reference = vec![7; 32];
    zeroize_eudi_pid_allocation(&mut allocation);
    assert!(!allocation.candidate.is_set());

    let mut revocation = pb::EudiPidRevocationFacts {
        issuer_identifier: "issuer-secret".to_owned(),
        revoking_actor_identifier: "actor-secret".to_owned(),
        ..Default::default()
    };
    zeroize_eudi_pid_revocation(&mut revocation);
    assert!(revocation.issuer_identifier.is_empty());
    assert!(revocation.revoking_actor_identifier.is_empty());

    let mut catalogue = pb::EudiCatalogueDocument {
        json: br#"{"sensitive":true}"#.to_vec(),
        ..Default::default()
    };
    zeroize_eudi_catalogue_document(&mut catalogue);
    assert!(catalogue.json.is_empty());
}
