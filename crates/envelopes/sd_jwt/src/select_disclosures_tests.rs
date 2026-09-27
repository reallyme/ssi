// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::indexing_slicing)]

use serde_json::json;

use crate::{
    create_array_element_disclosure, create_object_property_disclosure, digest_disclosure,
    select_sd_jwt_disclosures, SdJwtClaimPathComponent, SdJwtEnvelopeError, SdJwtHashAlgorithm,
    SdJwtProcessingPolicy,
};

#[test]
fn selects_nested_disclosure_and_its_parent_but_not_sibling() {
    let street =
        create_object_property_disclosure("MDEyMzQ1Njc4OWFiY2RlZg", "street", json!("Via Roma"));
    assert!(street.is_ok());
    let sibling =
        create_object_property_disclosure("MDEyMzQ1Njc4OWFiY2RlZg", "family_name", json!("Rossi"));
    assert!(sibling.is_ok());
    if let (Ok(street), Ok(sibling)) = (street, sibling) {
        let street_digest = digest_disclosure(street.encoded(), SdJwtHashAlgorithm::Sha256);
        assert!(street_digest.is_ok());
        if let Ok(street_digest) = street_digest {
            let address = create_object_property_disclosure(
                "MDEyMzQ1Njc4OWFiY2RlZg",
                "address",
                json!({"_sd": [street_digest]}),
            );
            assert!(address.is_ok());
            if let Ok(address) = address {
                let address_digest =
                    digest_disclosure(address.encoded(), SdJwtHashAlgorithm::Sha256);
                let sibling_digest =
                    digest_disclosure(sibling.encoded(), SdJwtHashAlgorithm::Sha256);
                assert!(address_digest.is_ok());
                assert!(sibling_digest.is_ok());
                if let (Ok(address_digest), Ok(sibling_digest)) = (address_digest, sibling_digest) {
                    let disclosures = vec![
                        street.encoded().to_owned(),
                        sibling.encoded().to_owned(),
                        address.encoded().to_owned(),
                    ];
                    let selected = select_sd_jwt_disclosures(
                        &json!({"_sd": [address_digest, sibling_digest]}),
                        &disclosures,
                        &[vec![
                            SdJwtClaimPathComponent::Name("address".to_owned()),
                            SdJwtClaimPathComponent::Name("street".to_owned()),
                        ]],
                        SdJwtProcessingPolicy::default(),
                    );
                    assert!(selected.is_ok());
                    if let Ok(selected) = selected {
                        assert_eq!(
                            selected.as_slice(),
                            &[disclosures[0].clone(), disclosures[2].clone()]
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn wildcard_array_path_selects_each_disclosed_element() {
    let first = create_array_element_disclosure("MDEyMzQ1Njc4OWFiY2RlZg", json!("reader"));
    let second = create_array_element_disclosure("MDEyMzQ1Njc4OWFiY2RlZg", json!("writer"));
    assert!(first.is_ok());
    assert!(second.is_ok());
    if let (Ok(first), Ok(second)) = (first, second) {
        let first_digest = digest_disclosure(first.encoded(), SdJwtHashAlgorithm::Sha256);
        let second_digest = digest_disclosure(second.encoded(), SdJwtHashAlgorithm::Sha256);
        assert!(first_digest.is_ok());
        assert!(second_digest.is_ok());
        if let (Ok(first_digest), Ok(second_digest)) = (first_digest, second_digest) {
            let disclosures = vec![second.encoded().to_owned(), first.encoded().to_owned()];
            let selected = select_sd_jwt_disclosures(
                &json!({
                    "roles": [
                        {"...": first_digest},
                        {"...": second_digest}
                    ]
                }),
                &disclosures,
                &[vec![
                    SdJwtClaimPathComponent::Name("roles".to_owned()),
                    SdJwtClaimPathComponent::All,
                ]],
                SdJwtProcessingPolicy::default(),
            );
            assert!(selected.is_ok());
            if let Ok(selected) = selected {
                assert_eq!(selected.as_slice(), disclosures);
            }
        }
    }
}

#[test]
fn array_indices_ignore_decoy_placeholders() {
    let first = create_array_element_disclosure("MDEyMzQ1Njc4OWFiY2RlZg", json!("US"));
    let second = create_array_element_disclosure("MDEyMzQ1Njc4OWFiY2RlZg", json!("CA"));
    assert!(first.is_ok());
    assert!(second.is_ok());
    if let (Ok(first), Ok(second)) = (first, second) {
        let first_digest = digest_disclosure(first.encoded(), SdJwtHashAlgorithm::Sha256);
        let second_digest = digest_disclosure(second.encoded(), SdJwtHashAlgorithm::Sha256);
        assert!(first_digest.is_ok());
        assert!(second_digest.is_ok());
        if let (Ok(first_digest), Ok(second_digest)) = (first_digest, second_digest) {
            let disclosures = vec![first.encoded().to_owned(), second.encoded().to_owned()];
            let selected = select_sd_jwt_disclosures(
                &json!({
                    "nationalities": [
                        {"...": "decoy-digest"},
                        {"...": first_digest},
                        {"...": second_digest}
                    ]
                }),
                &disclosures,
                &[vec![
                    SdJwtClaimPathComponent::Name("nationalities".to_owned()),
                    SdJwtClaimPathComponent::Index(1),
                ]],
                SdJwtProcessingPolicy::default(),
            );
            assert!(selected.is_ok());
            if let Ok(selected) = selected {
                assert_eq!(selected.as_slice(), &[disclosures[1].clone()]);
            }
        }
    }
}

#[test]
fn array_indices_ignore_multiple_decoys_at_every_position() {
    let first = create_array_element_disclosure("MDEyMzQ1Njc4OWFiY2RlZg", json!("US"));
    let second = create_array_element_disclosure("MDEyMzQ1Njc4OWFiY2RlZg", json!("CA"));
    assert!(first.is_ok());
    assert!(second.is_ok());
    if let (Ok(first), Ok(second)) = (first, second) {
        let first_digest = digest_disclosure(first.encoded(), SdJwtHashAlgorithm::Sha256);
        let second_digest = digest_disclosure(second.encoded(), SdJwtHashAlgorithm::Sha256);
        assert!(first_digest.is_ok());
        assert!(second_digest.is_ok());
        if let (Ok(first_digest), Ok(second_digest)) = (first_digest, second_digest) {
            let disclosures = vec![first.encoded().to_owned(), second.encoded().to_owned()];
            for decoy_count in 1..=3 {
                for insertion_position in 0..=2 {
                    let mut placeholders = vec![
                        json!({"...": first_digest.clone()}),
                        json!({"...": second_digest.clone()}),
                    ];
                    for decoy_index in 0..decoy_count {
                        placeholders.insert(
                            insertion_position,
                            json!({"...": format!("decoy-{insertion_position}-{decoy_index}")}),
                        );
                    }
                    for resolved_index in 0..=1 {
                        let selected = select_sd_jwt_disclosures(
                            &json!({"nationalities": placeholders.clone()}),
                            &disclosures,
                            &[vec![
                                SdJwtClaimPathComponent::Name("nationalities".to_owned()),
                                SdJwtClaimPathComponent::Index(resolved_index),
                            ]],
                            SdJwtProcessingPolicy::default(),
                        );
                        assert!(selected.is_ok());
                        if let Ok(selected) = selected {
                            assert_eq!(selected.as_slice(), &[disclosures[resolved_index].clone()]);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn rejects_unmatched_disclosures_and_empty_paths() {
    let disclosure =
        create_object_property_disclosure("MDEyMzQ1Njc4OWFiY2RlZg", "given_name", json!("Ada"));
    assert!(disclosure.is_ok());
    if let Ok(disclosure) = disclosure {
        let disclosures = vec![disclosure.encoded().to_owned()];
        let unmatched = select_sd_jwt_disclosures(
            &json!({}),
            &disclosures,
            &[vec![SdJwtClaimPathComponent::Name("given_name".to_owned())]],
            SdJwtProcessingPolicy::default(),
        );
        assert!(unmatched.is_err());
        let empty_path =
            select_sd_jwt_disclosures(&json!({}), &[], &[vec![]], SdJwtProcessingPolicy::default());
        assert!(empty_path.is_err());
    }
}

#[test]
fn rejects_requested_path_absent_from_reconstructed_claims() {
    let result = select_sd_jwt_disclosures(
        &json!({"given_name": "Ada"}),
        &[],
        &[vec![SdJwtClaimPathComponent::Name(
            "family_name".to_owned(),
        )]],
        SdJwtProcessingPolicy::default(),
    );

    assert!(matches!(
        result,
        Err(SdJwtEnvelopeError::RequestedPathNotFound)
    ));
}

#[test]
fn cleartext_requested_path_remains_a_valid_empty_selection() {
    let result = select_sd_jwt_disclosures(
        &json!({"given_name": "Ada"}),
        &[],
        &[vec![SdJwtClaimPathComponent::Name("given_name".to_owned())]],
        SdJwtProcessingPolicy::default(),
    );

    assert!(result.is_ok());
    if let Ok(selected) = result {
        assert!(selected.is_empty());
    }
}
