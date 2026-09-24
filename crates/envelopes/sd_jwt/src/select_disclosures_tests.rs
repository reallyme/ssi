// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::json;

use crate::{
    create_array_element_disclosure, create_object_property_disclosure, digest_disclosure,
    select_sd_jwt_disclosures, SdJwtClaimPathComponent, SdJwtHashAlgorithm, SdJwtProcessingPolicy,
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
