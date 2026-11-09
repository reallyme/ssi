// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_etsi_eaa_conformance::{
    validate_issuer_information, IssuerInformationEntry, IssuerInformationErrorReason,
};
use serde_json::{json, Value};

fn registrar_dataset() -> Value {
    json!({
        "identifier": {
            "type": "http://data.europa.eu/eudi/id/LEI",
            "identifier": "registered-provider-identifier"
        },
        "srvDescription": [
            {"lang": "en", "content": "Qualified attestation issuance"},
            {"lang": "de", "content": "Ausstellung qualifizierter Nachweise"}
        ],
        "registryURI": "https://registrar.example/providers/registered-provider-identifier",
        "providesAttestations": [
            {"format": "dc+sd-jwt", "type": "urn:eu.europa.ec.eudi:pid:1"},
            {"format": "mso_mdoc", "type": "eu.europa.ec.eudi.pid.1"}
        ]
    })
}

#[test]
fn accepts_required_registrar_dataset_and_optional_registration_certificate() {
    let dataset = registrar_dataset();
    let certificate = json!("opaque-profile-defined-registration-certificate");
    let entries = [
        IssuerInformationEntry {
            format: "registrar_dataset",
            data: &dataset,
        },
        IssuerInformationEntry {
            format: "registration_cert",
            data: &certificate,
        },
    ];

    let summary = validate_issuer_information(&entries).expect("valid issuer information");

    assert_eq!(summary.registrar_dataset_count(), 1);
    assert_eq!(summary.registration_certificate_count(), 1);
    assert_eq!(summary.provided_attestation_count(), 2);
    assert!(summary.registration_certificate_present());
}

#[test]
fn accepts_empty_registered_attestation_collection_and_unknown_extension() {
    let mut dataset = registrar_dataset();
    dataset["providesAttestations"] = json!([]);
    let extension = json!({"profile": "future"});
    let entries = [
        IssuerInformationEntry {
            format: "future_profile_information",
            data: &extension,
        },
        IssuerInformationEntry {
            format: "registrar_dataset",
            data: &dataset,
        },
    ];

    let summary = validate_issuer_information(&entries).expect("extensible issuer information");

    assert_eq!(summary.provided_attestation_count(), 0);
    assert!(!summary.registration_certificate_present());
}

#[test]
fn rejects_missing_registrar_dataset_with_stable_reason() {
    let certificate = json!("opaque-profile-defined-registration-certificate");
    let entries = [IssuerInformationEntry {
        format: "registration_cert",
        data: &certificate,
    }];

    let error = validate_issuer_information(&entries).expect_err("dataset is mandatory");

    assert_eq!(
        error.reason(),
        IssuerInformationErrorReason::MissingRegistrarDataset
    );
}

#[test]
fn rejects_empty_or_incomplete_registrar_dataset() {
    let empty = json!({});
    let empty_error = validate_issuer_information(&[IssuerInformationEntry {
        format: "registrar_dataset",
        data: &empty,
    }])
    .expect_err("dataset must be non-empty");
    assert_eq!(
        empty_error.reason(),
        IssuerInformationErrorReason::InvalidRegistrarDataset
    );

    let mut incomplete = registrar_dataset();
    incomplete
        .as_object_mut()
        .expect("fixture object")
        .remove("registryURI");
    let missing_error = validate_issuer_information(&[IssuerInformationEntry {
        format: "registrar_dataset",
        data: &incomplete,
    }])
    .expect_err("all four members are mandatory");
    assert_eq!(
        missing_error.reason(),
        IssuerInformationErrorReason::InvalidRegistrarDataset
    );
}

#[test]
fn rejects_malformed_identifier_description_uri_and_attestation() {
    let cases = [
        (
            "identifier",
            json!({"type": "relative-identifier-type", "identifier": "provider"}),
            IssuerInformationErrorReason::InvalidIdentifier,
        ),
        (
            "srvDescription",
            json!([{"lang": "en-US", "content": "service"}]),
            IssuerInformationErrorReason::InvalidServiceDescription,
        ),
        (
            "registryURI",
            json!("/relative/registrar"),
            IssuerInformationErrorReason::InvalidRegistryUri,
        ),
        (
            "providesAttestations",
            json!([{"format": "dc+sd-jwt"}]),
            IssuerInformationErrorReason::InvalidProvidedAttestation,
        ),
    ];

    for (member, invalid_value, expected_reason) in cases {
        let mut dataset = registrar_dataset();
        dataset[member] = invalid_value;
        let error = validate_issuer_information(&[IssuerInformationEntry {
            format: "registrar_dataset",
            data: &dataset,
        }])
        .expect_err("malformed member must fail closed");
        assert_eq!(error.reason(), expected_reason);
    }
}

#[test]
fn accepts_multiple_registrar_datasets_without_inventing_uniqueness() {
    let first = registrar_dataset();
    let second = registrar_dataset();
    let entries = [
        IssuerInformationEntry {
            format: "registrar_dataset",
            data: &first,
        },
        IssuerInformationEntry {
            format: "registrar_dataset",
            data: &second,
        },
    ];

    let summary =
        validate_issuer_information(&entries).expect("Part 3 does not require uniqueness");

    assert_eq!(summary.registrar_dataset_count(), 2);
    assert_eq!(summary.provided_attestation_count(), 4);
}
