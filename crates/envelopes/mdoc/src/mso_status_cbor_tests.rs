// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::panic, clippy::unwrap_used)]
#![cfg(feature = "mdoc-crypto")]

use super::{mobile_security_object_from_cbor, Value};
use crate::{
    MdocEnvelopeError, MdocIdentifierList, MdocInvalidInputReason, MdocStatus, MdocStatusExtension,
    MdocStatusList, MAX_MDOC_STATUS_CERTIFICATE_BYTES, MAX_MDOC_STATUS_EXTENSION_VALUE_BYTES,
    MAX_MDOC_STATUS_IDENTIFIER_BYTES, MAX_MDOC_STATUS_URI_BYTES,
};

const STATUS_URI: &str = "https://issuer.example/status/1";
const STATUS_CERTIFICATE_DER: &[u8] =
    include_bytes!("../../../revocation/ocsp/openssl/tests/fixtures/leaf.der");

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn valid_mso(status: Value) -> Value {
    Value::Map(vec![
        (text("version"), text("1.0")),
        (text("digestAlgorithm"), text("SHA-256")),
        (text("docType"), text("org.iso.18013.5.1.mDL")),
        (text("valueDigests"), Value::Map(Vec::new())),
        (
            text("deviceKeyInfo"),
            Value::Map(vec![(text("deviceKey"), Value::Map(Vec::new()))]),
        ),
        (
            text("validityInfo"),
            Value::Map(vec![
                (
                    text("signed"),
                    Value::Tag(0, Box::new(text("2026-01-01T00:00:00Z"))),
                ),
                (
                    text("validFrom"),
                    Value::Tag(0, Box::new(text("2026-01-01T00:00:00Z"))),
                ),
                (
                    text("validUntil"),
                    Value::Tag(0, Box::new(text("2027-01-01T00:00:00Z"))),
                ),
            ]),
        ),
        (text("status"), status),
    ])
}

fn status_list(members: Vec<(Value, Value)>) -> Value {
    Value::Map(vec![(text("status_list"), Value::Map(members))])
}

fn identifier_list(members: Vec<(Value, Value)>) -> Value {
    Value::Map(vec![(text("identifier_list"), Value::Map(members))])
}

fn parse_error(status: Value) -> MdocEnvelopeError {
    mobile_security_object_from_cbor(&valid_mso(status))
        .err()
        .unwrap()
}

#[test]
fn parses_status_list_with_certificate() {
    let parsed = mobile_security_object_from_cbor(&valid_mso(status_list(vec![
        (text("idx"), Value::Integer(42_u64.into())),
        (text("uri"), text(STATUS_URI)),
        (
            text("certificate"),
            Value::Bytes(STATUS_CERTIFICATE_DER.to_vec()),
        ),
    ])))
    .unwrap();

    let status = parsed
        .status
        .as_ref()
        .and_then(MdocStatus::status_list_ref)
        .unwrap();
    assert_eq!(status.index(), 42);
    assert_eq!(status.uri(), STATUS_URI);
    assert_eq!(status.certificate_der(), Some(STATUS_CERTIFICATE_DER));
}

#[test]
fn parses_identifier_list_without_certificate() {
    let parsed = mobile_security_object_from_cbor(&valid_mso(identifier_list(vec![
        (text("id"), Value::Bytes(vec![1, 2, 3, 4])),
        (text("uri"), text(STATUS_URI)),
    ])))
    .unwrap();

    let status = parsed
        .status
        .as_ref()
        .and_then(MdocStatus::identifier_list_ref)
        .unwrap();
    assert_eq!(status.identifier(), &[1, 2, 3, 4]);
    assert_eq!(status.uri(), STATUS_URI);
    assert_eq!(status.certificate_der(), None);
}

#[test]
fn preserves_both_optional_mechanisms_and_forward_compatible_members() {
    let parsed = mobile_security_object_from_cbor(&valid_mso(Value::Map(vec![
        (
            text("status_list"),
            Value::Map(vec![
                (text("idx"), Value::Integer(42_u64.into())),
                (text("uri"), text(STATUS_URI)),
                (text("future_status_list_member"), Value::Null),
            ]),
        ),
        (
            text("identifier_list"),
            Value::Map(vec![
                (text("id"), Value::Bytes(vec![1, 2, 3, 4])),
                (text("uri"), text(STATUS_URI)),
                (text("future_identifier_member"), Value::Bool(true)),
            ]),
        ),
        (
            text("future_status_member"),
            Value::Array(vec![Value::Integer(7_u64.into())]),
        ),
    ])))
    .unwrap();
    let status = parsed.status.as_ref().unwrap();
    assert!(status.status_list_ref().is_some());
    assert_eq!(
        status.status_list_ref().unwrap().extensions()[0].name(),
        "future_status_list_member"
    );
    let identifier = status.identifier_list_ref().unwrap();
    assert_eq!(identifier.extensions().len(), 1);
    assert_eq!(
        identifier.extensions()[0].name(),
        "future_identifier_member"
    );
    assert_eq!(status.extensions().len(), 1);
    assert_eq!(status.extensions()[0].name(), "future_status_member");
}

#[test]
fn rejects_duplicate_mechanisms() {
    let duplicate = Value::Map(vec![
        (text("status_list"), Value::Map(Vec::new())),
        (text("status_list"), Value::Map(Vec::new())),
    ]);
    assert_eq!(
        parse_error(duplicate),
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::DuplicateMsoStatusMember)
    );
}

#[test]
fn rejects_invalid_status_list_members() {
    let invalid_cases = [
        (
            status_list(vec![
                (text("idx"), text("42")),
                (text("uri"), text(STATUS_URI)),
            ]),
            MdocInvalidInputReason::InvalidMsoStatusListIndex,
        ),
        (
            status_list(vec![
                (text("idx"), Value::Integer(u64::MAX.into())),
                (text("uri"), text(STATUS_URI)),
            ]),
            MdocInvalidInputReason::InvalidMsoStatusListIndex,
        ),
        (
            status_list(vec![
                (text("idx"), Value::Integer(0_u64.into())),
                (text("uri"), text("")),
            ]),
            MdocInvalidInputReason::EmptyMsoStatusUri,
        ),
        (
            status_list(vec![
                (text("idx"), Value::Integer(0_u64.into())),
                (text("uri"), text("not a uri")),
            ]),
            MdocInvalidInputReason::InvalidMsoStatusUri,
        ),
        (
            status_list(vec![
                (text("idx"), Value::Integer(0_u64.into())),
                (text("uri"), text(STATUS_URI)),
                (text("certificate"), text("not bytes")),
            ]),
            MdocInvalidInputReason::InvalidMsoStatusCertificate,
        ),
    ];

    for (status, reason) in invalid_cases {
        assert_eq!(parse_error(status), MdocEnvelopeError::InvalidInput(reason));
    }
}

#[test]
fn rejects_invalid_identifier_list_members() {
    let invalid_cases = [
        (
            identifier_list(vec![
                (text("id"), text("not bytes")),
                (text("uri"), text(STATUS_URI)),
            ]),
            MdocInvalidInputReason::InvalidMsoStatusIdentifier,
        ),
        (
            identifier_list(vec![
                (text("id"), Value::Bytes(Vec::new())),
                (text("uri"), text(STATUS_URI)),
            ]),
            MdocInvalidInputReason::EmptyMsoStatusIdentifier,
        ),
        (
            identifier_list(vec![
                (text("id"), Value::Bytes(vec![1])),
                (text("id"), Value::Bytes(vec![2])),
                (text("uri"), text(STATUS_URI)),
            ]),
            MdocInvalidInputReason::DuplicateMsoStatusMember,
        ),
    ];

    for (status, reason) in invalid_cases {
        assert_eq!(parse_error(status), MdocEnvelopeError::InvalidInput(reason));
    }
}

#[test]
fn rejects_oversized_status_values() {
    assert_eq!(
        parse_error(status_list(vec![
            (text("idx"), Value::Integer(0_u64.into())),
            (
                text("uri"),
                text(&format!(
                    "https://example.com/{}",
                    "a".repeat(MAX_MDOC_STATUS_URI_BYTES)
                ))
            ),
        ])),
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MsoStatusUriTooLong)
    );
    assert_eq!(
        parse_error(identifier_list(vec![
            (
                text("id"),
                Value::Bytes(vec![0; MAX_MDOC_STATUS_IDENTIFIER_BYTES + 1])
            ),
            (text("uri"), text(STATUS_URI)),
        ])),
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MsoStatusIdentifierTooLong)
    );
    assert_eq!(
        parse_error(status_list(vec![
            (text("idx"), Value::Integer(0_u64.into())),
            (text("uri"), text(STATUS_URI)),
            (
                text("certificate"),
                Value::Bytes(vec![0; MAX_MDOC_STATUS_CERTIFICATE_BYTES + 1]),
            ),
        ])),
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MsoStatusCertificateTooLong)
    );
    assert_eq!(
        parse_error(status_list(vec![
            (text("idx"), Value::Integer(0_u64.into())),
            (text("uri"), text(STATUS_URI)),
            (
                text("future"),
                Value::Bytes(vec![0; crate::MAX_MDOC_CBOR_INPUT_BYTES]),
            ),
        ])),
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MsoStatusExtensionTooLong)
    );
}

#[test]
fn extension_type_rejects_malicious_direct_deserialization() {
    let empty_name = serde_json::json!({"name": "", "value_cbor": [246]});
    let malformed_value = serde_json::json!({"name": "future", "value_cbor": [255]});
    let oversized_value = serde_json::json!({
        "name": "future",
        "value_cbor": vec![0_u8; MAX_MDOC_STATUS_EXTENSION_VALUE_BYTES + 1]
    });
    assert!(serde_json::from_value::<MdocStatusExtension>(empty_name).is_err());
    assert!(serde_json::from_value::<MdocStatusExtension>(malformed_value).is_err());
    assert!(serde_json::from_value::<MdocStatusExtension>(oversized_value).is_err());
}

#[test]
fn typed_status_maps_reject_extensions_that_collide_with_known_members() {
    let extension = |name: &str| serde_json::json!({"name": name, "value_cbor": [246]});
    let top_level = serde_json::json!({
        "extensions": [extension("status_list")]
    });
    let status_list = serde_json::json!({
        "idx": 0,
        "uri": STATUS_URI,
        "certificate": null,
        "extensions": [extension("idx")]
    });
    let identifier_list = serde_json::json!({
        "id": [1],
        "uri": STATUS_URI,
        "certificate": null,
        "extensions": [extension("certificate")]
    });
    assert!(serde_json::from_value::<MdocStatus>(top_level).is_err());
    assert!(serde_json::from_value::<MdocStatusList>(status_list).is_err());
    assert!(serde_json::from_value::<MdocIdentifierList>(identifier_list).is_err());
}
