// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn iso23220_relationship_accepts_clause_cddl_shape() {
    let encoded = ciborium_bytes(&CiboriumValue::Array(vec![CiboriumValue::Map(vec![
        (
            CiboriumValue::Text("family_name".to_owned()),
            CiboriumValue::Text("Example".to_owned()),
        ),
        (
            CiboriumValue::Text("birth_date".to_owned()),
            CiboriumValue::Map(vec![(
                CiboriumValue::Text("birth_date".to_owned()),
                CiboriumValue::Text("2000-01-01".to_owned()),
            )]),
        ),
    ])]));

    let value = parse_iso23220_relationship_value(&encoded).unwrap();
    assert_eq!(value.relationship_count(), 1);
    let element = iso23220_relationship_element(
        Iso23220RelationshipKind::LegalRepresentative,
        value,
        vec![7_u8; 16],
    )
    .unwrap();

    assert_eq!(element.namespace, ISO_23220_NAMESPACE);
    assert_eq!(element.element_identifier, "legal_representative");
    assert_eq!(element.element_value_cbor, encoded);
}

#[test]
fn iso23220_relationship_accepts_empty_personal_data_map() {
    let encoded = ciborium_bytes(&CiboriumValue::Array(vec![CiboriumValue::Map(vec![])]));

    let value = parse_iso23220_relationship_value(&encoded).unwrap();

    assert_eq!(value.relationship_count(), 1);
    assert_eq!(value.as_cbor(), encoded);
}

#[test]
fn iso23220_relationship_rejects_table_text_array_shape() {
    let encoded = ciborium_bytes(&CiboriumValue::Array(vec![CiboriumValue::Text(
        "family_name".to_owned(),
    )]));

    let error = match parse_iso23220_relationship_value(&encoded) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(error) => error,
    };

    assert_eq!(
        error,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::MalformedIso23220Relationship)
    );
}

#[test]
fn iso23220_relationship_rejects_duplicate_personal_data_identifier() {
    let encoded = ciborium_bytes(&CiboriumValue::Array(vec![CiboriumValue::Map(vec![
        (
            CiboriumValue::Text("family_name".to_owned()),
            CiboriumValue::Text("First".to_owned()),
        ),
        (
            CiboriumValue::Text("family_name".to_owned()),
            CiboriumValue::Text("Second".to_owned()),
        ),
    ])]));

    let error = match parse_iso23220_relationship_value(&encoded) {
        Ok(_) => MdocEnvelopeError::UnsupportedOperation,
        Err(error) => error,
    };

    assert_eq!(
        error,
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::DuplicateCborMapKey)
    );
}
