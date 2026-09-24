// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::cbor::{encode_dag_cbor, CborValue};

use crate::{CredentialStatusError, CredentialStatusInvalidReason, StatusList, StatusPurpose};

/// Deterministically encode the status-list fields covered by issuer signature.
pub fn status_list_signing_payload(list: &StatusList) -> Result<Vec<u8>, CredentialStatusError> {
    let issued_at = i64::try_from(list.issued_at).map_err(|_| {
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::PayloadEncoding)
    })?;
    let next_update = i64::try_from(list.next_update).map_err(|_| {
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::PayloadEncoding)
    })?;
    let length = i64::try_from(list.length).map_err(|_| {
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::PayloadEncoding)
    })?;
    let list_id = match list.list_id {
        Some(value) => CborValue::Bytes(value.to_vec()),
        None => CborValue::Null,
    };

    encode_dag_cbor(&CborValue::Map(vec![
        ("issuer".to_owned(), CborValue::String(list.issuer.clone())),
        (
            "purpose".to_owned(),
            CborValue::String(purpose_label(list.purpose).to_owned()),
        ),
        ("issuedAt".to_owned(), CborValue::Int(issued_at)),
        ("nextUpdate".to_owned(), CborValue::Int(next_update)),
        (
            "encodedList".to_owned(),
            CborValue::Bytes(list.encoded_list.clone()),
        ),
        ("length".to_owned(), CborValue::Int(length)),
        ("listId".to_owned(), list_id),
    ]))
    .map_err(|_| {
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::PayloadEncoding)
    })
}

fn purpose_label(purpose: StatusPurpose) -> &'static str {
    match purpose {
        StatusPurpose::Revocation => "revocation",
        StatusPurpose::Suspension => "suspension",
    }
}
