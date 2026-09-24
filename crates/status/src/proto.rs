// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Package-owned mappings between generated status protobufs and the native model.

use buffa::{EnumValue, Enumeration, MessageField};
use buffa_types::google::protobuf::Timestamp;
use reallyme_ssi_proto::generated::proto::identity::credential::v1 as credential_pb;
use reallyme_ssi_proto::generated::proto::identity::status::v1 as status_pb;

use crate::{
    CredentialStatusError, CredentialStatusInvalidReason, StatusList, StatusListAlgorithm,
    StatusListSignature, StatusPurpose,
};

const STATUS_LIST_ID_BYTES: usize = 32;

/// Convert a native status list into its canonical generated protobuf message.
pub fn status_list_to_proto(
    list: &StatusList,
) -> Result<status_pb::StatusList, CredentialStatusError> {
    Ok(status_pb::StatusList {
        issuer_did: list.issuer.clone(),
        purpose: EnumValue::from(status_purpose_to_proto(list.purpose)),
        issued_at: MessageField::some(timestamp_to_proto(list.issued_at)?),
        next_update: MessageField::some(timestamp_to_proto(list.next_update)?),
        encoded_list: list.encoded_list.clone(),
        length: list.length,
        list_id: list.list_id.map_or_else(Vec::new, |value| value.to_vec()),
        signature: MessageField::some(status_signature_to_proto(&list.signature)),
        ..status_pb::StatusList::default()
    })
}

/// Convert a canonical generated status-list message into the native model.
pub fn status_list_from_proto(
    list: &status_pb::StatusList,
) -> Result<StatusList, CredentialStatusError> {
    let issued_at = list.issued_at.as_option().ok_or_else(invalid_time_window)?;
    let next_update = list
        .next_update
        .as_option()
        .ok_or_else(invalid_time_window)?;
    let signature = list
        .signature
        .as_option()
        .ok_or_else(invalid_signature_metadata)?;

    Ok(StatusList {
        issuer: list.issuer_did.clone(),
        purpose: status_purpose_from_proto(list.purpose.to_i32())?,
        issued_at: timestamp_from_proto(issued_at)?,
        next_update: timestamp_from_proto(next_update)?,
        encoded_list: list.encoded_list.clone(),
        length: list.length,
        list_id: optional_list_id_from_proto(list.list_id.as_slice())?,
        signature: status_signature_from_proto(signature)?,
    })
}

fn timestamp_to_proto(seconds: u64) -> Result<Timestamp, CredentialStatusError> {
    let seconds = i64::try_from(seconds).map_err(|_| invalid_time_window())?;
    Ok(Timestamp {
        seconds,
        nanos: 0,
        ..Timestamp::default()
    })
}

fn timestamp_from_proto(timestamp: &Timestamp) -> Result<u64, CredentialStatusError> {
    if timestamp.nanos != 0 {
        return Err(invalid_time_window());
    }
    u64::try_from(timestamp.seconds).map_err(|_| invalid_time_window())
}

fn optional_list_id_from_proto(
    bytes: &[u8],
) -> Result<Option<[u8; STATUS_LIST_ID_BYTES]>, CredentialStatusError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    <[u8; STATUS_LIST_ID_BYTES]>::try_from(bytes)
        .map(Some)
        .map_err(|_| invalid_length())
}

fn status_signature_to_proto(signature: &StatusListSignature) -> status_pb::StatusListSignature {
    status_pb::StatusListSignature {
        alg: EnumValue::from(status_algorithm_to_proto(signature.alg)),
        sig_bytes: signature.sig_bytes.clone(),
        ..status_pb::StatusListSignature::default()
    }
}

fn status_signature_from_proto(
    signature: &status_pb::StatusListSignature,
) -> Result<StatusListSignature, CredentialStatusError> {
    Ok(StatusListSignature {
        alg: status_algorithm_from_proto(signature.alg.to_i32())?,
        sig_bytes: signature.sig_bytes.clone(),
    })
}

const fn status_purpose_to_proto(purpose: StatusPurpose) -> credential_pb::StatusPurpose {
    match purpose {
        StatusPurpose::Revocation => credential_pb::StatusPurpose::Revocation,
        StatusPurpose::Suspension => credential_pb::StatusPurpose::Suspension,
    }
}

fn status_purpose_from_proto(value: i32) -> Result<StatusPurpose, CredentialStatusError> {
    match credential_pb::StatusPurpose::from_i32(value) {
        Some(credential_pb::StatusPurpose::Revocation) => Ok(StatusPurpose::Revocation),
        Some(credential_pb::StatusPurpose::Suspension) => Ok(StatusPurpose::Suspension),
        Some(credential_pb::StatusPurpose::Unspecified) | None => Err(
            CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::UnsupportedPurpose),
        ),
    }
}

const fn status_algorithm_to_proto(algorithm: StatusListAlgorithm) -> credential_pb::Algorithm {
    match algorithm {
        StatusListAlgorithm::Ed25519 => credential_pb::Algorithm::Ed25519,
        StatusListAlgorithm::P256 => credential_pb::Algorithm::P256,
        StatusListAlgorithm::Secp256k1 => credential_pb::Algorithm::Secp256k1,
    }
}

fn status_algorithm_from_proto(value: i32) -> Result<StatusListAlgorithm, CredentialStatusError> {
    match credential_pb::Algorithm::from_i32(value) {
        Some(credential_pb::Algorithm::Ed25519) => Ok(StatusListAlgorithm::Ed25519),
        Some(credential_pb::Algorithm::P256) => Ok(StatusListAlgorithm::P256),
        Some(credential_pb::Algorithm::Secp256k1) => Ok(StatusListAlgorithm::Secp256k1),
        _ => Err(invalid_signature_metadata()),
    }
}

const fn invalid_time_window() -> CredentialStatusError {
    CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::InvalidTimeWindow)
}

const fn invalid_signature_metadata() -> CredentialStatusError {
    CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::InvalidSignatureMetadata)
}

const fn invalid_length() -> CredentialStatusError {
    CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::InvalidLength)
}

#[cfg(test)]
#[path = "proto_tests.rs"]
mod tests;
