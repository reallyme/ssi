// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    status_list_signing_payload, CredentialStatusError, CredentialStatusInvalidReason, StatusList,
    StatusListAlgorithm, StatusPurpose,
};

/// Maximum number of credential entries accepted in one status list.
pub const MAX_STATUS_LIST_ENTRIES: u64 = 1_000_000;

/// Trait for verifying issuer signatures over status-list payloads.
pub trait StatusListVerifier {
    /// Verify an issuer signature over the deterministic status-list payload.
    fn verify_status_list(
        &self,
        issuer: &str,
        alg: StatusListAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialStatusError>;
}

/// Validate status-list structure without performing signature verification.
pub fn validate_status_list(list: &StatusList) -> Result<(), CredentialStatusError> {
    if list.issuer.trim().is_empty() {
        return Err(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::EmptyIssuer,
        ));
    }
    if list.length == 0 {
        return Err(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidLength,
        ));
    }
    if list.length > MAX_STATUS_LIST_ENTRIES {
        return Err(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::TooLarge,
        ));
    }
    if list.issued_at == 0 || list.next_update == 0 || list.issued_at >= list.next_update {
        return Err(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidTimeWindow,
        ));
    }
    if !matches!(
        list.purpose,
        StatusPurpose::Revocation | StatusPurpose::Suspension
    ) {
        return Err(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::UnsupportedPurpose,
        ));
    }
    let required_bytes = required_status_bytes(list.length)?;
    if list.encoded_list.len() != required_bytes {
        return Err(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidEncodedList,
        ));
    }
    if list.signature.sig_bytes.is_empty() {
        return Err(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidSignatureMetadata,
        ));
    }
    if !matches!(
        list.signature.alg,
        StatusListAlgorithm::Ed25519 | StatusListAlgorithm::P256 | StatusListAlgorithm::Secp256k1
    ) {
        return Err(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidSignatureMetadata,
        ));
    }

    Ok(())
}

/// Verify one credential's status against a signed status list.
pub fn verify_status(
    list: &StatusList,
    index: u64,
    now_unix: u64,
    verifier: &dyn StatusListVerifier,
) -> Result<(), CredentialStatusError> {
    validate_status_list(list)?;
    if now_unix < list.issued_at {
        return Err(CredentialStatusError::NotYetValid);
    }
    if now_unix > list.next_update {
        return Err(CredentialStatusError::Expired);
    }
    if index >= list.length {
        return Err(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidIndex,
        ));
    }

    let payload = status_list_signing_payload(list)?;
    verifier.verify_status_list(
        list.issuer.as_str(),
        list.signature.alg,
        payload.as_slice(),
        list.signature.sig_bytes.as_slice(),
    )?;

    let bit_set = status_bit(list, index)?;
    match list.purpose {
        StatusPurpose::Revocation if bit_set => Err(CredentialStatusError::Revoked),
        StatusPurpose::Suspension if bit_set => Err(CredentialStatusError::Suspended),
        _ => Ok(()),
    }
}

/// Return whether a status bit is set after bounds validation.
pub fn status_bit(list: &StatusList, index: u64) -> Result<bool, CredentialStatusError> {
    if index >= list.length {
        return Err(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidIndex,
        ));
    }
    let byte_index_u64 = index
        .checked_div(8)
        .ok_or(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidIndex,
        ))?;
    let byte_index = usize::try_from(byte_index_u64).map_err(|_| {
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::InvalidIndex)
    })?;
    let bit_index = u8::try_from(index % 8).map_err(|_| {
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::InvalidIndex)
    })?;
    let byte = list.encoded_list.get(byte_index).ok_or({
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::InvalidEncodedList)
    })?;

    Ok((byte >> bit_index) & 1_u8 == 1_u8)
}

fn required_status_bytes(length: u64) -> Result<usize, CredentialStatusError> {
    let adjusted = length
        .checked_add(7)
        .ok_or(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidLength,
        ))?;
    let bytes = adjusted
        .checked_div(8)
        .ok_or(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidLength,
        ))?;
    usize::try_from(bytes).map_err(|_| {
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::InvalidLength)
    })
}
