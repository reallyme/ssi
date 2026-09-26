// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(any(feature = "native", feature = "wasm"))]
use std::io::Read;
use std::io::Write;

#[cfg(any(feature = "native", feature = "wasm"))]
use flate2::read::ZlibDecoder;
use flate2::{write::ZlibEncoder, Compression};
use reallyme_codec::base64url::bytes_to_base64url;

use super::model::{
    TokenStatusBits, TokenStatusListError, TokenStatusListInvalidReason, TokenStatusListPayload,
    VerifiedTokenStatusList, MAX_COMPRESSED_STATUS_BYTES, MAX_TOKEN_STATUS_ENTRIES,
};

/// Pack status values least-significant-bit first within each byte.
pub fn pack_token_status_values(
    values: &[u8],
    bits: TokenStatusBits,
) -> Result<Vec<u8>, TokenStatusListError> {
    if values.is_empty() || values.len() > MAX_TOKEN_STATUS_ENTRIES {
        return Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidLength,
        ));
    }
    if values.iter().any(|value| *value > bits.maximum_value()) {
        return Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::StatusValueOutOfRange,
        ));
    }
    let width = usize::from(bits.width());
    let total_bits = values
        .len()
        .checked_mul(width)
        .ok_or(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidLength,
        ))?;
    let byte_len = total_bits
        .checked_add(7)
        .ok_or(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidLength,
        ))?
        / 8;
    let mut packed = vec![0_u8; byte_len];
    for (index, value) in values.iter().copied().enumerate() {
        let bit_offset = index
            .checked_mul(width)
            .ok_or(TokenStatusListError::InvalidInput(
                TokenStatusListInvalidReason::InvalidLength,
            ))?;
        let byte_index = bit_offset / 8;
        let shift = u32::try_from(bit_offset % 8).map_err(|_| {
            TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidLength)
        })?;
        packed[byte_index] |= value << shift;
    }
    Ok(packed)
}

/// Read one packed status value using draft-defined least-significant-bit order.
///
/// `bits` is supplied by the caller. For an authenticated list, prefer
/// [`VerifiedTokenStatusList::status`], which reads the width from the signed
/// `status_list.bits` claim.
pub fn token_status_value(
    packed: &[u8],
    bits: TokenStatusBits,
    index: usize,
) -> Result<u8, TokenStatusListError> {
    let width = usize::from(bits.width());
    let bit_offset = index
        .checked_mul(width)
        .ok_or(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidIndex,
        ))?;
    let byte_index = bit_offset / 8;
    let byte = packed
        .get(byte_index)
        .copied()
        .ok_or(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidIndex,
        ))?;
    let shift = u32::try_from(bit_offset % 8).map_err(|_| {
        TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidIndex)
    })?;
    Ok((byte >> shift) & bits.maximum_value())
}

impl VerifiedTokenStatusList {
    /// Read the status value at `index` using the bit width from the
    /// authenticated `status_list.bits` claim.
    pub fn status(&self, index: usize) -> Result<u8, TokenStatusListError> {
        let bits = TokenStatusBits::from_width(self.claims.status_list.bits).ok_or(
            TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidBits),
        )?;
        token_status_value(&self.packed_statuses, bits, index)
    }
}

/// Pack and compress status values into the draft-21 JSON claim shape.
pub fn build_token_status_list_payload(
    values: &[u8],
    bits: TokenStatusBits,
    aggregation_uri: Option<String>,
) -> Result<TokenStatusListPayload, TokenStatusListError> {
    let packed = pack_token_status_values(values, bits)?;
    let compressed = compress_status_bytes(&packed)?;
    Ok(TokenStatusListPayload {
        bits: bits.width(),
        lst: bytes_to_base64url(&compressed),
        aggregation_uri,
    })
}

pub(crate) fn compress_status_bytes(bytes: &[u8]) -> Result<Vec<u8>, TokenStatusListError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(bytes)
        .map_err(|_| TokenStatusListError::Encoding)?;
    let compressed = encoder
        .finish()
        .map_err(|_| TokenStatusListError::Encoding)?;
    if compressed.len() > MAX_COMPRESSED_STATUS_BYTES {
        return Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidCompressedList,
        ));
    }
    Ok(compressed)
}

#[cfg(any(feature = "native", feature = "wasm"))]
pub(crate) fn decompress_status_bytes(
    compressed: &[u8],
    bits: u8,
) -> Result<Vec<u8>, TokenStatusListError> {
    if compressed.is_empty() || compressed.len() > MAX_COMPRESSED_STATUS_BYTES {
        return Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidCompressedList,
        ));
    }
    let decoder = ZlibDecoder::new(compressed);
    let mut output = Vec::new();
    let width = match bits {
        1 | 2 | 4 | 8 => usize::from(bits),
        _ => {
            return Err(TokenStatusListError::InvalidInput(
                TokenStatusListInvalidReason::InvalidBits,
            ));
        }
    };
    let maximum_output = MAX_TOKEN_STATUS_ENTRIES
        .checked_mul(width)
        .and_then(|total_bits| total_bits.checked_add(7))
        .map(|rounded_bits| rounded_bits / 8)
        .ok_or(TokenStatusListError::Encoding)?;
    let read_limit = u64::try_from(maximum_output)
        .map_err(|_| TokenStatusListError::Encoding)?
        .checked_add(1)
        .ok_or(TokenStatusListError::Encoding)?;
    decoder
        .take(read_limit)
        .read_to_end(&mut output)
        .map_err(|_| {
            TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidCompressedList)
        })?;
    if output.is_empty() || output.len() > maximum_output {
        return Err(TokenStatusListError::InvalidInput(
            TokenStatusListInvalidReason::InvalidCompressedList,
        ));
    }
    Ok(output)
}
