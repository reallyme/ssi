// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn validate_not_before(
    nbf: Option<u64>,
    now_unix: u64,
    clock_skew_seconds: u64,
) -> Result<(), SdJwtVpError> {
    let Some(nbf_unix) = nbf else {
        return Ok(());
    };
    if nbf_unix == 0 {
        return Err(SdJwtVpError::Crypto);
    }
    let not_before_ceiling = skew_ceiling(now_unix, clock_skew_seconds)?;
    if not_before_ceiling < nbf_unix {
        return Err(SdJwtVpError::Crypto);
    }
    Ok(())
}

fn validate_issued_at(
    iat: Option<u64>,
    now_unix: u64,
    max_future_iat_skew_seconds: u64,
) -> Result<(), SdJwtVpError> {
    let Some(iat_unix) = iat else {
        return Ok(());
    };
    if iat_unix == 0 {
        return Err(SdJwtVpError::Crypto);
    }
    let issued_at_ceiling = skew_ceiling(now_unix, max_future_iat_skew_seconds)?;
    if iat_unix > issued_at_ceiling {
        return Err(SdJwtVpError::Crypto);
    }
    Ok(())
}

fn skew_floor(now_unix: u64, skew_seconds: u64) -> Result<u64, SdJwtVpError> {
    if now_unix < skew_seconds {
        return Ok(0);
    }
    now_unix
        .checked_sub(skew_seconds)
        .ok_or(SdJwtVpError::Crypto)
}

fn skew_ceiling(now_unix: u64, skew_seconds: u64) -> Result<u64, SdJwtVpError> {
    now_unix
        .checked_add(skew_seconds)
        .ok_or(SdJwtVpError::Crypto)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    sha2_256_digest(data).into_bytes()
}

fn u64be(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

fn claim_inner_digest(clm_tag: &[u8], value: &[u8], salt: &[u8]) -> Result<[u8; 32], SdJwtVpError> {
    // The credential commitment format encodes value lengths as unsigned
    // 64-bit integers. Presentation verification must reproduce that exact
    // transcript or a valid issuer commitment would be rejected.
    let value_len = u64::try_from(value.len()).map_err(|_| SdJwtVpError::InvalidDisclosure)?;
    let encoded_len = u64be(value_len);
    sha256_parts(&[clm_tag, encoded_len.as_slice(), value, salt])
}

fn leaf_digest(
    leaf_tag: &[u8],
    claim_path: &str,
    inner: &[u8; 32],
) -> Result<[u8; 32], SdJwtVpError> {
    let name_hash = sha256(claim_path.as_bytes());
    sha256_parts(&[leaf_tag, name_hash.as_slice(), inner])
}

fn node_digest(
    node_tag: &[u8],
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<[u8; 32], SdJwtVpError> {
    sha256_parts(&[node_tag, left, right])
}

fn sha256_parts(parts: &[&[u8]]) -> Result<[u8; 32], SdJwtVpError> {
    let capacity = parts.iter().try_fold(0_usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or(SdJwtVpError::InvalidDisclosure)
    })?;
    let mut input = Vec::with_capacity(capacity);
    for part in parts {
        input.extend_from_slice(part);
    }
    Ok(sha2_256_digest(&input).into_bytes())
}
