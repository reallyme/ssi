// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::{
    base64url::bytes_to_base64url,
    cbor::{
        decode_deterministic_cbor, encode_deterministic_cbor, DeterministicCborInteger,
        DeterministicCborMapEntry, DeterministicCborMapKey, DeterministicCborValue,
    },
};
use reallyme_cose::{
    cose_sign1_with_signature_algorithm_and_external_aad, cose_sign1_with_signer,
    cose_verify1_with_policy, Algorithm, CosePolicy, CoseSign1EncodeOptions,
    CoseSignatureAlgorithm, CoseSigner, CoseType,
};
use zeroize::Zeroizing;

use super::{
    check_freshness::check_freshness,
    issue_jwt::{validate_claims, validate_claims_with_compressed},
    model::{
        TokenStatusListClaims, TokenStatusListError, TokenStatusListFreshnessPolicy,
        TokenStatusListInvalidReason, TokenStatusListPayload, TokenStatusListProfile,
        VerifiedTokenStatusList, MAX_TOKEN_STATUS_CWT_BYTES, STATUS_LIST_CWT_CONTENT_FORMAT,
        STATUS_LIST_CWT_MEDIA_TYPE,
    },
};

const CWT_SUBJECT_CLAIM: u64 = 2;
const CWT_EXPIRATION_CLAIM: u64 = 4;
const CWT_ISSUED_AT_CLAIM: u64 = 6;
const CWT_STATUS_LIST_CLAIM: u64 = 65_533;
const CWT_TTL_CLAIM: u64 = 65_534;

fn integer_key(label: u64) -> DeterministicCborMapKey {
    DeterministicCborMapKey::Integer(DeterministicCborInteger::unsigned(label))
}

fn integer_value(value: u64) -> DeterministicCborValue {
    DeterministicCborValue::Integer(DeterministicCborInteger::unsigned(value))
}

fn entry(label: u64, value: DeterministicCborValue) -> DeterministicCborMapEntry {
    DeterministicCborMapEntry::new(integer_key(label), value)
}

fn text_entry(key: &str, value: DeterministicCborValue) -> DeterministicCborMapEntry {
    DeterministicCborMapEntry::new(DeterministicCborMapKey::text(key.to_owned()), value)
}

fn encode_claims(
    claims: &TokenStatusListClaims,
) -> Result<Zeroizing<Vec<u8>>, TokenStatusListError> {
    let compressed = validate_claims(claims)?.compressed;
    let mut status_entries = vec![
        text_entry("bits", integer_value(u64::from(claims.status_list.bits))),
        text_entry("lst", DeterministicCborValue::Bytes(compressed)),
    ];
    if let Some(uri) = claims.status_list.aggregation_uri.as_ref() {
        status_entries.push(text_entry(
            "aggregation_uri",
            DeterministicCborValue::Text(uri.clone()),
        ));
    }

    let mut claim_entries = vec![
        entry(
            CWT_SUBJECT_CLAIM,
            DeterministicCborValue::Text(claims.sub.clone()),
        ),
        entry(CWT_ISSUED_AT_CLAIM, integer_value(claims.iat)),
        entry(
            CWT_STATUS_LIST_CLAIM,
            DeterministicCborValue::Map(status_entries),
        ),
    ];
    if let Some(expiration) = claims.exp {
        claim_entries.push(entry(CWT_EXPIRATION_CLAIM, integer_value(expiration)));
    }
    if let Some(ttl) = claims.ttl {
        claim_entries.push(entry(CWT_TTL_CLAIM, integer_value(ttl)));
    }

    encode_deterministic_cbor(&DeterministicCborValue::Map(claim_entries))
        .map_err(|_| TokenStatusListError::Encoding)
}

fn cwt_options() -> CoseSign1EncodeOptions {
    CoseSign1EncodeOptions::tagged()
        .with_protected_type(CoseType::Text(STATUS_LIST_CWT_MEDIA_TYPE.to_owned()))
        .with_max_cose_sign1_bytes(MAX_TOKEN_STATUS_CWT_BYTES)
}

/// Issue a tagged COSE_Sign1 Token Status List CWT using local key bytes.
pub fn issue_token_status_list_cwt(
    claims: &TokenStatusListClaims,
    algorithm: CoseSignatureAlgorithm,
    issuer_private_key: &[u8],
    kid: Option<&[u8]>,
) -> Result<Vec<u8>, TokenStatusListError> {
    let payload = encode_claims(claims)?;
    cose_sign1_with_signature_algorithm_and_external_aad(
        algorithm,
        &payload,
        issuer_private_key,
        kid,
        &[],
        cwt_options(),
    )
    .map(|encoded| encoded.to_vec())
    .map_err(|_| TokenStatusListError::Authentication)
}

/// Issue a tagged COSE_Sign1 Token Status List CWT with a provider-owned key.
pub fn issue_token_status_list_cwt_with_signer(
    claims: &TokenStatusListClaims,
    signer: &dyn CoseSigner,
    kid: Option<&[u8]>,
) -> Result<Vec<u8>, TokenStatusListError> {
    let payload = encode_claims(claims)?;
    cose_sign1_with_signer(signer, &payload, kid, &[], cwt_options())
        .map(|encoded| encoded.to_vec())
        .map_err(|_| TokenStatusListError::Authentication)
}

/// Authenticate and validate a tagged COSE_Sign1 Token Status List CWT.
///
/// `freshness` bounds how long after `iat` the list is accepted, honoring a
/// shorter `ttl` claim; see [`TokenStatusListFreshnessPolicy`].
pub fn verify_token_status_list_cwt(
    cwt: &[u8],
    expected_algorithm: CoseSignatureAlgorithm,
    public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
    expected_status_list_uri: &str,
    now_unix: u64,
    freshness: TokenStatusListFreshnessPolicy,
) -> Result<VerifiedTokenStatusList, TokenStatusListError> {
    let policy = CosePolicy::new()
        .with_require_tagged_sign1(true)
        .allow_cose_algorithm(expected_algorithm)
        .with_max_cose_sign1_bytes(MAX_TOKEN_STATUS_CWT_BYTES);
    let verified = cose_verify1_with_policy(cwt, &policy, public_key_resolver)
        .map_err(|_| TokenStatusListError::Authentication)?;
    let valid_type = matches!(
        verified.cose_type,
        Some(CoseType::Text(ref value)) if value == STATUS_LIST_CWT_MEDIA_TYPE
    ) || matches!(
        verified.cose_type,
        Some(CoseType::Registered(value)) if value == STATUS_LIST_CWT_CONTENT_FORMAT
    );
    if !valid_type {
        return Err(TokenStatusListError::Authentication);
    }
    let (claims, compressed) = decode_claims(&verified.payload)?;
    let packed_statuses = validate_claims_with_compressed(&claims, &compressed)?;
    if claims.sub != expected_status_list_uri {
        return Err(TokenStatusListError::SubjectMismatch);
    }
    check_freshness(&claims, now_unix, freshness)?;
    Ok(VerifiedTokenStatusList {
        claims,
        packed_statuses,
    })
}

/// Decode CWT claims, returning the compressed status bytes alongside so they
/// are not re-encoded and re-decoded during validation.
fn decode_claims(payload: &[u8]) -> Result<(TokenStatusListClaims, Vec<u8>), TokenStatusListError> {
    let decoded = decode_deterministic_cbor(payload).map_err(|_| {
        TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidCwtClaims)
    })?;
    let entries = map_entries(&decoded)?;
    let subject = required_text(integer_member(entries, CWT_SUBJECT_CLAIM)?)?;
    let issued_at = required_unsigned(integer_member(entries, CWT_ISSUED_AT_CLAIM)?)?;
    let expiration = optional_unsigned(integer_member(entries, CWT_EXPIRATION_CLAIM)?)?;
    let ttl = optional_unsigned(integer_member(entries, CWT_TTL_CLAIM)?)?;
    let status = required_value(integer_member(entries, CWT_STATUS_LIST_CLAIM)?)?;
    let status_entries = map_entries(status)?;
    if status_entries.iter().any(|entry| {
        !matches!(
            entry.key(),
            DeterministicCborMapKey::Text(key)
                if matches!(key.as_str(), "bits" | "lst" | "aggregation_uri")
        )
    }) {
        return Err(invalid_claims());
    }
    let bits = required_unsigned(text_member(status_entries, "bits")?)?;
    let bits = u8::try_from(bits).map_err(|_| invalid_claims())?;
    let compressed = required_bytes(text_member(status_entries, "lst")?)?;
    let aggregation_uri = optional_text(text_member(status_entries, "aggregation_uri")?)?;

    let claims = TokenStatusListClaims {
        profile: TokenStatusListProfile::IetfDraft21,
        sub: subject,
        iat: issued_at,
        exp: expiration,
        ttl,
        status_list: TokenStatusListPayload {
            bits,
            lst: bytes_to_base64url(&compressed),
            aggregation_uri,
        },
    };
    Ok((claims, compressed))
}

fn invalid_claims() -> TokenStatusListError {
    TokenStatusListError::InvalidInput(TokenStatusListInvalidReason::InvalidCwtClaims)
}

fn map_entries(
    value: &DeterministicCborValue,
) -> Result<&[DeterministicCborMapEntry], TokenStatusListError> {
    match value {
        DeterministicCborValue::Map(entries) => Ok(entries),
        _ => Err(invalid_claims()),
    }
}

fn integer_member(
    entries: &[DeterministicCborMapEntry],
    expected: u64,
) -> Result<Option<&DeterministicCborValue>, TokenStatusListError> {
    let mut found = None;
    for item in entries {
        if matches!(
            item.key(),
            DeterministicCborMapKey::Integer(DeterministicCborInteger::Unsigned(value))
                if *value == expected
        ) {
            if found.is_some() {
                return Err(invalid_claims());
            }
            found = Some(item.value());
        }
    }
    Ok(found)
}

fn text_member<'a>(
    entries: &'a [DeterministicCborMapEntry],
    expected: &str,
) -> Result<Option<&'a DeterministicCborValue>, TokenStatusListError> {
    let mut found = None;
    for item in entries {
        if matches!(item.key(), DeterministicCborMapKey::Text(value) if value == expected) {
            if found.is_some() {
                return Err(invalid_claims());
            }
            found = Some(item.value());
        }
    }
    Ok(found)
}

fn required_value(
    value: Option<&DeterministicCborValue>,
) -> Result<&DeterministicCborValue, TokenStatusListError> {
    value.ok_or_else(invalid_claims)
}

fn required_unsigned(value: Option<&DeterministicCborValue>) -> Result<u64, TokenStatusListError> {
    match required_value(value)? {
        DeterministicCborValue::Integer(DeterministicCborInteger::Unsigned(value)) => Ok(*value),
        _ => Err(invalid_claims()),
    }
}

fn optional_unsigned(
    value: Option<&DeterministicCborValue>,
) -> Result<Option<u64>, TokenStatusListError> {
    value.map(|item| required_unsigned(Some(item))).transpose()
}

fn required_text(value: Option<&DeterministicCborValue>) -> Result<String, TokenStatusListError> {
    match required_value(value)? {
        DeterministicCborValue::Text(value) => Ok(value.clone()),
        _ => Err(invalid_claims()),
    }
}

fn optional_text(
    value: Option<&DeterministicCborValue>,
) -> Result<Option<String>, TokenStatusListError> {
    value.map(|item| required_text(Some(item))).transpose()
}

fn required_bytes(value: Option<&DeterministicCborValue>) -> Result<Vec<u8>, TokenStatusListError> {
    match required_value(value)? {
        DeterministicCborValue::Bytes(value) => Ok(value.clone()),
        _ => Err(invalid_claims()),
    }
}
