// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Deserialize;
use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::RegistryMetadata;
use crate::json::{canonical_json, deserialize_strict, MAX_JSON_BYTES};
use crate::model::RawWalletRelyingParty;
use crate::{
    ArtifactDigest, BoundedText, ProtocolProfile, RegistrationError, RegistrationErrorReason,
    RegistryPagination, RegistryPayload, RegistryPayloadShape,
};

const MAX_COMPACT_JWS_BYTES: usize = 6 * 1_024 * 1_024;
/// Tolerated forward clock skew for a registrar `iat`, in seconds.
const REGISTRY_CLOCK_SKEW_SECONDS: u64 = 60;
/// Largest caller-selectable freshness bound for a registrar answer, in seconds.
const MAX_REGISTRY_RESPONSE_AGE_SECONDS: u64 = 86_400;

/// Validated caller freshness policy for current signed registrar answers.
#[derive(Clone, Copy)]
pub(super) struct FreshnessPolicy {
    evaluation_time: u64,
    max_age_seconds: u64,
}

impl FreshnessPolicy {
    pub(super) fn try_new(
        evaluation_time: OffsetDateTime,
        max_age_seconds: u64,
    ) -> Result<Self, RegistrationError> {
        if max_age_seconds == 0 || max_age_seconds > MAX_REGISTRY_RESPONSE_AGE_SECONDS {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            ));
        }
        let evaluation_time =
            u64::try_from(evaluation_time.unix_timestamp()).map_err(|_error| {
                RegistrationError::from_reason(RegistrationErrorReason::ResponseNotFresh)
            })?;
        Ok(Self {
            evaluation_time,
            max_age_seconds,
        })
    }

    fn check(self, issued_at: u64) -> Result<(), RegistrationError> {
        let latest_issue = self
            .evaluation_time
            .checked_add(REGISTRY_CLOCK_SKEW_SECONDS)
            .ok_or_else(|| {
                RegistrationError::from_reason(RegistrationErrorReason::ResponseNotFresh)
            })?;
        let age = self.evaluation_time.saturating_sub(issued_at);
        if issued_at > latest_issue || age > self.max_age_seconds {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::ResponseNotFresh,
            ));
        }
        Ok(())
    }
}

pub(super) fn validate_profile_shape(
    profile: ProtocolProfile,
    shape: RegistryPayloadShape,
) -> Result<(), RegistrationError> {
    let valid = matches!(
        (profile, shape),
        (
            ProtocolProfile::Ts5V1_5,
            RegistryPayloadShape::Ts5SignedWrpArray
                | RegistryPayloadShape::Ts5SignedWrp
                | RegistryPayloadShape::Ts5SignedIntendedUseCheck
        ) | (
            ProtocolProfile::EuReferenceLegacyV0_2_2,
            RegistryPayloadShape::LegacyRawWrpArray
                | RegistryPayloadShape::LegacyRawWrp
                | RegistryPayloadShape::LegacyRawBoolean
        )
    );
    if !valid {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::PayloadShapeMismatch,
        ));
    }
    Ok(())
}

pub(super) fn validate_compact(compact: &[u8]) -> Result<(), RegistrationError> {
    if compact.is_empty() || compact.len() > MAX_COMPACT_JWS_BYTES || !compact.is_ascii() {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidCompactJws,
        ));
    }
    let mut parts = compact.split(|byte| *byte == b'.');
    let header = parts.next();
    let payload = parts.next();
    let signature = parts.next();
    if header.is_none()
        || payload.is_none()
        || signature.is_none()
        || parts.next().is_some()
        || header.is_some_and(<[u8]>::is_empty)
        || payload.is_some_and(<[u8]>::is_empty)
        || signature.is_some_and(<[u8]>::is_empty)
    {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidCompactJws,
        ));
    }
    Ok(())
}

pub(super) fn decode_compact_payload(
    compact: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RegistrationError> {
    let encoded = compact.split(|byte| *byte == b'.').nth(1).ok_or_else(|| {
        RegistrationError::from_reason(RegistrationErrorReason::InvalidCompactJws)
    })?;
    let decoded = Zeroizing::new(
        reallyme_codec::base64url::base64url_bytes_to_bytes(encoded).map_err(|_error| {
            RegistrationError::from_reason(RegistrationErrorReason::InvalidCompactJws)
        })?,
    );
    if decoded.is_empty() || decoded.len() > MAX_JSON_BYTES {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InputTooLarge,
        ));
    }
    Ok(decoded)
}

pub(super) fn parse_selected_payload(
    shape: RegistryPayloadShape,
    bytes: &[u8],
    freshness: FreshnessPolicy,
) -> Result<(RegistryPayload, RegistryMetadata), RegistrationError> {
    match shape {
        RegistryPayloadShape::Ts5SignedWrpArray => {
            let mut envelope: SignedWrpArray = deserialize_strict(bytes)?;
            let metadata = current_metadata(&envelope.iss, envelope.iat, freshness)?;
            let records = core::mem::take(&mut envelope.data)
                .into_iter()
                .map(RawWalletRelyingParty::validate)
                .collect::<Result<Vec<_>, RegistrationError>>()?;
            let pagination = validate_pagination(envelope.pagination.as_ref())?;
            Ok((
                RegistryPayload::WrpArray {
                    records,
                    pagination,
                },
                metadata,
            ))
        }
        RegistryPayloadShape::Ts5SignedWrp => {
            let mut envelope: SignedWrp = deserialize_strict(bytes)?;
            let issuer = Zeroizing::new(core::mem::take(&mut envelope.iss));
            let metadata = current_metadata(&issuer, envelope.iat, freshness)?;
            Ok((
                RegistryPayload::Wrp(Box::new(envelope.data.validate()?)),
                metadata,
            ))
        }
        RegistryPayloadShape::Ts5SignedIntendedUseCheck => {
            let envelope: SignedIntendedUseCheck = deserialize_strict(bytes)?;
            let metadata = current_metadata(&envelope.iss, envelope.iat, freshness)?;
            let details = envelope
                .data
                .details
                .as_deref()
                .map(BoundedText::try_new)
                .transpose()?;
            Ok((
                RegistryPayload::IntendedUseCheck {
                    is_registered: envelope.data.is_registered,
                    details,
                },
                metadata,
            ))
        }
        RegistryPayloadShape::LegacyRawWrpArray => {
            let _values: Vec<RawWalletRelyingParty> = deserialize_strict(bytes)?;
            Err(RegistrationError::from_reason(
                RegistrationErrorReason::UnboundLegacyAnswer,
            ))
        }
        RegistryPayloadShape::LegacyRawWrp => {
            let _value: RawWalletRelyingParty = deserialize_strict(bytes)?;
            Err(RegistrationError::from_reason(
                RegistrationErrorReason::UnboundLegacyAnswer,
            ))
        }
        RegistryPayloadShape::LegacyRawBoolean => {
            // The legacy Boolean carries no authenticated issuer, issue time,
            // or echo of the queried identifiers. It is parsed strictly so
            // malformed input keeps its precise reason, but it never yields an
            // answer a caller could treat as an authorization decision.
            let _answer: bool = deserialize_strict(bytes)?;
            Err(RegistrationError::from_reason(
                RegistrationErrorReason::UnboundLegacyAnswer,
            ))
        }
    }
}

fn current_metadata(
    issuer: &str,
    issued_at: i64,
    freshness: FreshnessPolicy,
) -> Result<RegistryMetadata, RegistrationError> {
    if issued_at <= 0 {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        ));
    }
    let issuer = BoundedText::try_new(issuer)?;
    let canonical = Zeroizing::new(canonical_json(&issuer)?);
    let issued_at = u64::try_from(issued_at)
        .map_err(|_error| RegistrationError::from_reason(RegistrationErrorReason::InvalidField))?;
    freshness.check(issued_at)?;
    Ok(RegistryMetadata::Current {
        issuer_digest: ArtifactDigest::of(&canonical),
        issued_at,
    })
}

fn validate_pagination(
    pagination: Option<&Pagination>,
) -> Result<Option<RegistryPagination>, RegistrationError> {
    pagination
        .map(|value| RegistryPagination::try_new(value.next_cursor.as_deref(), value.has_next_page))
        .transpose()
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct SignedWrpArray {
    iss: String,
    iat: i64,
    data: Vec<RawWalletRelyingParty>,
    pagination: Option<Pagination>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedWrp {
    iss: String,
    iat: i64,
    data: RawWalletRelyingParty,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct SignedIntendedUseCheck {
    iss: String,
    iat: i64,
    data: IntendedUseCheckData,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct IntendedUseCheckData {
    #[serde(rename = "isRegistered")]
    is_registered: bool,
    details: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Pagination {
    next_cursor: Option<String>,
    has_next_page: bool,
}
