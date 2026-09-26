// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Disclosure mode and value consistency rules shared by encode and decode.

use reallyme_ssi_proto::generated::proto::identity::presentation::v1::__buffa::oneof::claim_disclosure;
use reallyme_vp_core as vp;

use crate::presentation::VpProtoError;

/// Require a Rust disclosure model to populate exactly the value its mode declares.
pub(super) fn validate_disclosure_model(model: &vp::ClaimDisclosure) -> Result<(), VpProtoError> {
    let revealed = model.revealed_value.is_some();
    let threshold = model.threshold.is_some();
    let range = model.range.is_some();
    let set = model.set.is_some();
    let consistent = match model.mode {
        vp::DisclosureMode::Unspecified => return Err(VpProtoError::InvalidEnumValue),
        vp::DisclosureMode::Hidden => !revealed && !threshold && !range && !set,
        vp::DisclosureMode::Reveal | vp::DisclosureMode::Eq => {
            revealed && !threshold && !range && !set
        }
        vp::DisclosureMode::Gte | vp::DisclosureMode::Lte => {
            !revealed && threshold && !range && !set
        }
        vp::DisclosureMode::Range => {
            !revealed
                && !threshold
                && !set
                && model
                    .range
                    .as_ref()
                    .is_some_and(|value| value.min <= value.max)
        }
        vp::DisclosureMode::MemberOfSet => !revealed && !threshold && !range && set,
    };
    if consistent {
        Ok(())
    } else {
        Err(VpProtoError::InconsistentDisclosure)
    }
}

/// Require the populated value oneof to match the declared disclosure mode.
pub(super) fn validate_disclosure_value(
    mode: vp::DisclosureMode,
    value: Option<&claim_disclosure::Value>,
) -> Result<(), VpProtoError> {
    let consistent = match (mode, value) {
        (vp::DisclosureMode::Unspecified, _) => return Err(VpProtoError::InvalidEnumValue),
        (vp::DisclosureMode::Hidden, None)
        | (
            vp::DisclosureMode::Reveal | vp::DisclosureMode::Eq,
            Some(claim_disclosure::Value::RevealedValue(_)),
        )
        | (
            vp::DisclosureMode::Gte | vp::DisclosureMode::Lte,
            Some(claim_disclosure::Value::Threshold(_)),
        )
        | (vp::DisclosureMode::MemberOfSet, Some(claim_disclosure::Value::Set(_))) => true,
        (vp::DisclosureMode::Range, Some(claim_disclosure::Value::Range(range))) => {
            range.min <= range.max
        }
        _ => false,
    };
    if consistent {
        Ok(())
    } else {
        Err(VpProtoError::InconsistentDisclosure)
    }
}
