// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_credential_claims_core::{DisclosureMode, MAX_CLAIM_PATH_BYTES};
use identity_presentation_vp_core::model::SdJwtVcPresentation;
use reallyme_credential::committed::issue::MAX_COMMITMENT_CLAIMS;

use crate::error::SdJwtVpError;

// Mirrors the verifier's per-disclosure cap so policy extraction cannot be
// driven into unbounded decoding work before cryptographic verification.
const MAX_ENCODED_POLICY_DISCLOSURE_BYTES: usize = 2_000_000;

/// Semantic representation of a disclosed claim for policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosedClaim {
    /// Canonical claim path disclosed by the SD-JWT VP.
    pub claim_path: String,
    /// Semantic disclosure mode satisfied for the claim.
    pub mode: DisclosureMode,
}

/// Extract disclosed claim semantics from an SD-JWT VP.
///
/// This function:
/// - does NOT verify signatures
/// - does NOT check predicates
/// - does NOT inspect values
///
/// It purely answers:
/// "Which claims were disclosed, and how?"
pub fn extract_disclosed_claims(
    vp: &SdJwtVcPresentation,
) -> Result<Vec<DisclosedClaim>, SdJwtVpError> {
    if vp.disclosures.len() > MAX_COMMITMENT_CLAIMS {
        return Err(SdJwtVpError::InvalidDisclosure);
    }
    let mut out = Vec::new();
    out.try_reserve(vp.disclosures.len())
        .map_err(|_| SdJwtVpError::InvalidDisclosure)?;

    for encoded in &vp.disclosures {
        if encoded.len() > MAX_ENCODED_POLICY_DISCLOSURE_BYTES {
            return Err(SdJwtVpError::InvalidDisclosure);
        }
        let bytes = codec_base64url::base64url_to_bytes(encoded)
            .map_err(|_| SdJwtVpError::Serialization)?;

        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| SdJwtVpError::Serialization)?;

        // Expected SD-JWT disclosure array:
        // [ salt_b64, claim_path, value_b64, index, merkle_path[] ]
        let arr = value.as_array().ok_or(SdJwtVpError::Serialization)?;

        let claim_path = arr
            .get(1)
            .and_then(|v| v.as_str())
            .ok_or(SdJwtVpError::Serialization)?;
        if claim_path.len() > MAX_CLAIM_PATH_BYTES {
            return Err(SdJwtVpError::InvalidDisclosure);
        }

        // SD-JWT implies explicit reveal
        out.push(DisclosedClaim {
            claim_path: claim_path.to_string(),
            mode: DisclosureMode::Reveal,
        });
    }

    Ok(out)
}
