// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_credential_claims_core::DisclosureMode;

use identity_presentation_vp_core::model::{
    DisclosureMode as VpDisclosureMode, Presentation, SdJwtVcPresentation,
};

use crate::error::VpPolicyError;

/// A policy-relevant disclosure intent extracted from a presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosedClaim {
    /// Canonical claim path disclosed by the presentation.
    pub claim_path: String,

    /// Semantic disclosure mode satisfied for the claim.
    pub mode: DisclosureMode,
}

/// Extract disclosed claims from any VP presentation (SD-JWT or ZK).
///
/// This is format-agnostic policy plumbing:
/// - SD-JWT disclosures imply `Reveal`
/// - ZK disclosures carry explicit disclosure modes
pub fn extract_disclosed_claims(pres: &Presentation) -> Result<Vec<DisclosedClaim>, VpPolicyError> {
    match pres {
        Presentation::SdJwtVc(sd) => {
            extract_sd_jwt_disclosed_claims(sd).map_err(|_| VpPolicyError::ProofInvalid)
        }

        Presentation::Zk(zk) => zk
            .disclosures
            .iter()
            .map(|item| {
                Ok(DisclosedClaim {
                    claim_path: item.claim_path.clone(),
                    mode: map_zk_disclosure_mode(item.mode)?,
                })
            })
            .collect(),

        // mdoc presentations are verified by the mdoc delivery layer and do not
        // carry VP disclosure semantics in this crate.
        Presentation::Mdoc(_) => Err(VpPolicyError::PresentationFormatNotAllowed),
    }
}

fn extract_sd_jwt_disclosed_claims(
    vp: &SdJwtVcPresentation,
) -> Result<Vec<DisclosedClaim>, VpPolicyError> {
    let mut out = Vec::new();

    for encoded in &vp.disclosures {
        let bytes = codec_base64url::base64url_to_bytes(encoded)
            .map_err(|_| VpPolicyError::ProofInvalid)?;

        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| VpPolicyError::ProofInvalid)?;

        // Policy only needs the selector. Signature, digest, and value checks stay in
        // the SD-JWT verification layer so policy does not depend on JOSE.
        let arr = value.as_array().ok_or(VpPolicyError::ProofInvalid)?;
        let claim_path = arr
            .get(1)
            .and_then(|v| v.as_str())
            .ok_or(VpPolicyError::ProofInvalid)?;

        out.push(DisclosedClaim {
            claim_path: claim_path.to_owned(),
            mode: DisclosureMode::Reveal,
        });
    }

    Ok(out)
}

fn map_zk_disclosure_mode(mode: VpDisclosureMode) -> Result<DisclosureMode, VpPolicyError> {
    match mode {
        VpDisclosureMode::Unspecified => Err(VpPolicyError::ProofInvalid),
        VpDisclosureMode::Hidden => Ok(DisclosureMode::Hidden),
        VpDisclosureMode::Reveal => Ok(DisclosureMode::Reveal),
        VpDisclosureMode::Eq => Ok(DisclosureMode::Eq),
        VpDisclosureMode::Gte => Ok(DisclosureMode::Gte),
        VpDisclosureMode::Lte => Ok(DisclosureMode::Lte),
        VpDisclosureMode::Range => Ok(DisclosureMode::Range),
        VpDisclosureMode::MemberOfSet => Ok(DisclosureMode::MemberOfSet),
    }
}
