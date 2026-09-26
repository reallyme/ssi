// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    invalid, require_status, require_validity_window, require_vct_for_sd_jwt, validate_common,
    CredentialProfile, EnvelopeFormat, EnvelopeProfileInput, EnvelopeProfileInvalidReason, Result,
    EU_AGE_CLAIMSET, EU_PASSPORT_CLAIMSET, EU_PID_CLAIMSET, EU_TAX_CLAIMSET,
};

/// Enforce protocol-neutral EU PID/EAA/QEAA envelope constraints.
pub fn enforce_eu_pid_profile(input: &EnvelopeProfileInput<'_>) -> Result<()> {
    validate_common(input)?;
    require_validity_window(input)?;
    require_status(input)?;
    require_vct_for_sd_jwt(input)?;
    validate_eu_format(input.format)?;
    validate_eu_profile(input)?;
    validate_eu_claimset(input.claimset_id)?;
    validate_eu_profile_claimset(input)?;
    validate_qeaa_metadata(input)?;

    Ok(())
}

fn validate_eu_format(format: EnvelopeFormat) -> Result<()> {
    match format {
        EnvelopeFormat::JwtVcJson
        | EnvelopeFormat::DcSdJwt
        | EnvelopeFormat::MsoMdoc
        | EnvelopeFormat::CoseSign1Vc => Ok(()),
        EnvelopeFormat::DataIntegrity | EnvelopeFormat::Unspecified => Err(invalid(
            EnvelopeProfileInvalidReason::UnsupportedEnvelopeFormat,
        )),
    }
}

fn validate_eu_profile(input: &EnvelopeProfileInput<'_>) -> Result<()> {
    match input.credential_profile {
        CredentialProfile::EuPid
        | CredentialProfile::EuEaa
        | CredentialProfile::EuQeaa
        | CredentialProfile::EuAge
        | CredentialProfile::EuPassport => Ok(()),
        CredentialProfile::OpenId4Vc
        | CredentialProfile::DidMe
        | CredentialProfile::Unspecified => Err(invalid(
            EnvelopeProfileInvalidReason::UnsupportedCredentialProfile,
        )),
    }
}

fn validate_eu_claimset(claimset_id: &str) -> Result<()> {
    match claimset_id {
        EU_PID_CLAIMSET | EU_AGE_CLAIMSET | EU_TAX_CLAIMSET | EU_PASSPORT_CLAIMSET => Ok(()),
        _ => Err(invalid(EnvelopeProfileInvalidReason::UnsupportedClaimset)),
    }
}

/// Bind dedicated EU credential profiles to their claimset.
///
/// PID, age, and passport profiles each have exactly one claimset. EAA and
/// QEAA are attestation categories rather than claim schemas, so they accept
/// any claimset admitted by [`validate_eu_claimset`].
fn validate_eu_profile_claimset(input: &EnvelopeProfileInput<'_>) -> Result<()> {
    let expected = match input.credential_profile {
        CredentialProfile::EuPid => EU_PID_CLAIMSET,
        CredentialProfile::EuAge => EU_AGE_CLAIMSET,
        CredentialProfile::EuPassport => EU_PASSPORT_CLAIMSET,
        CredentialProfile::EuEaa | CredentialProfile::EuQeaa => return Ok(()),
        CredentialProfile::OpenId4Vc
        | CredentialProfile::DidMe
        | CredentialProfile::Unspecified => {
            return Err(invalid(
                EnvelopeProfileInvalidReason::UnsupportedCredentialProfile,
            ));
        }
    };
    if input.claimset_id == expected {
        Ok(())
    } else {
        Err(invalid(EnvelopeProfileInvalidReason::UnsupportedClaimset))
    }
}

fn validate_qeaa_metadata(input: &EnvelopeProfileInput<'_>) -> Result<()> {
    if !matches!(input.credential_profile, CredentialProfile::EuQeaa) {
        return Ok(());
    }
    if input.qeaa_metadata_present {
        Ok(())
    } else {
        Err(invalid(EnvelopeProfileInvalidReason::MissingQeaaMetadata))
    }
}
