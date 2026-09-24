// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    invalid, require_validity_window, require_vct_for_sd_jwt, validate_common, CredentialProfile,
    EnvelopeFormat, EnvelopeProfileInput, EnvelopeProfileInvalidReason, Result,
};

/// Enforce protocol-neutral OpenID4VC envelope constraints.
pub fn enforce_openid4vc_profile(input: &EnvelopeProfileInput<'_>) -> Result<()> {
    validate_common(input)?;
    require_validity_window(input)?;
    require_vct_for_sd_jwt(input)?;

    match input.format {
        EnvelopeFormat::JwtVcJson
        | EnvelopeFormat::DcSdJwt
        | EnvelopeFormat::MsoMdoc
        | EnvelopeFormat::CoseSign1Vc => {}
        EnvelopeFormat::DataIntegrity | EnvelopeFormat::Unspecified => {
            return Err(invalid(
                EnvelopeProfileInvalidReason::UnsupportedEnvelopeFormat,
            ));
        }
    }

    match input.credential_profile {
        CredentialProfile::OpenId4Vc
        | CredentialProfile::EuPid
        | CredentialProfile::EuEaa
        | CredentialProfile::EuQeaa
        | CredentialProfile::EuAge
        | CredentialProfile::EuPassport => Ok(()),
        CredentialProfile::DidMe | CredentialProfile::Unspecified => Err(invalid(
            EnvelopeProfileInvalidReason::UnsupportedCredentialProfile,
        )),
    }
}
