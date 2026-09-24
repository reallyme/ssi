// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    invalid, validate_common, CredentialProfile, EnvelopeFormat, EnvelopeProfileInput,
    EnvelopeProfileInvalidReason, Result, DID_ME_CRYPTOSUITE, DID_ME_METHOD,
};

/// Enforce protocol-neutral did:me envelope constraints.
pub fn enforce_did_me_profile(input: &EnvelopeProfileInput<'_>) -> Result<()> {
    validate_common(input)?;

    if !matches!(input.credential_profile, CredentialProfile::DidMe) {
        return Err(invalid(
            EnvelopeProfileInvalidReason::UnsupportedCredentialProfile,
        ));
    }

    if !input.issuer.starts_with(DID_ME_METHOD)
        || !input.subject.starts_with(DID_ME_METHOD)
        || input
            .did_method
            .is_some_and(|method| method != DID_ME_METHOD)
    {
        return Err(invalid(EnvelopeProfileInvalidReason::InvalidDidMeBinding));
    }

    match input.format {
        EnvelopeFormat::DataIntegrity | EnvelopeFormat::JwtVcJson | EnvelopeFormat::DcSdJwt => {}
        EnvelopeFormat::MsoMdoc | EnvelopeFormat::CoseSign1Vc | EnvelopeFormat::Unspecified => {
            return Err(invalid(
                EnvelopeProfileInvalidReason::UnsupportedEnvelopeFormat,
            ));
        }
    }

    if input
        .proof_cryptosuite
        .is_some_and(|suite| suite != DID_ME_CRYPTOSUITE)
    {
        return Err(invalid(
            EnvelopeProfileInvalidReason::UnsupportedDidMeCryptosuite,
        ));
    }

    Ok(())
}
