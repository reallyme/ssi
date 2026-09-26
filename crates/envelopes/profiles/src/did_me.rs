// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    invalid, validate_common, CredentialProfile, EnvelopeFormat, EnvelopeProfileInput,
    EnvelopeProfileInvalidReason, Result, DID_ME_CRYPTOSUITE, DID_ME_METHOD, DID_ME_PREFIX,
};

/// Enforce protocol-neutral did:me envelope constraints.
pub fn enforce_did_me_profile(input: &EnvelopeProfileInput<'_>) -> Result<()> {
    validate_common(input)?;

    if !matches!(input.credential_profile, CredentialProfile::DidMe) {
        return Err(invalid(
            EnvelopeProfileInvalidReason::UnsupportedCredentialProfile,
        ));
    }

    let Some(did_method) = input.did_method else {
        return Err(invalid(EnvelopeProfileInvalidReason::MissingDidMethod));
    };
    if did_method != DID_ME_METHOD || !is_did_me(input.issuer) || !is_did_me(input.subject) {
        return Err(invalid(EnvelopeProfileInvalidReason::InvalidDidMeBinding));
    }

    match input.format {
        EnvelopeFormat::DataIntegrity => {
            // A Data Integrity proof is only meaningful with a declared
            // cryptosuite; absence must not bypass the suite check.
            let Some(suite) = input.proof_cryptosuite else {
                return Err(invalid(
                    EnvelopeProfileInvalidReason::MissingDidMeCryptosuite,
                ));
            };
            validate_cryptosuite(suite)?;
        }
        EnvelopeFormat::JwtVcJson | EnvelopeFormat::DcSdJwt => {
            if let Some(suite) = input.proof_cryptosuite {
                validate_cryptosuite(suite)?;
            }
        }
        EnvelopeFormat::MsoMdoc | EnvelopeFormat::CoseSign1Vc | EnvelopeFormat::Unspecified => {
            return Err(invalid(
                EnvelopeProfileInvalidReason::UnsupportedEnvelopeFormat,
            ));
        }
    }

    Ok(())
}

/// Require a `did:me:` identifier with a non-empty method-specific id.
fn is_did_me(identifier: &str) -> bool {
    identifier
        .strip_prefix(DID_ME_PREFIX)
        .is_some_and(|method_specific_id| !method_specific_id.is_empty())
}

fn validate_cryptosuite(suite: &str) -> Result<()> {
    if suite == DID_ME_CRYPTOSUITE {
        Ok(())
    } else {
        Err(invalid(
            EnvelopeProfileInvalidReason::UnsupportedDidMeCryptosuite,
        ))
    }
}
