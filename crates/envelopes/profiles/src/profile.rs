// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// did:me identity envelope profile constraints.
#[path = "did_me.rs"]
pub mod did_me;
/// EU PID identity envelope profile constraints.
#[path = "eu_pid.rs"]
pub mod eu_pid;
/// OpenID4VC identity envelope profile constraints.
#[path = "openid4vc.rs"]
pub mod openid4vc;

pub use did_me::enforce_did_me_profile;
pub use eu_pid::enforce_eu_pid_profile;
pub use openid4vc::enforce_openid4vc_profile;

/// Credential envelope family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeFormat {
    /// Format has not been selected.
    Unspecified,
    /// OpenID4VCI `jwt_vc_json`.
    JwtVcJson,
    /// SD-JWT VC / Digital Credentials `dc+sd-jwt`.
    DcSdJwt,
    /// ISO/IEC 18013-5 `mso_mdoc`.
    MsoMdoc,
    /// COSE Sign1 credential envelope.
    CoseSign1Vc,
    /// W3C Data Integrity credential envelope.
    DataIntegrity,
}

/// Identity credential profile family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialProfile {
    /// Profile has not been selected.
    Unspecified,
    /// EU PID profile.
    EuPid,
    /// Electronic Attestation of Attributes profile.
    EuEaa,
    /// Qualified Electronic Attestation of Attributes profile.
    EuQeaa,
    /// Age-derived credential profile.
    EuAge,
    /// Passport-derived credential profile.
    EuPassport,
    /// did:me DID document or credential profile.
    DidMe,
    /// Generic OpenID4VC credential profile.
    OpenId4Vc,
}

/// Profile families with dedicated validation entry points.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeProfile {
    /// OpenID for Verifiable Credentials profile constraints.
    OpenId4Vc,
    /// EU PID and EUDI-aligned profile constraints.
    EuPid,
    /// ReallyMe DID profile constraints.
    DidMe,
}

/// Protocol-neutral metadata used to enforce an envelope profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeProfileInput<'a> {
    /// Credential envelope family.
    pub format: EnvelopeFormat,

    /// Credential profile family.
    pub credential_profile: CredentialProfile,

    /// Credential claimset identifier such as `eu.pid.v1`.
    pub claimset_id: &'a str,

    /// Issuer identifier or DID.
    pub issuer: &'a str,

    /// Subject identifier or DID.
    pub subject: &'a str,

    /// SD-JWT VC type when the envelope carries one.
    pub vct: Option<&'a str>,

    /// Inclusive validity start as Unix seconds.
    pub valid_from_unix: Option<u64>,

    /// Exclusive or profile-defined validity end as Unix seconds.
    pub valid_until_unix: Option<u64>,

    /// Whether credential-status metadata is present in the envelope.
    pub status_present: bool,

    /// Whether QEAA compliance metadata is present in the envelope.
    pub qeaa_metadata_present: bool,

    /// DID method name when known, for example `did:me`.
    pub did_method: Option<&'a str>,

    /// Data Integrity cryptosuite when known.
    pub proof_cryptosuite: Option<&'a str>,
}

/// Stable reasons for invalid envelope profile metadata.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EnvelopeProfileInvalidReason {
    /// Envelope format was not specified.
    #[error("missing envelope format")]
    MissingFormat,

    /// Credential profile was not specified.
    #[error("missing credential profile")]
    MissingCredentialProfile,

    /// Credential claimset identifier is missing.
    #[error("missing claimset identifier")]
    MissingClaimsetId,

    /// Issuer identifier is missing.
    #[error("missing issuer identifier")]
    MissingIssuer,

    /// Subject identifier is missing.
    #[error("missing subject identifier")]
    MissingSubject,

    /// Validity window is absent or malformed.
    #[error("invalid validity window")]
    InvalidValidityWindow,

    /// Envelope format is not accepted by the selected profile.
    #[error("unsupported envelope format")]
    UnsupportedEnvelopeFormat,

    /// Credential profile is not accepted by the selected profile.
    #[error("unsupported credential profile")]
    UnsupportedCredentialProfile,

    /// Claimset identifier is not accepted by the selected profile.
    #[error("unsupported claimset identifier")]
    UnsupportedClaimset,

    /// SD-JWT VC type is required for this envelope.
    #[error("missing SD-JWT VC type")]
    MissingVct,

    /// Credential-status metadata is required for this profile.
    #[error("missing status metadata")]
    MissingStatusMetadata,

    /// QEAA compliance metadata is required for this profile.
    #[error("missing QEAA metadata")]
    MissingQeaaMetadata,

    /// did:me profile requires did:me identifiers or method metadata.
    #[error("invalid did:me binding")]
    InvalidDidMeBinding,

    /// did:me Data Integrity proof uses an unsupported cryptosuite.
    #[error("unsupported did:me cryptosuite")]
    UnsupportedDidMeCryptosuite,
}

/// Error for envelope profile validation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EnvelopeProfileError {
    /// Profile metadata violated a typed validation rule.
    #[error("invalid envelope profile metadata: {0}")]
    InvalidInput(EnvelopeProfileInvalidReason),
}

impl From<EnvelopeProfileInvalidReason> for IdentityCoreErrorReason {
    fn from(reason: EnvelopeProfileInvalidReason) -> Self {
        match reason {
            EnvelopeProfileInvalidReason::MissingFormat => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_FORMAT
            }
            EnvelopeProfileInvalidReason::MissingCredentialProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_CREDENTIAL_PROFILE
            }
            EnvelopeProfileInvalidReason::MissingClaimsetId => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_CLAIMSET_ID
            }
            EnvelopeProfileInvalidReason::MissingIssuer => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_ISSUER
            }
            EnvelopeProfileInvalidReason::MissingSubject => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_SUBJECT
            }
            EnvelopeProfileInvalidReason::InvalidValidityWindow => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_INVALID_VALIDITY_WINDOW
            }
            EnvelopeProfileInvalidReason::UnsupportedEnvelopeFormat => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_UNSUPPORTED_ENVELOPE_FORMAT
            }
            EnvelopeProfileInvalidReason::UnsupportedCredentialProfile => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_UNSUPPORTED_CREDENTIAL_PROFILE
            }
            EnvelopeProfileInvalidReason::UnsupportedClaimset => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_UNSUPPORTED_CLAIMSET
            }
            EnvelopeProfileInvalidReason::MissingVct => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_VCT
            }
            EnvelopeProfileInvalidReason::MissingStatusMetadata => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_STATUS_METADATA
            }
            EnvelopeProfileInvalidReason::MissingQeaaMetadata => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_QEAA_METADATA
            }
            EnvelopeProfileInvalidReason::InvalidDidMeBinding => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_INVALID_DID_ME_BINDING
            }
            EnvelopeProfileInvalidReason::UnsupportedDidMeCryptosuite => {
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_UNSUPPORTED_DID_ME_CRYPTOSUITE
            }
        }
    }
}

impl From<EnvelopeProfileError> for IdentityCoreErrorReason {
    fn from(reason: EnvelopeProfileError) -> Self {
        match reason {
            EnvelopeProfileError::InvalidInput(reason) => reason.into(),
        }
    }
}

pub(crate) const DID_ME_METHOD: &str = "did:me";
pub(crate) const DID_ME_CRYPTOSUITE: &str = "es256-jws-cid-2025";
pub(crate) const EU_PID_CLAIMSET: &str = "eu.pid.v1";
pub(crate) const EU_AGE_CLAIMSET: &str = "eu.age.v1";
pub(crate) const EU_TAX_CLAIMSET: &str = "eu.tax.v1";
pub(crate) const EU_PASSPORT_CLAIMSET: &str = "eu.passport.v1";

pub(crate) type Result<T> = core::result::Result<T, EnvelopeProfileError>;

pub(crate) fn invalid(reason: EnvelopeProfileInvalidReason) -> EnvelopeProfileError {
    EnvelopeProfileError::InvalidInput(reason)
}

pub(crate) fn validate_common(input: &EnvelopeProfileInput<'_>) -> Result<()> {
    if matches!(input.format, EnvelopeFormat::Unspecified) {
        return Err(invalid(EnvelopeProfileInvalidReason::MissingFormat));
    }
    if matches!(input.credential_profile, CredentialProfile::Unspecified) {
        return Err(invalid(
            EnvelopeProfileInvalidReason::MissingCredentialProfile,
        ));
    }
    if input.claimset_id.trim().is_empty() {
        return Err(invalid(EnvelopeProfileInvalidReason::MissingClaimsetId));
    }
    if input.issuer.trim().is_empty() {
        return Err(invalid(EnvelopeProfileInvalidReason::MissingIssuer));
    }
    if input.subject.trim().is_empty() {
        return Err(invalid(EnvelopeProfileInvalidReason::MissingSubject));
    }
    if let (Some(valid_from), Some(valid_until)) = (input.valid_from_unix, input.valid_until_unix) {
        if valid_until <= valid_from {
            return Err(invalid(EnvelopeProfileInvalidReason::InvalidValidityWindow));
        }
    }

    Ok(())
}

pub(crate) fn require_status(input: &EnvelopeProfileInput<'_>) -> Result<()> {
    if input.status_present {
        Ok(())
    } else {
        Err(invalid(EnvelopeProfileInvalidReason::MissingStatusMetadata))
    }
}

pub(crate) fn require_validity_window(input: &EnvelopeProfileInput<'_>) -> Result<()> {
    let (Some(valid_from), Some(valid_until)) = (input.valid_from_unix, input.valid_until_unix)
    else {
        return Err(invalid(EnvelopeProfileInvalidReason::InvalidValidityWindow));
    };
    if valid_until <= valid_from {
        return Err(invalid(EnvelopeProfileInvalidReason::InvalidValidityWindow));
    }

    Ok(())
}

pub(crate) fn require_vct_for_sd_jwt(input: &EnvelopeProfileInput<'_>) -> Result<()> {
    if !matches!(input.format, EnvelopeFormat::DcSdJwt) {
        return Ok(());
    }
    if input.vct.is_some_and(|vct| !vct.trim().is_empty()) {
        Ok(())
    } else {
        Err(invalid(EnvelopeProfileInvalidReason::MissingVct))
    }
}

#[cfg(test)]
#[path = "lib_proto_error_tests.rs"]
mod proto_error_tests;
