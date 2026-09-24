// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{EnvelopeProfileError, EnvelopeProfileInvalidReason, IdentityCoreErrorReason};

#[test]
fn envelope_profile_reasons_map_to_stable_proto_reasons() {
    let cases = [
            (
                EnvelopeProfileInvalidReason::MissingFormat,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_FORMAT,
            ),
            (
                EnvelopeProfileInvalidReason::MissingCredentialProfile,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_CREDENTIAL_PROFILE,
            ),
            (
                EnvelopeProfileInvalidReason::MissingClaimsetId,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_CLAIMSET_ID,
            ),
            (
                EnvelopeProfileInvalidReason::MissingIssuer,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_ISSUER,
            ),
            (
                EnvelopeProfileInvalidReason::MissingSubject,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_SUBJECT,
            ),
            (
                EnvelopeProfileInvalidReason::InvalidValidityWindow,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_INVALID_VALIDITY_WINDOW,
            ),
            (
                EnvelopeProfileInvalidReason::UnsupportedEnvelopeFormat,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_UNSUPPORTED_ENVELOPE_FORMAT,
            ),
            (
                EnvelopeProfileInvalidReason::UnsupportedCredentialProfile,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_UNSUPPORTED_CREDENTIAL_PROFILE,
            ),
            (
                EnvelopeProfileInvalidReason::UnsupportedClaimset,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_UNSUPPORTED_CLAIMSET,
            ),
            (
                EnvelopeProfileInvalidReason::MissingVct,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_VCT,
            ),
            (
                EnvelopeProfileInvalidReason::MissingStatusMetadata,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_STATUS_METADATA,
            ),
            (
                EnvelopeProfileInvalidReason::MissingQeaaMetadata,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_QEAA_METADATA,
            ),
            (
                EnvelopeProfileInvalidReason::InvalidDidMeBinding,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_INVALID_DID_ME_BINDING,
            ),
            (
                EnvelopeProfileInvalidReason::UnsupportedDidMeCryptosuite,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_UNSUPPORTED_DID_ME_CRYPTOSUITE,
            ),
        ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}

#[test]
fn envelope_profile_error_delegates_to_invalid_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(EnvelopeProfileError::InvalidInput(
            EnvelopeProfileInvalidReason::MissingSubject
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ENVELOPE_PROFILE_MISSING_SUBJECT
    );
}
