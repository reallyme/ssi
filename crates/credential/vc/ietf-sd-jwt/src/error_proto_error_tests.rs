// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::IetfSdJwtVcError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn ietf_sd_jwt_vc_errors_map_to_stable_proto_reasons() {
    let cases = [
            (
                IetfSdJwtVcError::InvalidInput,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_INVALID_INPUT,
            ),
            (
                IetfSdJwtVcError::MissingAlgorithm,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_MISSING_ALGORITHM,
            ),
            (
                IetfSdJwtVcError::UnsupportedAlgorithm,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_UNSUPPORTED_ALGORITHM,
            ),
            (
                IetfSdJwtVcError::Signature,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_SIGNATURE,
            ),
            (
                IetfSdJwtVcError::Verification,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_VERIFICATION,
            ),
            (
                IetfSdJwtVcError::Serialization,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_SERIALIZATION,
            ),
            (
                IetfSdJwtVcError::InvalidCompactFormat,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_INVALID_COMPACT_FORMAT,
            ),
            (
                IetfSdJwtVcError::InvalidDisclosure,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_INVALID_DISCLOSURE,
            ),
            (
                IetfSdJwtVcError::DisclosureDigestMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_DISCLOSURE_DIGEST_MISMATCH,
            ),
            (
                IetfSdJwtVcError::DuplicateClaimKey,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_DUPLICATE_CLAIM_KEY,
            ),
            (
                IetfSdJwtVcError::ReservedClaimKey,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_RESERVED_CLAIM_KEY,
            ),
            (
                IetfSdJwtVcError::InvalidJwtHeader,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_INVALID_JWT_HEADER,
            ),
            (
                IetfSdJwtVcError::MissingSdClaim,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_MISSING_SD_CLAIM,
            ),
            (
                IetfSdJwtVcError::InvalidSdClaim,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_IETF_SD_JWT_VC_INVALID_SD_CLAIM,
            ),
        ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
