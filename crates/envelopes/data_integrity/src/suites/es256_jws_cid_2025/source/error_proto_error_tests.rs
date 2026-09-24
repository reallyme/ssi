// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{Es256JwsCid2025Error, IdentityCoreErrorReason};

#[test]
fn es256_jws_cid_2025_errors_map_to_stable_proto_reasons() {
    let cases = [
            (
                Es256JwsCid2025Error::InvalidInput,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_INVALID_INPUT,
            ),
            (
                Es256JwsCid2025Error::BadProofType,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_BAD_PROOF_TYPE,
            ),
            (
                Es256JwsCid2025Error::BadCryptosuite,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_BAD_CRYPTOSUITE,
            ),
            (
                Es256JwsCid2025Error::MissingVerificationMethod,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_MISSING_VERIFICATION_METHOD,
            ),
            (
                Es256JwsCid2025Error::MissingJws,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_MISSING_JWS,
            ),
            (
                Es256JwsCid2025Error::VerificationMethodNotAllowed,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_VERIFICATION_METHOD_NOT_ALLOWED,
            ),
            (
                Es256JwsCid2025Error::VerificationMethodNotFound,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_VERIFICATION_METHOD_NOT_FOUND,
            ),
            (
                Es256JwsCid2025Error::InvalidMultikey,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_INVALID_MULTIKEY,
            ),
            (
                Es256JwsCid2025Error::WrongAlgorithm,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_WRONG_ALGORITHM,
            ),
            (
                Es256JwsCid2025Error::MalformedJws,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_MALFORMED_JWS,
            ),
            (
                Es256JwsCid2025Error::BadJwsHeader,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_BAD_JWS_HEADER,
            ),
            (
                Es256JwsCid2025Error::PayloadMismatch,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_PAYLOAD_MISMATCH,
            ),
            (
                Es256JwsCid2025Error::BadSignatureEncoding,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_BAD_SIGNATURE_ENCODING,
            ),
            (
                Es256JwsCid2025Error::VerifyFailed,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_ES256_JWS_CID_2025_VERIFY_FAILED,
            ),
        ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
