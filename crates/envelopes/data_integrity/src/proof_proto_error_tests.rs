// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{DataIntegrityProofError, IdentityCoreErrorReason};

#[test]
fn data_integrity_proof_errors_map_to_stable_proto_reasons() {
    let cases = [
            (
                DataIntegrityProofError::InvalidInput,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DATA_INTEGRITY_PROOF_INVALID_INPUT,
            ),
            (
                DataIntegrityProofError::UnsupportedCryptosuite,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DATA_INTEGRITY_PROOF_UNSUPPORTED_CRYPTOSUITE,
            ),
            (
                DataIntegrityProofError::CryptosuiteFailed,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DATA_INTEGRITY_PROOF_CRYPTOSUITE_FAILED,
            ),
        ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
