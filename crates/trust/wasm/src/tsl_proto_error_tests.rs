// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{TslSignerTrustFailureReason, TslWasmError};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn wasm_tsl_signer_trust_failures_map_to_stable_proto_reasons() {
    let cases = [
        (
            TslSignerTrustFailureReason::NoValidPath,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_NO_VALID_PATH,
        ),
        (
            TslSignerTrustFailureReason::InvalidTime,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INVALID_TIME,
        ),
        (
            TslSignerTrustFailureReason::ChainLinkPolicy,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_CHAIN_LINK_POLICY,
        ),
        (
            TslSignerTrustFailureReason::InvalidSignature,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INVALID_SIGNATURE,
        ),
        (
            TslSignerTrustFailureReason::Revoked,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_REVOKED,
        ),
        (
            TslSignerTrustFailureReason::StatusFailure,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_STATUS_FAILURE,
        ),
        (
            TslSignerTrustFailureReason::Internal,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_INTERNAL,
        ),
    ];

    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}

#[test]
fn wasm_tsl_errors_delegate_or_map_to_stable_proto_reasons() {
    assert_eq!(
        IdentityCoreErrorReason::from(TslWasmError::InvalidXml),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_WASM_INVALID_XML
    );
    assert_eq!(
        IdentityCoreErrorReason::from(TslWasmError::TrustFailure(
            TslSignerTrustFailureReason::StatusFailure
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_TSL_SIGNER_STATUS_FAILURE
    );
}
