// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stable protobuf error mapping coverage for bounded Brotli failures.

use reallyme_compression_brotli::BrotliError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

use super::brotli_error_to_proto_reason;

#[test]
fn maps_each_brotli_failure_to_a_stable_proto_reason() {
    assert_eq!(
        brotli_error_to_proto_reason(BrotliError::CompressionFailed),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SERIALIZATION_FAILED
    );
    assert_eq!(
        brotli_error_to_proto_reason(BrotliError::DecompressionFailed),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING
    );
    assert_eq!(
        brotli_error_to_proto_reason(BrotliError::OutputTooLarge),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
    );
}
