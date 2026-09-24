// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SSI protobuf error mapping for protocol-independent compression failures.

use reallyme_compression_brotli::BrotliError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

/// Map a bounded Brotli failure into the stable SSI protobuf error taxonomy.
///
/// The compression crate deliberately does not depend on SSI contracts. This
/// adapter keeps protocol error ownership in the protobuf codec boundary.
#[must_use]
pub const fn brotli_error_to_proto_reason(error: BrotliError) -> IdentityCoreErrorReason {
    match error {
        BrotliError::CompressionFailed => {
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_SERIALIZATION_FAILED
        }
        BrotliError::DecompressionFailed => {
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING
        }
        BrotliError::OutputTooLarge => {
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_RESOURCE_LIMIT_EXCEEDED
        }
    }
}

#[cfg(test)]
#[path = "compression_tests.rs"]
mod tests;
