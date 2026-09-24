// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Typed Brotli wrapper failures.
///
/// Variants avoid embedding backend error text or raw input data because
/// compressed identity payloads can be attacker-controlled.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
pub enum BrotliError {
    /// Compression failed in the Brotli backend.
    #[error("brotli compression failed")]
    CompressionFailed,

    /// Decompression failed before producing a trusted payload.
    #[error("brotli decompression failed")]
    DecompressionFailed,

    /// Decompressed output exceeded the configured maximum length.
    #[error("brotli decompressed output exceeds configured limit")]
    OutputTooLarge,
}
