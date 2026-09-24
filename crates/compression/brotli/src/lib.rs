// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol-independent bounded Brotli helpers for byte payloads.
//!
//! The public decompression API enforces an output cap by default so untrusted
//! compressed payloads cannot expand without bound. Malformed or oversized
//! streams always return a typed error; the crate never reinterprets them as
//! plaintext.

mod compress;
mod decompress;
mod error;

pub use compress::brotli_compress;
pub use decompress::{
    brotli_decompress, brotli_decompress_with_limit, DEFAULT_MAX_DECOMPRESSED_BYTES,
};
pub use error::BrotliError;
