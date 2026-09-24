// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::Write;

use brotli::CompressorWriter;

use crate::BrotliError;

const BROTLI_BUFFER_SIZE: usize = 4096;
const BROTLI_QUALITY_BEST: u32 = 11;
const BROTLI_LG_WINDOW_DEFAULT: u32 = 22;

/// Compress bytes using Brotli at best compression.
///
/// Intended for arbitrary byte payloads. Protocol-specific framing and input
/// size policy remain the caller's responsibility.
pub fn brotli_compress(data: &[u8]) -> Result<Vec<u8>, BrotliError> {
    let mut out = Vec::new();

    {
        let mut writer = CompressorWriter::new(
            &mut out,
            BROTLI_BUFFER_SIZE,
            BROTLI_QUALITY_BEST,
            BROTLI_LG_WINDOW_DEFAULT,
        );
        writer
            .write_all(data)
            .map_err(|_| BrotliError::CompressionFailed)?;
    }

    Ok(out)
}
