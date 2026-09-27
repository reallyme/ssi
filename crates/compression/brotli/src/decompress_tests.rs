// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::brotli_decompress_with_limit;
use std::io::Write;

#[test]
fn version_0_2_lgwin_22_stream_decodes_under_a_small_output_limit() {
    // Produced by the 0.2.x compressor, whose default lgwin was 22. This is a
    // protocol-compatibility vector, not generated during the test.
    const V0_2_COMPATIBILITY_BLOB: &[u8] = &[
        0x1b, 0x2b, 0x00, 0xf8, 0x45, 0x37, 0x97, 0xea, 0x42, 0x12, 0x31, 0x44, 0x9b, 0xc1, 0x64,
        0x88, 0x62, 0x10, 0x0e, 0x82, 0xc8, 0x93, 0x10, 0x59, 0x92, 0x2a, 0x6e, 0x32, 0xf2, 0xa6,
        0xef, 0x85, 0x08, 0x03, 0x93, 0x40, 0x77, 0xee, 0xb5, 0x2c, 0xbf, 0xf2, 0x66, 0x01,
    ];
    const EXPECTED: &[u8] = b"ReallyMe SSI 0.2 Brotli compatibility vector";

    // Prove the checked-in bytes come from the exact encoder configuration
    // published by 0.2.0, rather than merely being an arbitrary WBITS=22
    // stream produced by another implementation.
    let mut legacy_output = Vec::new();
    let encoded = {
        let mut writer = brotli::CompressorWriter::new(&mut legacy_output, 4_096, 11, 22);
        writer.write_all(EXPECTED)
    };
    assert!(encoded.is_ok());
    assert_eq!(legacy_output.as_slice(), V0_2_COMPATIBILITY_BLOB);

    let decoded = brotli_decompress_with_limit(V0_2_COMPATIBILITY_BLOB, 64);
    assert!(decoded.is_ok());
    if let Ok(decoded) = decoded {
        assert_eq!(decoded.as_slice(), EXPECTED);
    }
}
