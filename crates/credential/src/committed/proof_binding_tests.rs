// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::indexing_slicing)]

use super::p256_coordinates;
use crate::committed::error::VcError;
use crate::committed::model::{PublicKeyRepresentation, RawPublicKeySerialization};

#[test]
fn p256_raw_key_serialization_must_match_the_encoded_point() {
    let mut uncompressed = vec![0_u8; 65];
    uncompressed[0] = 0x04;
    let mut compressed = vec![0_u8; 33];
    compressed[0] = 0x02;

    for key in [
        PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::Sec1Compressed,
            bytes: uncompressed,
        },
        PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::Sec1Uncompressed,
            bytes: compressed,
        },
    ] {
        assert_eq!(p256_coordinates(&key), Err(VcError::InvalidCredential));
    }
}

#[test]
fn p256_uncompressed_key_must_be_a_real_curve_point() {
    let generator = [
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
        0x68, 0x37, 0xbf, 0x51, 0xf5,
    ];
    let valid = PublicKeyRepresentation::Raw {
        serialization: RawPublicKeySerialization::Sec1Uncompressed,
        bytes: generator.to_vec(),
    };
    assert!(p256_coordinates(&valid).is_ok());

    let mut invalid = generator;
    invalid[64] ^= 1;
    let invalid = PublicKeyRepresentation::Raw {
        serialization: RawPublicKeySerialization::Sec1Uncompressed,
        bytes: invalid.to_vec(),
    };
    assert_eq!(p256_coordinates(&invalid), Err(VcError::InvalidCredential));
}
