// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::normalize_precomputed_p256_signature;
use reallyme_crypto::p256::p256_ecdsa_jose_signature_to_der;

const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

#[test]
// Fixed test vectors make these two conversions provable preconditions.
#[allow(clippy::expect_used)]
fn precomputed_signer_normalizes_high_s_from_raw_and_der() {
    let mut high_s = [0_u8; 64];
    high_s[31] = 1;
    high_s[32..].copy_from_slice(&P256_ORDER);
    high_s[63] = high_s[63]
        .checked_sub(1)
        .expect("P-256 order ends above zero");
    let mut expected = [0_u8; 64];
    expected[31] = 1;
    expected[63] = 1;

    assert_eq!(
        normalize_precomputed_p256_signature(&high_s),
        Ok(expected.to_vec())
    );
    let der =
        p256_ecdsa_jose_signature_to_der(&high_s).expect("test signature has two in-range scalars");
    assert_eq!(
        normalize_precomputed_p256_signature(&der),
        Ok(expected.to_vec())
    );

    high_s[32..].fill(0);
    assert!(normalize_precomputed_p256_signature(&high_s).is_err());
}
