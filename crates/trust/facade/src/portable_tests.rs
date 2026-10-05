// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::rsa_modulus_bits;

#[test]
fn rsa_modulus_floor_uses_actual_significant_bit_length() {
    let mut modulus = vec![0xff; 256];
    *modulus.first_mut().expect("nonempty RSA fixture") = 0x7f;
    assert_eq!(rsa_modulus_bits(&modulus), Some(2_047));
    *modulus.first_mut().expect("nonempty RSA fixture") = 0x80;
    assert_eq!(rsa_modulus_bits(&modulus), Some(2_048));
    modulus.insert(0, 0);
    assert_eq!(rsa_modulus_bits(&modulus), Some(2_048));
    assert_eq!(rsa_modulus_bits(&[]), None);
    assert_eq!(rsa_modulus_bits(&[0, 0]), None);
}
