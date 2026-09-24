// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{alg_str_to_alg, vc_alg_str_to_alg};
use crate::Algorithm;

#[test]
fn vc_alg_str_to_alg_is_strict() {
    assert_eq!(vc_alg_str_to_alg("EdDSA"), Ok(Algorithm::Ed25519));
    assert!(vc_alg_str_to_alg("Ed25519").is_err());
}

#[test]
fn alg_str_to_alg_accepts_only_canonical_did_names() {
    assert_eq!(alg_str_to_alg("Ed25519"), Ok(Algorithm::Ed25519));
    assert!(alg_str_to_alg("EdDSA").is_err());
    assert!(alg_str_to_alg("ed25519").is_err());
    assert!(alg_str_to_alg("P256").is_err());
}
