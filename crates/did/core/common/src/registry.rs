// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::algorithm::Algorithm;

/// The cryptographic role of a key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// Key is used to produce signatures.
    Signing,

    /// Key is used for agreement or ECDH-style derivation.
    KeyAgreement,

    /// Key is used as a key encapsulation mechanism public key.
    Kem,
}

/// Canonical specification for an algorithm in the identity system
pub struct AlgorithmSpec {
    /// Semantic algorithm
    pub alg: Algorithm,

    /// Multicodec name (used by codec-multicodec / multikey)
    pub multicodec_name: &'static str,

    /// Expected raw public key length
    pub public_key_len: usize,

    /// Key role
    pub role: KeyRole,

    /// JOSE `alg` (if applicable)
    pub jose_alg: Option<&'static str>,

    /// COSE `alg` (if applicable)
    pub cose_alg: Option<i32>,

    /// EU / W3C profile type (if applicable)
    pub profile_type: Option<&'static str>,
}

/// Canonical algorithm registry.
///
/// This is the *only* authoritative table describing
/// algorithm semantics in the system.
pub static ALGORITHM_REGISTRY: &[AlgorithmSpec] = &[
    AlgorithmSpec {
        alg: Algorithm::Ed25519,
        multicodec_name: "ed25519-pub",
        public_key_len: 32,
        role: KeyRole::Signing,
        jose_alg: Some("EdDSA"),
        cose_alg: Some(-8),
        profile_type: None,
    },
    AlgorithmSpec {
        alg: Algorithm::X25519,
        multicodec_name: "x25519-pub",
        public_key_len: 32,
        role: KeyRole::KeyAgreement,
        jose_alg: None,
        cose_alg: None,
        profile_type: None,
    },
    AlgorithmSpec {
        alg: Algorithm::P256,
        multicodec_name: "p256-pub",
        public_key_len: 33,
        role: KeyRole::Signing,
        jose_alg: Some("ES256"),
        cose_alg: Some(-7),
        profile_type: Some("P256Key2024"),
    },
    AlgorithmSpec {
        alg: Algorithm::Secp256k1,
        multicodec_name: "secp256k1-pub",
        public_key_len: 33,
        role: KeyRole::Signing,
        jose_alg: Some("ES256K"),
        cose_alg: None,
        profile_type: None,
    },
    AlgorithmSpec {
        alg: Algorithm::MlDsa87,
        multicodec_name: "mldsa-87-pub",
        public_key_len: 2592,
        role: KeyRole::Signing,
        jose_alg: None,
        cose_alg: None,
        profile_type: Some("MLDSA87Key2024"),
    },
    AlgorithmSpec {
        alg: Algorithm::MlKem768,
        multicodec_name: "mlkem-768-pub",
        public_key_len: 1184,
        role: KeyRole::Kem,
        jose_alg: None,
        cose_alg: None,
        profile_type: Some("MLKEM768Key2024"),
    },
    AlgorithmSpec {
        alg: Algorithm::MlKem1024,
        multicodec_name: "mlkem-1024-pub",
        public_key_len: 1568,
        role: KeyRole::Kem,
        jose_alg: None,
        cose_alg: None,
        profile_type: Some("MLKEM1024Key2024"),
    },
];

/// Lookup by semantic algorithm
pub fn lookup_by_algorithm(alg: Algorithm) -> Option<&'static AlgorithmSpec> {
    ALGORITHM_REGISTRY.iter().find(|s| s.alg == alg)
}

/// Lookup by multicodec name
pub fn lookup_by_multicodec_name(name: &str) -> Option<&'static AlgorithmSpec> {
    ALGORITHM_REGISTRY
        .iter()
        .find(|s| s.multicodec_name == name)
}

/// Lookup by profile type
pub fn lookup_by_profile_type(profile: &str) -> Option<&'static AlgorithmSpec> {
    ALGORITHM_REGISTRY
        .iter()
        .find(|s| s.profile_type == Some(profile))
}
