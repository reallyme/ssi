// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::create::CreateOptions;
use identity_core_primitives::algorithm_map::alg_to_did_alg_str;
use identity_core_primitives::Algorithm;
use reallyme_did_types::VerificationMethod;

/// DID profile identifiers for built-in did:me document templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidProfile {
    /// Full identity profile with classical, post-quantum, and key-agreement methods.
    CoreIdentity,

    /// Public profile with authentication, assertion, invocation, and agreement methods.
    PublicProfile,

    /// Public profile extended with issuer-oriented assertion capabilities.
    PublicProfileIssuer,

    /// Issuer profile for credential issuance and update-policy authorization.
    Issuer,

    /// Messaging profile with authentication and key-agreement methods.
    Messaging,

    /// Payment profile using a secp256k1 verification method.
    Payment,
}

/// Helper to construct VerificationMethod templates.
/// `public_key_multibase` is left empty and populated by the API layer.
///
/// NOTE:
/// - This is a *document-layer* type
/// - Algorithms must remain strings here
fn vm(id: &str, did: &str, alg: Algorithm) -> VerificationMethod {
    VerificationMethod {
        id: id.into(),
        controller: did.into(),
        vm_type: "Multikey".into(),
        algorithm: Some(alg_to_did_alg_str(alg).to_string()),
        public_key_multibase: String::new(),
    }
}

/// Build a DID profile → partial CreateOptions.
///
/// This is a **direct semantic port** of the TS `buildProfile(profile, did)`
/// with **Algorithm enums as the source of truth**.
///
/// IMPORTANT INVARIANT:
/// - All *engine* semantics use `Algorithm` enums
/// - Strings appear ONLY in document-layer structs
pub fn build_profile(profile: DidProfile, did: &str) -> CreateOptions {
    match profile {
        // -----------------------------------------------------------
        // 1. CORE IDENTITY
        // -----------------------------------------------------------
        DidProfile::CoreIdentity => CreateOptions {
            id: did.into(),
            controller: vec![did.into()],
            sequence: 1,
            prev: None,
            nonce: None,

            controller_keys: vec![
                vm("#mldsa87-root", did, Algorithm::MlDsa87),
                vm("#mldsa87-auth", did, Algorithm::MlDsa87),
                vm("#ed25519", did, Algorithm::Ed25519),
                vm("#p256", did, Algorithm::P256),
                vm("#x25519", did, Algorithm::X25519),
                vm("#mlkem768", did, Algorithm::MlKem768),
                vm("#mlkem1024", did, Algorithm::MlKem1024),
            ],

            authentication: vec!["#ed25519".into(), "#mldsa87-auth".into(), "#p256".into()],
            assertion: vec!["#ed25519".into(), "#p256".into(), "#mldsa87-auth".into()],
            invocation: vec!["#mldsa87-root".into(), "#ed25519".into()],
            key_agreement: vec!["#x25519".into(), "#mlkem768".into(), "#mlkem1024".into()],

            allowed_verification_methods: vec!["#mldsa87-root".into(), "#ed25519".into()],
            threshold: Some(2),

            services: vec![],
            domain_verification: vec![],

            also_known_as: vec![],
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            created: None,
        },

        // -----------------------------------------------------------
        // 2. PUBLIC PROFILE
        // -----------------------------------------------------------
        DidProfile::PublicProfile => CreateOptions {
            id: did.into(),
            controller: vec![did.into()],
            sequence: 1,
            prev: None,
            nonce: None,

            controller_keys: vec![
                vm("#mldsa87-root", did, Algorithm::MlDsa87),
                vm("#ed25519", did, Algorithm::Ed25519),
                vm("#p256", did, Algorithm::P256),
                vm("#x25519", did, Algorithm::X25519),
                vm("#mlkem768", did, Algorithm::MlKem768),
                vm("#mlkem1024", did, Algorithm::MlKem1024),
            ],

            authentication: vec!["#ed25519".into(), "#p256".into()],
            assertion: vec!["#ed25519".into(), "#p256".into()],
            invocation: vec!["#mldsa87-root".into(), "#ed25519".into()],
            key_agreement: vec!["#x25519".into(), "#mlkem768".into(), "#mlkem1024".into()],

            allowed_verification_methods: vec!["#mldsa87-root".into()],
            threshold: None,

            services: vec![],
            domain_verification: vec![],

            also_known_as: vec![],
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            created: None,
        },

        // -----------------------------------------------------------
        // 3. PUBLIC PROFILE + ISSUER
        // -----------------------------------------------------------
        DidProfile::PublicProfileIssuer => CreateOptions {
            id: did.into(),
            controller: vec![did.into()],
            sequence: 1,
            prev: None,
            nonce: None,

            controller_keys: vec![
                vm("#mldsa87-root", did, Algorithm::MlDsa87),
                vm("#mldsa87-auth", did, Algorithm::MlDsa87),
                vm("#ed25519", did, Algorithm::Ed25519),
                vm("#p256", did, Algorithm::P256),
                vm("#x25519", did, Algorithm::X25519),
                vm("#mlkem768", did, Algorithm::MlKem768),
                vm("#mlkem1024", did, Algorithm::MlKem1024),
            ],

            authentication: vec!["#ed25519".into(), "#mldsa87-auth".into(), "#p256".into()],
            assertion: vec!["#ed25519".into(), "#p256".into(), "#mldsa87-auth".into()],
            invocation: vec!["#mldsa87-root".into(), "#ed25519".into()],
            key_agreement: vec!["#x25519".into(), "#mlkem768".into(), "#mlkem1024".into()],

            allowed_verification_methods: vec!["#mldsa87-root".into(), "#ed25519".into()],
            threshold: Some(2),

            services: vec![],
            domain_verification: vec![],

            also_known_as: vec![],
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            created: None,
        },

        // -----------------------------------------------------------
        // 4. ISSUER
        // -----------------------------------------------------------
        DidProfile::Issuer => CreateOptions {
            id: did.into(),
            controller: vec![did.into()],
            sequence: 1,
            prev: None,
            nonce: None,

            controller_keys: vec![
                vm("#mldsa87-root", did, Algorithm::MlDsa87),
                vm("#mldsa87-auth", did, Algorithm::MlDsa87),
                vm("#ed25519", did, Algorithm::Ed25519),
                vm("#p256", did, Algorithm::P256),
            ],

            authentication: vec!["#ed25519".into(), "#mldsa87-auth".into(), "#p256".into()],
            assertion: vec!["#ed25519".into(), "#p256".into(), "#mldsa87-auth".into()],
            invocation: vec!["#mldsa87-root".into()],
            key_agreement: vec![],

            allowed_verification_methods: vec!["#mldsa87-root".into(), "#ed25519".into()],
            threshold: Some(2),

            services: vec![],
            domain_verification: vec![],

            also_known_as: vec![],
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            created: None,
        },

        // -----------------------------------------------------------
        // 5. MESSAGING
        // -----------------------------------------------------------
        DidProfile::Messaging => CreateOptions {
            id: did.into(),
            controller: vec![did.into()],
            sequence: 1,
            prev: None,
            nonce: None,

            controller_keys: vec![
                vm("#ed25519", did, Algorithm::Ed25519),
                vm("#x25519", did, Algorithm::X25519),
                vm("#mlkem768", did, Algorithm::MlKem768),
                vm("#mlkem1024", did, Algorithm::MlKem1024),
            ],

            authentication: vec!["#ed25519".into()],
            assertion: vec![],
            invocation: vec!["#ed25519".into()],
            key_agreement: vec!["#x25519".into(), "#mlkem768".into(), "#mlkem1024".into()],

            allowed_verification_methods: vec!["#ed25519".into()],
            threshold: None,

            services: vec![],
            domain_verification: vec![],

            also_known_as: vec![],
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            created: None,
        },

        // -----------------------------------------------------------
        // 6. PAYMENT
        // -----------------------------------------------------------
        DidProfile::Payment => CreateOptions {
            id: did.into(),
            controller: vec![did.into()],
            sequence: 1,
            prev: None,
            nonce: None,

            controller_keys: vec![vm("#k1", did, Algorithm::Secp256k1)],

            authentication: vec!["#k1".into()],
            assertion: vec![],
            invocation: vec!["#k1".into()],
            key_agreement: vec![],

            allowed_verification_methods: vec!["#k1".into()],
            threshold: None,

            services: vec![],
            domain_verification: vec![],

            also_known_as: vec![],
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            created: None,
        },
    }
}
