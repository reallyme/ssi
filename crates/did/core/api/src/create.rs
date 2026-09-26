// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use identity_core_primitives::algorithm_map::alg_str_to_alg;
use identity_core_primitives::algorithm_map::alg_to_did_alg_str;
use identity_core_primitives::Algorithm;

use reallyme_crypto::core::RngOutputKind;
use reallyme_crypto::csprng::{generate_bytes, OsSecureRandom};
use reallyme_did_types::{DIDDocument, VerificationMethod};

use crate::error::DidApiError;
use crate::profile::{build_profile, DidProfile};
use reallyme_keys::KeySet;

use reallyme_did_core::signing::is_attestation_algorithm;
use reallyme_did_core::{
    create_engine,
    keys::{generate_keypair_for_algorithm, public_key_to_multikey_for_algorithm},
    CoreVerificationMethod, CreateOptions, DidCoreError, UpdatePolicy as CoreUpdatePolicy,
};
use reallyme_did_method_me::{generate_did_me, GENESIS_NONCE_LEN};

/// Developer-facing CreateConfig (exact TS mirror)
pub struct CreateConfig {
    /// Optional ReallyMe policy preset used to populate keys and relationships.
    ///
    /// When both this field and `verification_methods` are absent, creation uses
    /// the did:me v1 default interoperability profile. Supplying
    /// `verification_methods` selects advanced manual configuration.
    pub profile: Option<DidProfile>,

    /// Additional identifiers to publish in `alsoKnownAs`.
    pub also_known_as: Option<Vec<String>>,

    /// Hardware binding metadata to publish in the DID document.
    pub hardware_bound: Option<bool>,

    /// Biometric protection metadata to publish in the DID document.
    pub biometric_protected: Option<bool>,

    /// User verification method metadata to publish in the DID document.
    pub user_verification_method: Option<String>,

    /// Device model metadata to publish in the DID document.
    pub device_model: Option<String>,

    /// Optional service endpoints for the generated document.
    pub services: Option<Vec<reallyme_did_core::ServiceInput>>,

    /// Optional update policy override.
    pub update_policy: Option<UpdatePolicyInput>,

    /// Optional domain verification claims.
    pub domain_verification: Option<Vec<reallyme_did_core::DomainVerificationInput>>,

    /// Manual VM definitions (ONLY when no profile)
    pub verification_methods: Option<Vec<(String, Algorithm)>>, // (id, algorithm)

    /// Manual authentication relationship references.
    pub authentication: Option<Vec<String>>,

    /// Manual assertion relationship references.
    pub assertion: Option<Vec<String>>,

    /// Manual capability invocation relationship references.
    pub invocation: Option<Vec<String>>,

    /// Manual key agreement relationship references.
    pub key_agreement: Option<Vec<String>>,

    /// Host-supplied RFC3339 timestamp for generated proofs.
    pub created: Option<String>,
}

/// Creation-time update policy input.
pub struct UpdatePolicyInput {
    /// Verification method references allowed to authorize updates.
    pub allowed_keys: Option<Vec<String>>,

    /// Optional update threshold.
    pub threshold: Option<u64>,
}

fn populate_genesis_nonce(opts: &mut CreateOptions) -> Result<(), DidApiError> {
    if opts.sequence == 1 && opts.nonce.is_none() {
        let mut rng = OsSecureRandom;
        let nonce = generate_bytes::<GENESIS_NONCE_LEN>(&mut rng, RngOutputKind::Generic)
            .map_err(|_| DidApiError::EngineFailure)?;
        opts.nonce = Some(nonce.into_bytes().to_vec());
    }
    Ok(())
}

fn derive_and_apply_genesis_identifier(opts: &mut CreateOptions) -> Result<(), DidApiError> {
    if opts.sequence != 1 {
        return Ok(());
    }

    let nonce = opts
        .nonce
        .as_deref()
        .ok_or(DidApiError::MissingGenesisNonce)?;

    let controller_keys = opts
        .controller_keys
        .iter()
        .map(|vm| {
            let alg_str = vm
                .algorithm
                .as_deref()
                .ok_or(DidApiError::MissingVerificationMethodAlgorithm)?;
            let alg = alg_str_to_alg(alg_str).map_err(|_| DidApiError::UnsupportedAlgorithm)?;

            Ok(CoreVerificationMethod {
                id: vm.id.clone(),
                vm_type: "Multikey".into(),
                algorithm: alg,
                public_key_multibase: vm.public_key_multibase.clone(),
            })
        })
        .collect::<Result<Vec<_>, DidApiError>>()?;

    let update_policy = CoreUpdatePolicy {
        allowed_verification_methods: opts.allowed_verification_methods.clone(),
        threshold: opts.threshold,
    };

    let did = generate_did_me(nonce, &update_policy, &controller_keys)
        .map_err(|_| DidApiError::EngineFailure)?;

    opts.id = did.clone();
    opts.controller = vec![did.clone()];
    for vm in &mut opts.controller_keys {
        vm.controller = did.clone();
    }

    Ok(())
}

/// Convert CreateConfig → CreateOptions and populate KeySet
pub fn build_create_options(
    cfg: CreateConfig,
    did: &str,
    ks: &mut KeySet,
) -> Result<CreateOptions, DidApiError> {
    let manual_configuration = cfg.profile.is_none()
        && (cfg.verification_methods.is_some()
            || cfg.authentication.is_some()
            || cfg.assertion.is_some()
            || cfg.invocation.is_some()
            || cfg.key_agreement.is_some()
            || cfg.update_policy.is_some());
    let selected_profile = if manual_configuration {
        None
    } else {
        Some(cfg.profile.unwrap_or(DidProfile::CoreIdentity))
    };

    // ------------------------------------------------------------
    // 1. Base CreateOptions
    // ------------------------------------------------------------
    let mut opts = if let Some(profile) = selected_profile {
        build_profile(profile, did)
    } else {
        CreateOptions {
            id: did.into(),
            controller: vec![did.into()],
            sequence: 1,
            prev: None,

            controller_keys: vec![],
            authentication: vec![],
            assertion: vec![],
            invocation: vec![],
            key_agreement: vec![],

            services: cfg.services.unwrap_or_default(),
            allowed_verification_methods: cfg
                .update_policy
                .as_ref()
                .and_then(|p| p.allowed_keys.clone())
                .unwrap_or_default(),
            threshold: cfg.update_policy.as_ref().and_then(|p| p.threshold),
            nonce: None,
            // Applied after profile/manual selection so callers receive the same
            // explicit domain-binding semantics in both creation modes.
            domain_verification: Vec::new(),

            also_known_as: cfg.also_known_as.unwrap_or_default(),
            hardware_bound: cfg.hardware_bound,
            biometric_protected: cfg.biometric_protected,
            user_verification_method: cfg.user_verification_method,
            device_model: cfg.device_model,

            created: None, // set below
        }
    };

    opts.domain_verification = cfg.domain_verification.unwrap_or_default();

    // APPLY host-supplied timestamp for BOTH profile + manual
    opts.created = cfg.created;

    // ------------------------------------------------------------
    // 1a. Manual-mode relationship propagation
    // ------------------------------------------------------------
    if manual_configuration {
        if let Some(v) = cfg.authentication {
            opts.authentication = v;
        }
        if let Some(v) = cfg.assertion {
            opts.assertion = v;
        }
        if let Some(v) = cfg.invocation {
            opts.invocation = v;
        }
        if let Some(v) = cfg.key_agreement {
            opts.key_agreement = v;
        }
    }

    // ------------------------------------------------------------
    // 2. PROFILE MODE — generate keys for all VMs
    // ------------------------------------------------------------
    if !opts.controller_keys.is_empty() {
        for vm in &mut opts.controller_keys {
            let alg_str = vm
                .algorithm
                .as_deref()
                .ok_or(DidApiError::MissingVerificationMethodAlgorithm)?;

            let alg = alg_str_to_alg(alg_str).map_err(|_| DidApiError::UnsupportedAlgorithm)?;

            vm.algorithm = Some(alg_to_did_alg_str(alg).to_string());

            let (public, secret) =
                generate_keypair_for_algorithm(alg).map_err(|_| DidApiError::EngineFailure)?;

            let multikey = public_key_to_multikey_for_algorithm(alg, &public)
                .map_err(|_| DidApiError::EngineFailure)?;

            ks.put_key_zeroizing(&vm.id, secret, multikey.clone())
                .map_err(|_| DidApiError::EngineFailure)?;
            vm.public_key_multibase = multikey;
        }

        populate_genesis_nonce(&mut opts)?;
        derive_and_apply_genesis_identifier(&mut opts)?;
        return Ok(opts);
    }

    // ------------------------------------------------------------
    // 3. MANUAL MODE (no profile)
    // ------------------------------------------------------------
    let vms = cfg
        .verification_methods
        .ok_or(DidApiError::MissingVerificationMethods)?;

    for (id, alg) in vms {
        let (public, secret) =
            generate_keypair_for_algorithm(alg).map_err(|_| DidApiError::EngineFailure)?;

        let multikey = public_key_to_multikey_for_algorithm(alg, &public)
            .map_err(|_| DidApiError::EngineFailure)?;

        ks.put_key_zeroizing(&id, secret, multikey.clone())
            .map_err(|_| DidApiError::EngineFailure)?;

        opts.controller_keys.push(VerificationMethod {
            id,
            vm_type: "Multikey".into(),
            controller: did.into(),
            algorithm: Some(alg_to_did_alg_str(alg).to_string()),
            public_key_multibase: multikey,
        });
    }

    // Manual mode: if caller didn’t provide update_policy.allowed, default to
    // every verification method that can sign core attestations. Key-agreement
    // and P-256 keys can never satisfy an update policy.
    if opts.allowed_verification_methods.is_empty() {
        opts.allowed_verification_methods = opts
            .controller_keys
            .iter()
            .filter(|vm| {
                vm.algorithm
                    .as_deref()
                    .and_then(|alg| alg_str_to_alg(alg).ok())
                    .is_some_and(is_attestation_algorithm)
            })
            .map(|vm| vm.id.clone())
            .collect();
    }

    populate_genesis_nonce(&mut opts)?;
    derive_and_apply_genesis_identifier(&mut opts)?;

    Ok(opts)
}

/// High-level createDid API (clean Rust version)
pub fn create_did(cfg: CreateConfig, did: &str) -> Result<(DIDDocument, KeySet), DidApiError> {
    if !did.starts_with("did:me:") {
        return Err(DidApiError::UnsupportedDidMethod);
    }

    let mut ks = KeySet::new();

    let opts = build_create_options(cfg, did, &mut ks)?;

    // Find the private keys in the keyset
    let res = create_engine(&opts, |id| {
        let key_id = id
            .rsplit('#')
            .next()
            .map(|f| format!("#{}", f))
            .unwrap_or_else(|| id.to_string());
        ks.get_private(&key_id)
            .ok()
            .and_then(|key| (!key.is_empty()).then_some(key.to_vec()))
    })
    .map_err(|err| match err {
        DidCoreError::PolicyViolation => DidApiError::PolicyViolation,
        _ => DidApiError::EngineFailure,
    })?;

    Ok((res.document, ks))
}
