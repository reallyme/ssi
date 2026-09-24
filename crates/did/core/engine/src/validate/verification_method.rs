// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_types::DIDDocument;

use reallyme_codec::multikey::parse_multikey;
use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::validate_verification_method_multikey;

use identity_core_primitives::algorithm_map::alg_str_to_alg;
use identity_core_primitives::Algorithm;

use crate::validate::diagnostic::{DidValidationCode, DidValidationIssue, DidValidationLocation};

/// Result of verification-method semantic validation.
#[derive(Debug, Clone)]
pub struct VerificationMethodValidationResult {
    /// Whether all verification methods are semantically valid.
    pub ok: bool,

    /// Machine-readable validation issues collected for callers and tests.
    pub errors: Vec<DidValidationIssue>,
}

const MAX_DIAGNOSTIC_INDEX: u32 = u32::MAX;

fn vm_issue(index: usize) -> DidValidationIssue {
    let index = match u32::try_from(index) {
        Ok(value) => value,
        Err(_) => MAX_DIAGNOSTIC_INDEX,
    };
    DidValidationIssue::indexed(
        DidValidationCode::VerificationMethodInvalid,
        DidValidationLocation::VerificationMethod,
        index,
    )
}

/// Semantic validation of DID verification methods.
///
/// Mirrors TS validateVerificationMethods exactly.
pub fn validate_verification_methods(doc: &DIDDocument) -> VerificationMethodValidationResult {
    let mut errors = Vec::new();
    let methods = &doc.verification_method;
    let did = &doc.id;

    // ----------------------------------------------------
    // 1. IDs must be unique
    // ----------------------------------------------------
    {
        let mut seen = std::collections::HashSet::new();
        for (index, vm) in methods.iter().enumerate() {
            if !seen.insert(&vm.id) {
                errors.push(vm_issue(index));
            }
        }
    }

    // ----------------------------------------------------
    // 2. controller MUST equal DID
    // ----------------------------------------------------
    for (index, vm) in methods.iter().enumerate() {
        if vm.controller != *did {
            errors.push(vm_issue(index));
        }
    }

    // ----------------------------------------------------
    // 3–5. Multikey decode + semantic validation
    // ----------------------------------------------------
    for (index, vm) in methods.iter().enumerate() {
        // ---- parse multikey ----
        let parsed = match parse_multikey(&vm.public_key_multibase) {
            Ok(p) => p,
            Err(_) => {
                errors.push(vm_issue(index));
                continue;
            }
        };

        // ---- algorithm string → semantic Algorithm ----
        let declared_alg = match vm.algorithm.as_deref() {
            Some(a) => a,
            None => {
                errors.push(vm_issue(index));
                continue;
            }
        };

        let sem_alg = match alg_str_to_alg(declared_alg) {
            Ok(a) => a,
            Err(_) => {
                errors.push(vm_issue(index));
                continue;
            }
        };

        // ---- semantic → crypto algorithm ----
        let crypto_alg = match sem_alg {
            Algorithm::Ed25519 => CryptoAlgorithm::Ed25519,
            Algorithm::Secp256k1 => CryptoAlgorithm::Secp256k1,
            Algorithm::P256 => CryptoAlgorithm::P256,
            Algorithm::MlDsa87 => CryptoAlgorithm::MlDsa87,
            Algorithm::X25519 => CryptoAlgorithm::X25519,
            Algorithm::MlKem768 => CryptoAlgorithm::MlKem768,
            Algorithm::MlKem1024 => CryptoAlgorithm::MlKem1024,
        };

        // ---- type ↔ codec validation ----
        if validate_verification_method_multikey(crypto_alg, &vm.vm_type, &vm.public_key_multibase)
            .is_err()
        {
            errors.push(vm_issue(index));
        }

        // ---- declared algorithm must match multikey-derived algorithm ----
        if declared_alg != parsed.alg {
            errors.push(vm_issue(index));
        }
    }

    VerificationMethodValidationResult {
        ok: errors.is_empty(),
        errors,
    }
}
