// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use std::collections::{HashMap, HashSet};

use crate::identifier::core_signature_input;
use crate::signing::attestation_crypto_algorithm;
use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_codec::multikey::parse_multikey;
use reallyme_crypto::dispatch::verify;
use reallyme_did_types::{Attestation, UpdatePolicy, VerificationMethod};

use identity_core_primitives::algorithm_map::alg_str_to_alg;

use crate::validate::diagnostic::{DidValidationCode, DidValidationIssue, DidValidationLocation};
use crate::validate::limits::{
    MAX_ATTESTATIONS, MAX_RELATIONSHIP_REFERENCES, MAX_VERIFICATION_METHODS,
};

/// Result of cryptographic attestation validation.
#[derive(Debug)]
pub struct AttestationValidationResult {
    /// Whether all attestations validated successfully.
    pub ok: bool,

    /// Machine-readable validation issues collected for callers and tests.
    pub errors: Vec<DidValidationIssue>,
}

/// Result of update-policy attestation authorization validation.
#[derive(Debug)]
pub struct AttestationPolicyValidationResult {
    /// Whether attestations satisfy the configured update policy.
    pub ok: bool,

    /// Machine-readable validation issues collected for callers and tests.
    pub errors: Vec<DidValidationIssue>,
}

const MAX_DIAGNOSTIC_INDEX: u32 = u32::MAX;

fn indexed_issue(code: DidValidationCode, index: usize) -> DidValidationIssue {
    let index = match u32::try_from(index) {
        Ok(value) => value,
        Err(_) => MAX_DIAGNOSTIC_INDEX,
    };
    DidValidationIssue::indexed(code, DidValidationLocation::Attestation, index)
}

fn attestation_issue(index: usize) -> DidValidationIssue {
    indexed_issue(DidValidationCode::AttestationInvalid, index)
}

fn signature_issue(index: usize) -> DidValidationIssue {
    indexed_issue(DidValidationCode::AttestationSignatureInvalid, index)
}

fn policy_issue() -> DidValidationIssue {
    DidValidationIssue::new(
        DidValidationCode::AttestationPolicyNotSatisfied,
        DidValidationLocation::Attestation,
    )
}

/// Validate that core attestations satisfy updatePolicy.allowedVerificationMethods
/// and updatePolicy.threshold. Signature validity is checked separately by
/// `validate_attestations`; this policy check keeps control-plane authorization
/// explicit and auditable.
pub fn validate_attestation_policy(
    update_policy: &UpdatePolicy,
    attestations: &[Attestation],
) -> AttestationPolicyValidationResult {
    let mut errors = Vec::new();

    if attestations.len() > MAX_ATTESTATIONS
        || update_policy.allowed_verification_methods.len() > MAX_RELATIONSHIP_REFERENCES
    {
        return AttestationPolicyValidationResult {
            ok: false,
            errors: vec![DidValidationIssue::new(
                DidValidationCode::ResourceLimitExceeded,
                DidValidationLocation::Attestation,
            )],
        };
    }

    let threshold = update_policy.threshold.unwrap_or(1);
    let threshold_usize = match usize::try_from(threshold) {
        Ok(v) => v,
        Err(_) => {
            return AttestationPolicyValidationResult {
                ok: false,
                errors: vec![policy_issue()],
            };
        }
    };

    if threshold_usize == 0 || threshold_usize > update_policy.allowed_verification_methods.len() {
        errors.push(policy_issue());
    }

    let allowed: HashSet<&str> = update_policy
        .allowed_verification_methods
        .iter()
        .map(String::as_str)
        .collect();
    let mut satisfied: HashSet<&str> = HashSet::new();

    for (index, att) in attestations.iter().enumerate() {
        if allowed.contains(att.vm.as_str()) {
            // A signer may attest at most once; repeated entries never count twice.
            if !satisfied.insert(att.vm.as_str()) {
                errors.push(indexed_issue(
                    DidValidationCode::AttestationPolicyNotSatisfied,
                    index,
                ));
            }
        } else {
            errors.push(indexed_issue(
                DidValidationCode::AttestationPolicyNotSatisfied,
                index,
            ));
        }
    }

    if threshold_usize > 0 && satisfied.len() < threshold_usize {
        errors.push(policy_issue());
    }

    AttestationPolicyValidationResult {
        ok: errors.is_empty(),
        errors,
    }
}

/// Validate ALL attestations inside a DID Document.
///
/// `verification_methods` must be the controller keys committed in a signed
/// canonical core (the document's own genesis core, or the previous core for an
/// update), never the unsigned JSON `verificationMethod` projection. The
/// full-document validators decode them from core bytes before calling this.
pub fn validate_attestations(
    verification_methods: &[VerificationMethod],
    attestations: &[Attestation],
    core_cbor_b64url: &str,
) -> AttestationValidationResult {
    let mut errors = Vec::new();

    // Decode core CBOR bytes
    let core_bytes = match base64url_to_bytes(core_cbor_b64url) {
        Ok(b) => b,
        Err(_) => {
            return AttestationValidationResult {
                ok: false,
                errors: vec![DidValidationIssue::new(
                    DidValidationCode::CoreCborEncodingInvalid,
                    DidValidationLocation::Core,
                )],
            };
        }
    };

    if attestations.len() > MAX_ATTESTATIONS
        || verification_methods.len() > MAX_VERIFICATION_METHODS
    {
        return AttestationValidationResult {
            ok: false,
            errors: vec![DidValidationIssue::new(
                DidValidationCode::ResourceLimitExceeded,
                DidValidationLocation::Attestation,
            )],
        };
    }

    let signing_input = match core_signature_input(&core_bytes) {
        Ok(input) => input,
        Err(_) => {
            return AttestationValidationResult {
                ok: false,
                errors: vec![DidValidationIssue::new(
                    DidValidationCode::ResourceLimitExceeded,
                    DidValidationLocation::Core,
                )],
            };
        }
    };

    let vm_by_id: HashMap<&str, &VerificationMethod> = verification_methods
        .iter()
        .map(|vm| (vm.id.as_str(), vm))
        .collect();

    for (index, att) in attestations.iter().enumerate() {
        // ----------------------------------------------------
        // 1. Locate verification method
        // ----------------------------------------------------
        let vm = match vm_by_id.get(att.vm.as_str()).copied() {
            Some(v) => v,
            None => {
                errors.push(attestation_issue(index));
                continue;
            }
        };

        // ----------------------------------------------------
        // 2. Algorithm agreement (string-level)
        // ----------------------------------------------------
        let vm_alg_str = match vm.algorithm.as_deref() {
            Some(a) => a,
            None => {
                errors.push(attestation_issue(index));
                continue;
            }
        };

        let att_alg_str = &att.alg;

        let vm_alg = match alg_str_to_alg(vm_alg_str) {
            Ok(a) => a,
            Err(_) => {
                errors.push(attestation_issue(index));
                continue;
            }
        };

        let att_alg = match alg_str_to_alg(att_alg_str) {
            Ok(a) => a,
            Err(_) => {
                errors.push(attestation_issue(index));
                continue;
            }
        };

        if vm_alg != att_alg {
            errors.push(attestation_issue(index));
            continue;
        }

        // ----------------------------------------------------
        // 3. Decode signature
        // ----------------------------------------------------
        let sig_bytes = match base64url_to_bytes(&att.sig) {
            Ok(b) => b,
            Err(_) => {
                errors.push(attestation_issue(index));
                continue;
            }
        };

        // ----------------------------------------------------
        // 4. Parse multikey → raw public key
        // ----------------------------------------------------
        let parsed = match parse_multikey(&vm.public_key_multibase) {
            Ok(p) => p,
            Err(_) => {
                errors.push(attestation_issue(index));
                continue;
            }
        };

        // ----------------------------------------------------
        // 5. Parse algorithm string → semantic Algorithm
        // ----------------------------------------------------
        let sem_alg = match alg_str_to_alg(vm_alg_str) {
            Ok(a) => a,
            Err(_) => {
                errors.push(attestation_issue(index));
                continue;
            }
        };

        // ----------------------------------------------------
        // 6. Map semantic Algorithm → reallyme_crypto::core::Algorithm
        // ----------------------------------------------------
        let crypto_alg = match attestation_crypto_algorithm(sem_alg) {
            Some(alg) => alg,
            None => {
                errors.push(attestation_issue(index));
                continue;
            }
        };

        // ----------------------------------------------------
        // 7. Verify signature
        // ----------------------------------------------------
        let ok = verify(crypto_alg, &parsed.public_key, &signing_input, &sig_bytes).is_ok();

        if !ok {
            errors.push(signature_issue(index));
        }
    }

    AttestationValidationResult {
        ok: errors.is_empty(),
        errors,
    }
}
