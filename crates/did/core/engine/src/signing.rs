// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::attestation::CoreAttestation;
use crate::canonical::Canonical;
use crate::core::{CoreVerificationMethod, DidCore};
use crate::error::DidCoreError;
use crate::identifier::core_signature_input;

use identity_core_primitives::algorithm_map::alg_to_did_alg_str;
use identity_core_primitives::Algorithm as IdentityAlgorithm;
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::sign;
use zeroize::Zeroizing;

/// Map an identity-level algorithm to the crypto algorithm used for core attestations.
///
/// Returns `None` for algorithms that are not core attestation algorithms. The
/// set must stay identical to the attestation verifier in
/// `validate::attestation`: P-256 is used for ES256 Data Integrity proofs and
/// relationship keys, but it is not a did:me update-authority algorithm.
pub(crate) fn attestation_crypto_algorithm(alg: IdentityAlgorithm) -> Option<CryptoAlgorithm> {
    match alg {
        IdentityAlgorithm::Ed25519 => Some(CryptoAlgorithm::Ed25519),
        IdentityAlgorithm::Secp256k1 => Some(CryptoAlgorithm::Secp256k1),
        IdentityAlgorithm::MlDsa87 => Some(CryptoAlgorithm::MlDsa87),

        // Not core attestation algorithms
        IdentityAlgorithm::P256 => None,
        IdentityAlgorithm::X25519 => None,
        IdentityAlgorithm::MlKem768 => None,
        IdentityAlgorithm::MlKem1024 => None,
    }
}

/// Return true when `alg` may authorize did:me core updates (sign attestations).
#[must_use]
pub fn is_attestation_algorithm(alg: IdentityAlgorithm) -> bool {
    attestation_crypto_algorithm(alg).is_some()
}

/// Produce core attestations over the canonical DID core.
///
/// - Enforces updatePolicy.allowed
/// - Enforces signing algorithm eligibility
/// - Uses the `reallyme-crypto` dispatch facade
pub fn sign_core(
    core: &DidCore,
    controller_keys: &[CoreVerificationMethod],
    allowed: &[String],
    key_lookup: impl Fn(&str) -> Option<Vec<u8>>,
) -> Result<Vec<CoreAttestation>, DidCoreError> {
    sign_core_with_policy(
        core,
        controller_keys,
        allowed,
        core.update_policy.threshold,
        key_lookup,
    )
}

/// Produce attestations over `core`, authorized by an explicit update policy.
///
/// Genesis signing uses the core's own policy. Updates are different: the new
/// core bytes are signed, but the previous active policy authorizes the
/// transition. Keeping the policy explicit prevents accidental validation
/// against the newly proposed policy during policy rotation.
pub fn sign_core_with_policy(
    core: &DidCore,
    controller_keys: &[CoreVerificationMethod],
    allowed: &[String],
    threshold: Option<u64>,
    key_lookup: impl Fn(&str) -> Option<Vec<u8>>,
) -> Result<Vec<CoreAttestation>, DidCoreError> {
    let threshold = threshold.unwrap_or(1);
    let threshold_usize = usize::try_from(threshold).map_err(|_| DidCoreError::PolicyViolation)?;

    if threshold_usize == 0 || threshold_usize > allowed.len() {
        return Err(DidCoreError::PolicyViolation);
    }

    // Every allowed reference must name a controller key with an attestation
    // algorithm; otherwise the policy could never be verified.
    for id in allowed {
        match controller_keys.iter().find(|vm| &vm.id == id) {
            Some(vm) if attestation_crypto_algorithm(vm.algorithm).is_some() => {}
            _ => return Err(DidCoreError::PolicyViolation),
        }
    }

    let bytes = core.canonical_cbor()?;
    let signing_input = core_signature_input(&bytes)?;
    let mut out = Vec::new();

    for vm in controller_keys {
        // 1. Must be allowed by update policy
        if !allowed.contains(&vm.id) {
            continue;
        }

        // 2. Identity algorithm is already typed
        let identity_alg = vm.algorithm;

        // 3. Map to crypto algorithm (rejected above for allowed keys)
        let crypto_alg = match attestation_crypto_algorithm(identity_alg) {
            Some(a) => a,
            None => return Err(DidCoreError::PolicyViolation),
        };

        // 4. Lookup private key; the engine-owned copy is cleared on drop.
        let Some(secret) = key_lookup(&vm.id).map(Zeroizing::new) else {
            continue;
        };

        // 5. Sign canonical core
        let sig = sign(crypto_alg, &secret, &signing_input)
            .map_err(|_| DidCoreError::InternalInvariant)?;

        // 6. Emit attestation
        out.push(CoreAttestation {
            algorithm: alg_to_did_alg_str(identity_alg).to_string(),
            verification_method: vm.id.clone(),
            signature: bytes_to_base64url(&sig),
        });
    }

    // The generated attestations must satisfy the authorizing policy threshold.
    if out.len() < threshold_usize {
        return Err(DidCoreError::PolicyViolation);
    }

    Ok(out)
}
