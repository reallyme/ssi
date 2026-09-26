// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Step 6: create engine (Rust).
///
/// - validate inputs
/// - autopopulate domain verification bindings
/// - build DidCore
/// - canonical CBOR
/// - CID
/// - core attestations
/// - DIDDocument projection
///
/// `key_lookup` provides the private key bytes for a given verification method id (e.g. "#ed25519").
pub fn create_engine(
    opts: &CreateOptions,
    key_lookup: impl Fn(&str) -> Option<Vec<u8>>,
) -> Result<CreateResult, DidCoreError> {
    // 0. Basic preconditions
    if opts.id.is_empty()
        || opts.controller.is_empty()
        || opts.controller[0].is_empty()
        || opts.sequence < 1
        || (opts.sequence == 1
            && (opts.prev.is_some() || opts.nonce.as_ref().map(|n| n.len()) != Some(16)))
        || (opts.sequence > 1 && (opts.prev.is_none() || opts.nonce.is_some()))
    {
        return Err(DidCoreError::InvalidCanonicalState(
            CanonicalStateViolation::InvalidCreatePreconditions,
        ));
    }

    // 1. Domain verification auto-population
    let domain_verification = autopopulate_domain_verification(opts)?;

    // 2. Core controller keys (strip controller field, force type "Multikey")
    let core_controller_keys: Vec<CoreVerificationMethod> = opts
        .controller_keys
        .iter()
        .map(|vm| {
            let alg_str = vm
                .algorithm
                .as_deref()
                .ok_or(DidCoreError::InvalidCanonicalState(
                    CanonicalStateViolation::MissingVerificationMethodAlgorithm,
                ))?;

            let alg = match alg_str {
                // Proof encoding → semantic key algorithm
                "ES256" => Algorithm::P256,

                // Common P-256 aliases (input convenience).
                "P-256" | "P256" | "p256" => Algorithm::P256,

                // Semantic algorithms (must match identity_core_primitives::Algorithm::from_str)
                other => Algorithm::from_str(other).map_err(|_| {
                    DidCoreError::InvalidCanonicalState(
                        CanonicalStateViolation::UnsupportedVerificationMethodAlgorithm,
                    )
                })?,
            };

            Ok(CoreVerificationMethod {
                id: vm.id.clone(),
                vm_type: "Multikey".into(),
                algorithm: alg,
                public_key_multibase: vm.public_key_multibase.clone(),
            })
        })
        .collect::<Result<Vec<_>, DidCoreError>>()?;

    // ------------------------------------------------------------
    // 2a. Relationship validation (spec-enforced)
    // ------------------------------------------------------------

    fn vm_exists(id: &str, vms: &[CoreVerificationMethod]) -> bool {
        vms.iter().any(|vm| vm.id == id)
    }

    // authentication: Ed25519 | ML-DSA-87 | P-256
    for k in &opts.authentication {
        if !vm_exists(k, &core_controller_keys) {
            return Err(DidCoreError::InvalidCanonicalState(
                CanonicalStateViolation::MissingAuthenticationMethod,
            ));
        }

        match vm_algorithm(k, &core_controller_keys) {
            Some(Algorithm::Ed25519 | Algorithm::MlDsa87 | Algorithm::P256) => {}
            _ => {
                return Err(DidCoreError::InvalidCanonicalState(
                    CanonicalStateViolation::InvalidAuthenticationAlgorithm,
                ))
            }
        }
    }

    // assertion: Ed25519 | ML-DSA-87 | P-256
    for k in &opts.assertion {
        if !vm_exists(k, &core_controller_keys) {
            return Err(DidCoreError::InvalidCanonicalState(
                CanonicalStateViolation::MissingAssertionMethod,
            ));
        }

        match vm_algorithm(k, &core_controller_keys) {
            Some(Algorithm::Ed25519 | Algorithm::MlDsa87 | Algorithm::P256) => {}
            _ => {
                return Err(DidCoreError::InvalidCanonicalState(
                    CanonicalStateViolation::InvalidAssertionAlgorithm,
                ))
            }
        }
    }

    // keyAgreement: X25519 | ML-KEM-768 | ML-KEM-1024
    for k in &opts.key_agreement {
        if !vm_exists(k, &core_controller_keys) {
            return Err(DidCoreError::InvalidCanonicalState(
                CanonicalStateViolation::MissingKeyAgreementMethod,
            ));
        }

        match vm_algorithm(k, &core_controller_keys) {
            Some(Algorithm::X25519 | Algorithm::MlKem768 | Algorithm::MlKem1024) => {}
            _ => {
                return Err(DidCoreError::InvalidCanonicalState(
                    CanonicalStateViolation::InvalidKeyAgreementAlgorithm,
                ))
            }
        }
    }

    // Invocation is projected from updatePolicy. Validate any caller-supplied
    // relationship references anyway so contradictory input cannot be hidden
    // by that projection.
    for k in &opts.invocation {
        if !vm_exists(k, &core_controller_keys) {
            return Err(DidCoreError::InvalidCanonicalState(
                CanonicalStateViolation::MissingInvocationMethod,
            ));
        }
    }

    // 3. Core services (JSON -> canonical bytes)
    let core_services = map_services(&opts.services)?;

    // 3a. For multiple controllers, sort them to ensure a canonical order
    let mut controllers = opts.controller.clone();
    controllers.sort();

    let mut core_controller_keys = core_controller_keys.clone();
    core_controller_keys.sort_by(|a, b| a.id.cmp(&b.id));

    // 4. Build DidCore
    let core = DidCore {
        id: opts.id.clone(),
        sequence: opts.sequence,
        controller: controllers,
        controller_keys: core_controller_keys.clone(),
        authentication: opts.authentication.clone(),
        assertion: opts.assertion.clone(),
        key_agreement: opts.key_agreement.clone(),
        services: core_services,
        nonce: opts.nonce.clone(),
        update_policy: CoreUpdatePolicy {
            allowed_verification_methods: opts.allowed_verification_methods.clone(),
            threshold: opts.threshold,
        },
        prev: opts.prev.clone(),
    };

    // 5. Canonical CBOR + CID
    let core_cbor = core.canonical_cbor()?;
    let core_cid = compute_core_cid(&core)?;

    // 6. Core attestations (Step 4)
    let core_attestations = sign_core(
        &core,
        &core_controller_keys,
        &opts.allowed_verification_methods,
        |id| key_lookup(id),
    )?;

    let attestations: Vec<JsonAttestation> = core_attestations
        .into_iter()
        .map(|a| JsonAttestation {
            alg: a.algorithm,
            vm: a.verification_method,
            sig: a.signature,
        })
        .collect();

    // Step 7: Optional ES256 DataIntegrityProof over CID
    let mut data_integrity_proof: Option<DataIntegrityProof> = None;

    // find first P-256 VM in assertion
    let p256_vmid = opts
        .controller_keys
        .iter()
        .find(|vm| {
            matches!(
                vm.algorithm.as_deref(),
                Some("P-256" | "P256" | "p256" | "ES256")
            ) && opts.assertion.contains(&vm.id)
        })
        .map(|vm| vm.id.clone());

    if let Some(vm_id) = p256_vmid {
        let created = opts
            .created
            .as_deref()
            .ok_or(DidCoreError::InvalidCanonicalState(
                CanonicalStateViolation::MissingProofCreated,
            ))?;

        if let Some(privkey) = key_lookup(&vm_id).map(zeroize::Zeroizing::new) {
            let proof =
                envelopes_data_integrity::suites::es256_jws_cid_2025::sign_es256_jws_cid_2025(
                    &core_cid, &privkey, &vm_id, created,
                )
                .map_err(|_| DidCoreError::InternalInvariant)?;

            data_integrity_proof = Some(proof);
        }
    }

    let verification_method =
        canonicalize_projection_verification_methods(&opts.controller_keys, &core_controller_keys)?;

    // 8. DIDDocument projection (Step 5)
    let doc = project_did_document(DocumentProjection {
        core: &core,
        core_cid: &core_cid,

        also_known_as: opts.also_known_as.clone(),
        hardware_bound: opts.hardware_bound,
        biometric_protected: opts.biometric_protected,
        user_verification_method: opts.user_verification_method.clone(),
        device_model: opts.device_model.clone(),

        key_history: vec![],
        verification_method,

        capability_invocation: opts.allowed_verification_methods.clone(),

        domain_verification,
        attestations,
        data_integrity_proof,
        eudi_level_of_assurance: None,
        eudi_schema_version: None,
    })?;

    Ok(CreateResult {
        document: doc,
        core_cbor,
        core_cid,
    })
}
