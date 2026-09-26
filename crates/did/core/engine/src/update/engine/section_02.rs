// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Update engine (TS parity).
///
/// `authorization_priv_lookup` returns previous active private key bytes for
/// authorizing the core transition under the old update policy.
/// `current_priv_lookup` returns private key bytes for updated-document
/// operations such as regenerated Data Integrity proofs.
/// `pub_lookup` returns the **rotated** publicKeyMultibase for a vm id (needed for rotation).
pub fn update_engine(
    opts: UpdateOptions,
    authorization_priv_lookup: impl Fn(&str) -> Option<Vec<u8>>,
    current_priv_lookup: impl Fn(&str) -> Option<Vec<u8>>,
    pub_lookup: impl Fn(&str) -> Option<String>,
) -> Result<DIDDocument, UpdateError> {
    let old = opts.old;

    // ----------------------------------------------------
    // 0. Basic checks (TS)
    // ----------------------------------------------------
    if opts.allowed.is_empty() && !opts.deactivate {
        return Err(UpdateError::PolicyViolation);
    }

    // ----------------------------------------------------
    // 1. Chain rules: sequence, prev, keyHistory
    // ----------------------------------------------------
    let next_seq = old
        .sequence
        .checked_add(1)
        .ok_or(UpdateError::InvalidSequence)?;
    let prev_cid = old.current_core.clone();

    validate_chain(
        old.sequence,
        next_seq,
        &old.current_core,
        Some(old.current_core.as_str()),
    )?;

    let mut new_history = old.key_history.clone();
    new_history.push(old.current_core.clone());

    // ----------------------------------------------------
    // 2. Rebuild verificationMethod array with rotated pubs
    // ----------------------------------------------------
    let new_controller_keys = if opts.deactivate {
        Vec::new()
    } else {
        apply_rotations(&old.verification_method, &opts.rotate, |id| pub_lookup(id))?
    };

    // ----------------------------------------------------
    // 3. Merge services + domain verification (TS semantics)
    // ----------------------------------------------------
    let merged_services = if opts.deactivate {
        Vec::new()
    } else {
        merge_services(&old.service, opts.services)
    };
    let merged_dv = merge_domain_verification(
        &old.id,
        &old.domain_verification,
        opts.domain_verification.as_deref(),
    )?;

    let core_services = canonicalize_services(&merged_services)?;

    // ----------------------------------------------------
    // 4. Build DidCore for updated state
    // ----------------------------------------------------

    // When multiple controllers, sort them for canonical stability
    let mut controller_vec = match &old.controller {
        reallyme_did_types::Controller::Single(d) => vec![d.clone()],
        reallyme_did_types::Controller::Multiple(v) => v.clone(),
    };

    controller_vec.sort();

    let old_update_policy = old
        .update_policy
        .as_ref()
        .ok_or(UpdateError::PolicyViolation)?;

    let mut previous_controller_keys = old
        .verification_method
        .iter()
        .map(|vm| {
            let alg_str = vm.algorithm.as_deref().ok_or(UpdateError::InvalidState)?;

            let alg = match alg_str {
                "ES256" => Algorithm::P256,
                other => Algorithm::from_str(other).map_err(|_| UpdateError::InvalidState)?,
            };

            Ok(CoreVerificationMethod {
                id: vm.id.clone(),
                vm_type: "Multikey".into(),
                algorithm: alg,
                public_key_multibase: vm.public_key_multibase.clone(),
            })
        })
        .collect::<Result<Vec<_>, UpdateError>>()?;
    previous_controller_keys.sort_by(|a, b| a.id.cmp(&b.id));

    let mut core_controller_keys = new_controller_keys
        .iter()
        .map(|vm| {
            let alg_str = vm.algorithm.as_deref().ok_or(UpdateError::InvalidState)?;

            let alg = match alg_str {
                "ES256" => Algorithm::P256, // proof encoding → semantic P-256
                other => Algorithm::from_str(other).map_err(|_| UpdateError::InvalidState)?,
            };

            Ok(CoreVerificationMethod {
                id: vm.id.clone(),
                vm_type: "Multikey".into(),
                algorithm: alg,
                public_key_multibase: vm.public_key_multibase.clone(),
            })
        })
        .collect::<Result<Vec<_>, UpdateError>>()?;

    // Canonical order is required so the updated core has a stable CID.
    core_controller_keys.sort_by(|a, b| a.id.cmp(&b.id));

    let projected_verification_methods =
        canonicalize_projected_verification_methods(&new_controller_keys, &core_controller_keys)?;

    let authentication = if opts.deactivate {
        Vec::new()
    } else {
        opts.relationships
            .authentication
            .unwrap_or_else(|| old.authentication.clone())
    };
    let assertion = if opts.deactivate {
        Vec::new()
    } else {
        opts.relationships
            .assertion
            .unwrap_or_else(|| old.assertion_method.clone())
    };
    let key_agreement = if opts.deactivate {
        Vec::new()
    } else {
        opts.relationships
            .key_agreement
            .unwrap_or_else(|| old.key_agreement.clone())
    };

    let next_allowed = if opts.deactivate {
        Vec::new()
    } else {
        opts.allowed.clone()
    };
    let next_threshold = if opts.deactivate {
        None
    } else {
        opts.threshold
    };

    validate_relationship_references(
        &authentication,
        &assertion,
        &key_agreement,
        &next_allowed,
        next_threshold,
        &core_controller_keys,
    )?;

    // Now build DidCore
    let core = DidCore {
        id: old.id.clone(),
        sequence: next_seq,
        prev: Some(prev_cid.clone()),
        controller: controller_vec,
        controller_keys: core_controller_keys,
        authentication,
        assertion: assertion.clone(),
        key_agreement,
        services: core_services,
        nonce: None,
        update_policy: CoreUpdatePolicy {
            allowed_verification_methods: next_allowed,
            threshold: next_threshold,
        },
    };

    // ----------------------------------------------------
    // 6. Canonical CBOR + CID
    // ----------------------------------------------------
    let _core_cbor = core
        .canonical_cbor()
        .map_err(|_| UpdateError::InvalidState)?;
    let core_cid = compute_core_cid(&core).map_err(|_| UpdateError::InvalidState)?;

    // ----------------------------------------------------
    // 7. Core attestations
    // ----------------------------------------------------
    let core_attestations = sign_core_with_policy(
        &core,
        &previous_controller_keys,
        &old_update_policy.allowed_verification_methods,
        old_update_policy.threshold,
        |id| authorization_priv_lookup(id),
    )
    .map_err(|error| match error {
        DidCoreError::PolicyViolation => UpdateError::PolicyViolation,
        _ => UpdateError::InvalidState,
    })?;

    let attestations: Vec<Attestation> = core_attestations
        .into_iter()
        .map(|a| Attestation {
            alg: a.algorithm,
            vm: a.verification_method,
            sig: a.signature,
        })
        .collect();

    // ----------------------------------------------------
    // 7b. Optional ES256 DataIntegrityProof over NEW CID
    // ----------------------------------------------------
    let mut data_integrity_proof: Option<reallyme_did_types::DataIntegrityProof> = None;

    // Did the old document have a DI proof?
    let had_proof_before = old.data_integrity_proof.is_some();

    // Find P-256 assertion key in the UPDATED document
    let p256_vmid = new_controller_keys
        .iter()
        .find(|vm| {
            matches!(
                vm.algorithm.as_deref(),
                Some("P-256" | "P256" | "p256" | "ES256")
            ) && assertion.contains(&vm.id)
        })
        .map(|vm| vm.id.clone());

    // Case 1: proof existed before AND P-256 key still exists → regenerate
    if had_proof_before {
        if let Some(vm_id) = p256_vmid {
            let created = opts.created.as_deref().ok_or(UpdateError::InvalidState)?;

            if let Some(privkey) = current_priv_lookup(&vm_id).map(zeroize::Zeroizing::new) {
                let proof =
                    envelopes_data_integrity::suites::es256_jws_cid_2025::sign_es256_jws_cid_2025(
                        &core_cid, &privkey, &vm_id, created,
                    )
                    .map_err(|_| UpdateError::InvalidState)?;

                data_integrity_proof = Some(proof);
            }
        }
    // else: P-256 key removed → drop proof (correct behavior)
    }
    // Case 2 (optional): no proof before, but caller explicitly requested one
    else if let (Some(vm_id), Some(created)) = (p256_vmid, opts.created.as_deref()) {
        if let Some(privkey) = current_priv_lookup(&vm_id).map(zeroize::Zeroizing::new) {
            let proof =
                envelopes_data_integrity::suites::es256_jws_cid_2025::sign_es256_jws_cid_2025(
                    &core_cid, &privkey, &vm_id, created,
                )
                .map_err(|_| UpdateError::InvalidState)?;

            data_integrity_proof = Some(proof);
        }
    }

    // ----------------------------------------------------
    // 8. Project updated DIDDocument
    // ----------------------------------------------------
    project_did_document(DocumentProjection {
        core: &core,
        core_cid: &core_cid,

        also_known_as: opts
            .metadata
            .also_known_as
            .unwrap_or_else(|| old.also_known_as.clone()),
        hardware_bound: opts.metadata.hardware_bound.or(old.hardware_bound),
        biometric_protected: opts
            .metadata
            .biometric_protected
            .or(old.biometric_protected),
        user_verification_method: opts
            .metadata
            .user_verification_method
            .or(old.user_verification_method.clone()),
        device_model: opts.metadata.device_model.or(old.device_model.clone()),

        key_history: new_history,
        verification_method: projected_verification_methods,
        capability_invocation: core.update_policy.allowed_verification_methods.clone(),
        domain_verification: merged_dv,
        attestations,
        data_integrity_proof,
        eudi_level_of_assurance: old.eudi_level_of_assurance.clone(),
        eudi_schema_version: old.eudi_schema_version.clone(),
    })
    .map_err(|_| UpdateError::InvalidState)
}
