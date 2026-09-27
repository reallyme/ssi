// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn screen_intermediate_algorithms(
    chain: &X509Chain,
    now: OffsetDateTime,
    policy: &X509Policy,
) -> Result<(), X509Error> {
    // Apply algorithm policy to each path certificate. The terminal anchor is
    // handled separately because RFC 5280 treats it as a trust input.
    let intermediate_count = chain.certs.len().saturating_sub(2);
    for intermediate in chain.certs.iter().skip(1).take(intermediate_count) {
        if !public_key_meets_minimums(intermediate, policy) {
            return Err(X509Error::PolicyFailed(X509PolicyFailure::WeakPublicKey));
        }
        if !policy.allowed_public_key_algorithms.is_empty()
            && !policy
                .allowed_public_key_algorithms
                .contains(&intermediate.profile.public_key.algorithm())
        {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::PublicKeyAlgorithmNotAllowed,
            ));
        }
        if !policy.allowed_signature_algorithms.is_empty()
            && !policy
                .allowed_signature_algorithms
                .contains(&intermediate.profile.signature_algorithm)
        {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::SignatureAlgorithmNotAllowed,
            ));
        }
        if policy.etsi_algorithm_policy == EtsiAlgorithmPolicy::Ts119312V211
            && (!etsi_ts_119_312_v2_1_1_key_allowed(intermediate, now)
                || !etsi_ts_119_312_v2_1_1_signature_parameters_allowed(intermediate))
        {
            return Err(X509Error::PolicyFailed(
                X509PolicyFailure::AlgorithmParametersNotAllowed,
            ));
        }
    }
    Ok(())
}
