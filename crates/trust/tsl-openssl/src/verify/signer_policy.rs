// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_x509::{EtsiAlgorithmPolicy, TrustAnchorRequirement};

use crate::error::{TslOpenSslError, TslSignerTrustFailureReason};

pub(super) fn bind_tsl_signer_policy(
    mut policy: envelopes_x509::policy::X509Policy,
) -> Result<envelopes_x509::policy::X509Policy, TslOpenSslError> {
    let required = envelopes_x509::tsl_signer_policy();
    policy.minimum_rsa_bits = Some(
        policy
            .minimum_rsa_bits
            .unwrap_or_default()
            .max(required.minimum_rsa_bits.unwrap_or_default()),
    );
    policy.minimum_ec_bits = Some(
        policy
            .minimum_ec_bits
            .unwrap_or_default()
            .max(required.minimum_ec_bits.unwrap_or_default()),
    );
    if policy.allowed_public_key_algorithms.is_empty() {
        policy.allowed_public_key_algorithms = required.allowed_public_key_algorithms;
    } else if policy
        .allowed_public_key_algorithms
        .iter()
        .any(|algorithm| !required.allowed_public_key_algorithms.contains(algorithm))
    {
        return Err(TslOpenSslError::TrustFailure(
            TslSignerTrustFailureReason::Rejected,
        ));
    }
    if policy.allowed_signature_algorithms.is_empty() {
        policy.allowed_signature_algorithms = required.allowed_signature_algorithms;
    } else if policy
        .allowed_signature_algorithms
        .iter()
        .any(|algorithm| !required.allowed_signature_algorithms.contains(algorithm))
    {
        return Err(TslOpenSslError::TrustFailure(
            TslSignerTrustFailureReason::Rejected,
        ));
    }
    policy.etsi_algorithm_policy = EtsiAlgorithmPolicy::Ts119312V211;
    policy.require_intermediate_ca = true;
    policy.trust_anchor_requirement = match policy.trust_anchor_requirement {
        TrustAnchorRequirement::None => TrustAnchorRequirement::Rfc5280Ca,
        TrustAnchorRequirement::Rfc5280Ca | TrustAnchorRequirement::EudiProviderCa => {
            policy.trust_anchor_requirement
        }
        _ => {
            return Err(TslOpenSslError::TrustFailure(
                TslSignerTrustFailureReason::Rejected,
            ));
        }
    };
    Ok(policy)
}
