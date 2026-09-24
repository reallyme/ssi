// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use identity_trust_tsl_core::{TrustServiceStatus, TrustServiceType};

use crate::{TrustApiError, TrustPolicyErrorReason, TrustPolicyId};

/// Requirements attached to a named trust policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustPolicyRequirements {
    /// Required ETSI trust-service type identifier.
    pub required_service_type: TrustServiceType,
    /// Accepted ETSI service statuses.
    pub allowed_statuses: Vec<TrustServiceStatus>,
}

/// Map a stable policy identifier to service requirements.
pub fn map_trust_policy_to_profile(
    policy_id: TrustPolicyId,
) -> Result<TrustPolicyRequirements, TrustApiError> {
    match policy_id {
        TrustPolicyId::EuQeaaV1 => Ok(TrustPolicyRequirements {
            required_service_type: TrustServiceType::QualifiedElectronicAttestation,
            allowed_statuses: vec![TrustServiceStatus::Granted],
        }),
        _ => Err(TrustApiError::Policy(
            TrustPolicyErrorReason::UnknownTrustPolicy,
        )),
    }
}
