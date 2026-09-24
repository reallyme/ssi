// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Tests for trust policy mapping.

use identity_credential_trust_api::{map_trust_policy_to_profile, TrustPolicyId};
use identity_trust_tsl_core::{TrustServiceStatus, TrustServiceType};

#[test]
fn maps_qeaa_policy_to_requirements() {
    let policy = map_trust_policy_to_profile(TrustPolicyId::EuQeaaV1)
        .expect("QEAA policy should be supported");

    assert_eq!(
        policy.required_service_type,
        TrustServiceType::QualifiedElectronicAttestation
    );
    assert_eq!(policy.allowed_statuses, vec![TrustServiceStatus::Granted]);
}

#[test]
fn rejects_unknown_policy() {
    let err = map_trust_policy_to_profile(TrustPolicyId::GenericX509V1);

    assert!(err.is_err(), "unknown policy IDs must be rejected");
}
