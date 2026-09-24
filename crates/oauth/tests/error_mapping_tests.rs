// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stable external mappings for OAuth domain errors.

use reallyme_openid_oauth::Reason;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn attestation_key_binding_failure_has_stable_external_mappings() {
    assert_eq!(
        Reason::AttestationKeyBindingFailed.to_string(),
        "attestation_key_binding_failed"
    );
    assert_eq!(
        IdentityCoreErrorReason::from(Reason::AttestationKeyBindingFailed),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_OAUTH_ATTESTATION_KEY_BINDING_FAILED
    );
}

#[test]
fn attestation_trust_outcomes_have_distinct_stable_mappings() {
    let cases = [
        (
            Reason::InvalidAttestationReceipt,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_OAUTH_INVALID_ATTESTATION_RECEIPT,
        ),
        (
            Reason::AttestationTrustRejected,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_OAUTH_ATTESTATION_TRUST_REJECTED,
        ),
        (
            Reason::AttestationTrustIndeterminate,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_OAUTH_ATTESTATION_TRUST_INDETERMINATE,
        ),
        (
            Reason::AttestationTrustEvidenceStale,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_OAUTH_ATTESTATION_TRUST_EVIDENCE_STALE,
        ),
        (
            Reason::AttestationTrustEvidenceFutureIssued,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_OAUTH_ATTESTATION_TRUST_EVIDENCE_FUTURE_ISSUED,
        ),
        (
            Reason::AttestationReplay,
            IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_OAUTH_ATTESTATION_REPLAY,
        ),
    ];
    for (reason, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(reason), expected);
    }
}

#[test]
fn authorization_server_issuer_mismatch_has_a_dedicated_proto_reason() {
    assert_eq!(
        Reason::AuthorizationServerIssuerMismatch.to_string(),
        "authorization_server_issuer_mismatch"
    );
    assert_eq!(
        IdentityCoreErrorReason::from(Reason::AuthorizationServerIssuerMismatch),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_OAUTH_AUTHORIZATION_SERVER_ISSUER_MISMATCH
    );
}
