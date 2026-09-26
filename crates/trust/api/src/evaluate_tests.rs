// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unit tests for typed trust evaluation input and purpose policy.

use super::{core_context_for_authorization, verify_credential_trust_api};
use crate::{AuthorizationPurpose, TrustApiError};

use reallyme_trust_core::{CertificateStatusPolicy, SignatureVerifier, StatusRequirement};

struct RejectingVerifier;

impl SignatureVerifier for RejectingVerifier {
    fn verify_chain(
        &self,
        _chain: &envelopes_x509::X509Chain,
        _now: time::OffsetDateTime,
    ) -> Result<(), reallyme_trust_core::SignatureVerifyError> {
        Err(reallyme_trust_core::SignatureVerifyError::InvalidSignature)
    }
}

#[test]
fn purpose_without_a_trusted_list_is_invalid_input() {
    let result = verify_credential_trust_api(
        Vec::new(),
        Vec::new(),
        &RejectingVerifier,
        None,
        None,
        Some(AuthorizationPurpose::QeaaIssuer),
        time::OffsetDateTime::UNIX_EPOCH,
    );
    assert!(matches!(result, Err(TrustApiError::InvalidInput)));
}

#[test]
fn qualified_purposes_require_leaf_and_intermediate_status() {
    let required = CertificateStatusPolicy {
        leaf: StatusRequirement::Required,
        intermediates: StatusRequirement::Required,
        trust_anchor: StatusRequirement::Exempt,
    };
    for purpose in [
        AuthorizationPurpose::QeaaIssuer,
        AuthorizationPurpose::QwacTlsServer,
        AuthorizationPurpose::QsealSigner,
    ] {
        assert_eq!(
            core_context_for_authorization(purpose).status_policy,
            required
        );
    }
    assert_eq!(
        reallyme_trust_core::TrustEvaluationContext::default().status_policy,
        CertificateStatusPolicy::default()
    );
}
