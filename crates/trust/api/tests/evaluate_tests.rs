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
//! Tests for trust API evaluation.

use envelopes_x509::{BasicConstraints, KeyUsage, X509Certificate};
use identity_credential_trust_api::{evaluate_trust_api, TrustApiError, TrustDecisionOutcome};
use reallyme_trust_core::SignatureVerifier;
use time::OffsetDateTime;

struct AcceptAllVerifier;

impl SignatureVerifier for AcceptAllVerifier {
    fn verify_chain(
        &self,
        _chain: &envelopes_x509::X509Chain,
        _now: OffsetDateTime,
    ) -> Result<(), reallyme_trust_core::SignatureVerifyError> {
        Ok(())
    }
}

fn certificate(subject: &str, issuer: &str, is_ca: bool) -> X509Certificate {
    X509Certificate {
        der: subject.as_bytes().to_vec(),
        subject: subject.to_owned(),
        issuer: issuer.to_owned(),
        subject_der: subject.as_bytes().to_vec(),
        issuer_der: issuer.as_bytes().to_vec(),
        serial: vec![1],
        not_before: OffsetDateTime::UNIX_EPOCH,
        not_after: OffsetDateTime::UNIX_EPOCH + time::Duration::days(1),
        spki_der: vec![1],
        signature_algorithm_oid: "1.2.840.113549.1.1.11".to_owned(),
        basic_constraints: Some(BasicConstraints {
            ca: is_ca,
            path_len_constraint: None,
        }),
        key_usage: Some(KeyUsage {
            digital_signature: !is_ca,
            content_commitment: false,
            key_cert_sign: is_ca,
            crl_sign: is_ca,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            encipher_only: false,
            decipher_only: false,
        }),
        extended_key_usage: None,
        subject_key_identifier: is_ca.then_some(vec![0xA5]),
        authority_key_identifier: (!is_ca).then_some(vec![0xA5]),
        san_dns: Vec::new(),
        san_ip: Vec::new(),
        certificate_policies: Vec::new(),
        qc_statements: Default::default(),
        profile: Default::default(),
    }
}

#[test]
fn empty_chain_rejected() {
    let err = evaluate_trust_api(
        vec![],             // presented chain
        vec![],             // trust roots
        &AcceptAllVerifier, // signature verifier
        None,               // status checker
        OffsetDateTime::now_utc(),
    )
    .unwrap_err();

    assert!(matches!(err, TrustApiError::NotTrusted));
}

#[test]
fn default_api_enforces_leaf_signature_usage_and_ca_anchor() {
    let valid_leaf = certificate("CN=Leaf", "CN=Root", false);
    let valid_root = certificate("CN=Root", "CN=Root", true);
    let trusted = evaluate_trust_api(
        vec![valid_leaf.clone()],
        vec![valid_root.clone()],
        &AcceptAllVerifier,
        None,
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("bounded valid path returns a decision");
    assert_eq!(
        trusted.outcome,
        TrustDecisionOutcome::Trusted,
        "unexpected trust decision: {trusted:?}"
    );

    let mut non_signing_leaf = valid_leaf.clone();
    non_signing_leaf
        .key_usage
        .as_mut()
        .expect("test leaf key usage is present")
        .digital_signature = false;
    let rejected_leaf = evaluate_trust_api(
        vec![non_signing_leaf],
        vec![valid_root],
        &AcceptAllVerifier,
        None,
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("policy failure returns a typed decision");
    assert_eq!(rejected_leaf.outcome, TrustDecisionOutcome::Rejected);

    let non_ca_root = certificate("CN=Root", "CN=Root", false);
    let rejected_anchor = evaluate_trust_api(
        vec![valid_leaf],
        vec![non_ca_root],
        &AcceptAllVerifier,
        None,
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("anchor policy failure returns a typed decision");
    assert_eq!(rejected_anchor.outcome, TrustDecisionOutcome::Rejected);
}
