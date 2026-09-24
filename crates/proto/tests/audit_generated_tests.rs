// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated audit protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use reallyme_ssi_proto::generated::proto::identity::audit::v1::{
    AuditInfo, IdentityProofing, IdentityProofingLevel, IssuerCredential, IssuerCredentialKind,
    KeyManagement, KeyProtection, QeaaCompliance, QeaaPolicies, QtspInfo, QtspRole,
    RevocationPolicy, StatusMethod,
};

#[test]
fn audit_proto_round_trips_with_buffa() {
    let qeaa = QeaaCompliance {
        qtsp: MessageField::some(QtspInfo {
            tsp_name: "Test QTSP".to_owned(),
            tsp_id: "EU:QTSP:123".to_owned(),
            tsp_role: EnumValue::from(QtspRole::QeaaProvider),
            ..QtspInfo::default()
        }),
        policies: MessageField::some(QeaaPolicies {
            policy_id: "eu-qeaa-policy-v1".to_owned(),
            standards: vec!["ETSI EN 319 411-2".to_owned()],
            ..QeaaPolicies::default()
        }),
        issuer_credential: MessageField::some(IssuerCredential {
            kind: EnumValue::from(IssuerCredentialKind::X509),
            cert_fingerprint_sha256: vec![7; 32],
            cert_chain_der: vec![vec![0x30, 0x03, 0x01]],
            trusted_list_ref: "EU-TSL:example".to_owned(),
            policy_oids: vec!["0.4.0.194112.1.3".to_owned()],
            qcstatements_oids: vec!["0.4.0.1862.1.1".to_owned()],
            ..IssuerCredential::default()
        }),
        key_management: MessageField::some(KeyManagement {
            signing_key_id: "issuer-signing-key-1".to_owned(),
            protection: EnumValue::from(KeyProtection::Qscd),
            ..KeyManagement::default()
        }),
        identity_proofing: MessageField::some(IdentityProofing {
            standard: "ETSI TS 119 461".to_owned(),
            loip: EnumValue::from(IdentityProofingLevel::High),
            evidence_ref: "urn:reallyme:evidence:proofing:1".to_owned(),
            evidence_hash: vec![9; 32],
            ..IdentityProofing::default()
        }),
        audit: MessageField::some(AuditInfo {
            audit_standard: "ETSI EN 319 403-1".to_owned(),
            audit_report_ref: "urn:reallyme:audit:report:1".to_owned(),
            audit_report_hash: vec![3; 32],
            period_from_unix: 1_700_000_000,
            period_to_unix: 1_800_000_000,
            ..AuditInfo::default()
        }),
        revocation: MessageField::some(RevocationPolicy {
            status_method: EnumValue::from(StatusMethod::StatusList),
            signing_key_id: "status-signing-key-1".to_owned(),
            max_status_age_seconds: 86_400,
            ..RevocationPolicy::default()
        }),
        ..QeaaCompliance::default()
    };

    let encoded = qeaa.encode_to_vec();
    let decoded_result = QeaaCompliance::decode(&mut encoded.as_slice());
    assert!(decoded_result.is_ok());
    let decoded = match decoded_result {
        Ok(decoded) => decoded,
        Err(_) => return,
    };

    let Some(decoded_audit) = decoded.audit.as_option() else {
        return;
    };
    assert_eq!(decoded_audit.audit_report_hash, vec![3; 32]);
    assert_eq!(decoded_audit.period_to_unix, 1_800_000_000);
}

#[test]
fn audit_proto_rejects_truncated_buffa_message() {
    let malformed = [
        0x0a, 0x02, // field 1, length-delimited QtspInfo with two declared bytes
        0x08, // truncated nested message: varint tag is present without a value
    ];

    let decoded_result = QeaaCompliance::decode(&mut malformed.as_slice());

    assert!(decoded_result.is_err());
}

#[test]
fn audit_debug_redacts_evidence_references() {
    const EVIDENCE_REF: &str = "urn:reallyme:evidence:sensitive";
    let proofing = IdentityProofing {
        standard: "sensitive-standard".to_owned(),
        evidence_ref: EVIDENCE_REF.to_owned(),
        evidence_hash: vec![0xA6_u8; 32],
        ..IdentityProofing::default()
    };

    let debug = format!("{proofing:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(EVIDENCE_REF));
    assert!(!debug.contains("sensitive-standard"));
}
