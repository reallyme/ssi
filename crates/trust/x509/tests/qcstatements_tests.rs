// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
//! Test coverage for this crate.

use reallyme_codec::base64::base64_to_bytes;
use reallyme_trust_x509::qcstatements::{
    parse_qc_statements, OID_ETSI_QCS_QC_COMPLIANCE, OID_ETSI_QCS_QC_SSCD, OID_ETSI_QCS_QC_TYPE,
    OID_ETSI_QCT_WEB,
};
use std::fs;

#[test]
fn parses_qc_compliance_and_qctype_web() {
    let b64 = fs::read_to_string("tests/fixtures/qcstatements_qwac.der").unwrap();
    let der = base64_to_bytes(b64.trim()).unwrap();

    let parsed = parse_qc_statements(&der).unwrap();

    assert!(parsed
        .statement_ids
        .contains(&OID_ETSI_QCS_QC_COMPLIANCE.to_string()));
    assert!(parsed
        .statement_ids
        .contains(&OID_ETSI_QCS_QC_TYPE.to_string()));
    assert!(parsed.qc_types.contains(&OID_ETSI_QCT_WEB.to_string()));
    assert_eq!(der.len(), 2 + usize::from(der[1]), "DER length mismatch");
}

#[test]
fn parses_unknown_qc_statement_without_claiming_qctype() {
    let der = [0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04];

    let parsed = parse_qc_statements(&der).unwrap();

    assert_eq!(parsed.statement_ids, vec!["1.2.3.4".to_owned()]);
    assert!(parsed.qc_types.is_empty());
}

#[test]
fn parses_qc_sscd_statement_for_conditional_policy() {
    let der = [
        0x30, 0x0a, 0x30, 0x08, 0x06, 0x06, 0x04, 0x00, 0x8e, 0x46, 0x01, 0x04,
    ];

    let parsed = parse_qc_statements(&der).unwrap();

    assert_eq!(parsed.statement_ids, vec![OID_ETSI_QCS_QC_SSCD.to_owned()]);
}

#[test]
fn rejects_malformed_qcstatements_der() {
    let der = [0x30, 0x03, 0x30, 0x01, 0x06];

    let err = parse_qc_statements(&der).unwrap_err();

    assert_eq!(err, reallyme_trust_x509::X509Error::ParseError);
}
