// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{model::QcStatements, X509Error};

use asn1_rs::{Any, FromDer, Sequence};
use oid_registry::Oid;

pub const OID_QC_STATEMENTS_EXT: &str = "1.3.6.1.5.5.7.1.3";
pub const OID_ETSI_QCS_QC_COMPLIANCE: &str = "0.4.0.1862.1.1";
pub const OID_ETSI_QCS_QC_SSCD: &str = "0.4.0.1862.1.4";
pub const OID_ETSI_QCS_QC_TYPE: &str = "0.4.0.1862.1.6";

pub const OID_ETSI_QCT_ESIGN: &str = "0.4.0.1862.1.6.1";
pub const OID_ETSI_QCT_ESEAL: &str = "0.4.0.1862.1.6.2";
pub const OID_ETSI_QCT_WEB: &str = "0.4.0.1862.1.6.3";

pub fn parse_qc_statements(der: &[u8]) -> Result<QcStatements, X509Error> {
    // qcStatements ::= SEQUENCE { QCStatement, QCStatement, ... }
    let (outer_remaining, outer) = Sequence::from_der(der).map_err(|_| X509Error::ParseError)?;
    if !outer_remaining.is_empty() {
        return Err(X509Error::ParseError);
    }

    let mut statement_ids = Vec::new();
    let mut qc_types = Vec::new();

    let mut rem = outer.content.as_ref();

    while !rem.is_empty() {
        // Parse ONE QCStatement ::= SEQUENCE
        let (r, stmt_seq) = Sequence::from_der(rem).map_err(|_| X509Error::ParseError)?;
        rem = r;

        let mut inner = stmt_seq.content.as_ref();

        // statementId
        let (r2, oid_any) = Any::from_der(inner).map_err(|_| X509Error::ParseError)?;
        inner = r2;

        let oid: Oid = oid_any.try_into().map_err(|_| X509Error::ParseError)?;
        let oid_str = oid.to_string();
        statement_ids.push(oid_str.clone());

        // statementInfo (only qcType has structured info)
        if oid_str == OID_ETSI_QCS_QC_TYPE && !inner.is_empty() {
            let (statement_remaining, info_seq) =
                Sequence::from_der(inner).map_err(|_| X509Error::ParseError)?;
            if !statement_remaining.is_empty() {
                return Err(X509Error::ParseError);
            }

            let mut type_remaining = info_seq.content.as_ref();
            while !type_remaining.is_empty() {
                let (remaining, qct_any) =
                    Any::from_der(type_remaining).map_err(|_| X509Error::ParseError)?;
                let qct_oid: Oid = qct_any.try_into().map_err(|_| X509Error::ParseError)?;
                qc_types.push(qct_oid.to_string());
                type_remaining = remaining;
            }
        } else if !inner.is_empty() {
            // Preserve the statement identifier while requiring its optional
            // statementInfo to be one complete DER value.
            let (remaining, _) = Any::from_der(inner).map_err(|_| X509Error::ParseError)?;
            if !remaining.is_empty() {
                return Err(X509Error::ParseError);
            }
        }
    }

    statement_ids.sort();
    statement_ids.dedup();
    qc_types.sort();
    qc_types.dedup();

    Ok(QcStatements {
        statement_ids,
        qc_types,
    })
}
