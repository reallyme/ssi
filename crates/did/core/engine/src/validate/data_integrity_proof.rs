// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_types::{DIDDocument, DataIntegrityProof};

use crate::validate::diagnostic::{DidValidationCode, DidValidationIssue, DidValidationLocation};

/// Result of Data Integrity proof schema validation.
#[derive(Debug, Clone)]
pub struct DataIntegrityProofValidationResult {
    /// Whether the optional proof is absent or schema-valid.
    pub ok: bool,

    /// Machine-readable validation issues collected for callers and tests.
    pub errors: Vec<DidValidationIssue>,
}

fn proof_issue() -> DidValidationIssue {
    DidValidationIssue::new(
        DidValidationCode::DataIntegrityProofInvalid,
        DidValidationLocation::DataIntegrityProof,
    )
}

/// Strict shape validation for did:me DataIntegrityProof (ES256 JWS CID 2025).
///
/// - type MUST equal "DataIntegrityProof"
/// - cryptosuite MUST equal "es256-jws-cid-2025"
/// - proofPurpose MUST equal "assertionMethod"
/// - verificationMethod MUST be "#fragment"
/// - created MUST be present, but its value is informational for DID validity
/// - jws MUST be compact JWS header.payload.signature using base64url charset
///
/// NOTE: this performs NO cryptographic verification.
pub fn validate_data_integrity_proof_schema(
    doc: &DIDDocument,
) -> DataIntegrityProofValidationResult {
    let mut errors = Vec::new();

    let proof = match &doc.data_integrity_proof {
        None => {
            return DataIntegrityProofValidationResult { ok: true, errors };
        }
        Some(p) => p,
    };

    validate_one(proof, &mut errors);

    DataIntegrityProofValidationResult {
        ok: errors.is_empty(),
        errors,
    }
}

fn validate_one(p: &DataIntegrityProof, errors: &mut Vec<DidValidationIssue>) {
    // type
    if p.proof_type != "DataIntegrityProof" {
        errors.push(proof_issue());
    }

    // cryptosuite
    match p.cryptosuite.as_deref() {
        Some("es256-jws-cid-2025") => {}
        _ => errors.push(proof_issue()),
    }

    match p.proof_purpose.as_deref() {
        Some("assertionMethod") => {}
        _ => errors.push(proof_issue()),
    }

    // verificationMethod
    match p.verification_method.as_deref() {
        Some(vm) if is_fragment_ref(vm) => {}
        _ => errors.push(proof_issue()),
    }

    // The did:me spec treats created as informational. A verifier may require
    // the field for proof shape, but must not reject a proof solely because of
    // timestamp parsing, clock skew, freshness, or timezone policy.
    match p.created.as_deref() {
        Some(ts) if !ts.is_empty() => {}
        _ => errors.push(proof_issue()),
    }

    // jws compact
    match p.jws.as_deref() {
        Some(jws) if is_compact_jws(jws) => {}
        _ => errors.push(proof_issue()),
    }
}

fn is_fragment_ref(s: &str) -> bool {
    s.starts_with('#') && s.len() > 1
}

fn is_compact_jws(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && is_b64url_token(p))
}

fn is_b64url_token(s: &str) -> bool {
    s.bytes().all(|b| {
        matches!(b,
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
        )
    })
}
