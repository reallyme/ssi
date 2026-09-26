// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_codec::cbor::{decode_dag_cbor, verify_dag_cbor_cid, CborValue};

use reallyme_did_types::Controller;

use crate::validate::diagnostic::{DidValidationCode, DidValidationIssue, DidValidationLocation};
use crate::validate::limits::MAX_CORE_CBOR_ENCODED_BYTES;

/// Result of validating the embedded canonical core snapshot.
#[derive(Debug)]
pub struct CoreValidationResult {
    /// Whether the core snapshot is valid.
    pub ok: bool,

    /// Machine-readable validation issues collected for callers and tests.
    pub errors: Vec<DidValidationIssue>,

    /// Non-fatal validation issues for optional or externally supplied validation context.
    pub warnings: Vec<DidValidationIssue>,

    /// Decoded DAG-CBOR core value when decoding succeeds.
    pub core: Option<CborValue>,

    /// Raw canonical CBOR bytes when base64url decoding succeeds.
    pub cbor_bytes: Option<Vec<u8>>,
}

/// Minimal DID Document view required to validate `coreCbor` and `currentCore`.
pub struct DidMeDocCoreView<'a> {
    /// DID Document id.
    pub id: &'a str,

    /// DID Document controller value.
    pub controller: &'a Controller,

    /// DID Document sequence.
    pub sequence: u64,

    /// Previous core CID, if any.
    pub prev: Option<&'a str>,

    /// Current core CID.
    pub current_core: &'a str,

    /// Base64url-encoded canonical core CBOR.
    pub core_cbor: &'a str,
}

fn issue(code: DidValidationCode, location: DidValidationLocation) -> DidValidationIssue {
    DidValidationIssue::new(code, location)
}

/// Validate that a DID Document's encoded core snapshot is canonical and self-consistent.
pub fn validate_core_snapshot(doc: DidMeDocCoreView<'_>) -> CoreValidationResult {
    let mut errors = Vec::new();
    let warnings = Vec::new();

    // ---------------------------------------------------------------------
    // 1. Decode coreCbor base64 (bounded before any decoding work)
    // ---------------------------------------------------------------------
    if doc.core_cbor.len() > MAX_CORE_CBOR_ENCODED_BYTES {
        errors.push(issue(
            DidValidationCode::ResourceLimitExceeded,
            DidValidationLocation::Core,
        ));
        return CoreValidationResult {
            ok: false,
            errors,
            warnings,
            core: None,
            cbor_bytes: None,
        };
    }

    let cbor_bytes: Vec<u8> = match base64url_to_bytes(doc.core_cbor) {
        Ok(b) => b,
        Err(_) => {
            errors.push(issue(
                DidValidationCode::CoreCborEncodingInvalid,
                DidValidationLocation::Core,
            ));
            return CoreValidationResult {
                ok: false,
                errors,
                warnings,
                core: None,
                cbor_bytes: None,
            };
        }
    };

    // ---------------------------------------------------------------------
    // 2. Decode canonical DAG-CBOR
    // ---------------------------------------------------------------------
    let core_value: CborValue = match decode_dag_cbor(&cbor_bytes) {
        Ok(v) => v,
        Err(_) => {
            errors.push(issue(
                DidValidationCode::CoreCborCanonicalInvalid,
                DidValidationLocation::Core,
            ));
            return CoreValidationResult {
                ok: false,
                errors,
                warnings,
                core: None,
                cbor_bytes: None,
            };
        }
    };

    if !matches!(core_value, CborValue::Map(_)) {
        errors.push(issue(
            DidValidationCode::CoreShapeInvalid,
            DidValidationLocation::Core,
        ));
        return CoreValidationResult {
            ok: false,
            errors,
            warnings,
            core: None,
            cbor_bytes: None,
        };
    }

    // ---------------------------------------------------------------------
    // 3. Recompute CID and compare with currentCore
    // ---------------------------------------------------------------------
    let (cid_ok, _expected, _actual) = verify_dag_cbor_cid(doc.current_core, &cbor_bytes);
    if !cid_ok {
        errors.push(issue(
            DidValidationCode::CoreCidMismatch,
            DidValidationLocation::Core,
        ));
    }

    // ---------------------------------------------------------------------
    // 4. core.id vs doc.id
    // ---------------------------------------------------------------------
    match map_get(&core_value, "id") {
        Some(CborValue::String(id)) => {
            if id != doc.id {
                errors.push(issue(
                    DidValidationCode::CoreProjectionMismatch,
                    DidValidationLocation::Id,
                ));
            }
        }
        _ => errors.push(issue(
            DidValidationCode::CoreShapeInvalid,
            DidValidationLocation::Id,
        )),
    }

    // ---------------------------------------------------------------------
    // 5. core.sequence vs doc.sequence
    // ---------------------------------------------------------------------
    match map_get(&core_value, "sequence") {
        Some(CborValue::Int(seq)) => {
            if *seq < 1 {
                errors.push(issue(
                    DidValidationCode::CoreStateInvalid,
                    DidValidationLocation::Core,
                ));
            }
            if let Ok(seq_u) = u64::try_from(*seq) {
                if seq_u != doc.sequence {
                    errors.push(issue(
                        DidValidationCode::CoreProjectionMismatch,
                        DidValidationLocation::Core,
                    ));
                }
            }
        }
        _ => errors.push(issue(
            DidValidationCode::CoreShapeInvalid,
            DidValidationLocation::Core,
        )),
    }

    // ---------------------------------------------------------------------
    // 6. core.prev vs doc.prev
    // ---------------------------------------------------------------------
    if doc.sequence == 1 {
        // TS: core.prev must be null/undefined when sequence=1
        if map_get(&core_value, "prev").is_some() {
            errors.push(issue(
                DidValidationCode::CoreStateInvalid,
                DidValidationLocation::Core,
            ));
        }
        match (map_get(&core_value, "nonce"), doc.prev) {
            (Some(CborValue::Bytes(nonce)), None) if nonce.len() == 16 => {}
            (Some(CborValue::Bytes(_)), None) => {
                errors.push(issue(
                    DidValidationCode::CoreStateInvalid,
                    DidValidationLocation::Nonce,
                ));
            }
            _ => errors.push(issue(
                DidValidationCode::CoreStateInvalid,
                DidValidationLocation::Nonce,
            )),
        }
    } else {
        match map_get(&core_value, "prev") {
            Some(CborValue::String(prev)) => {
                if Some(prev.as_str()) != doc.prev {
                    errors.push(issue(
                        DidValidationCode::CoreProjectionMismatch,
                        DidValidationLocation::Core,
                    ));
                }
            }
            _ => errors.push(issue(
                DidValidationCode::CoreStateInvalid,
                DidValidationLocation::Core,
            )),
        }
        if map_get(&core_value, "nonce").is_some() {
            errors.push(issue(
                DidValidationCode::CoreStateInvalid,
                DidValidationLocation::Nonce,
            ));
        }
    }

    // ---------------------------------------------------------------------
    // 7. controller consistency (supports reduced projection)
    // ---------------------------------------------------------------------
    validate_controller_projection(&core_value, doc.controller, &mut errors);

    CoreValidationResult {
        ok: errors.is_empty(),
        errors,
        warnings,
        core: Some(core_value),
        cbor_bytes: Some(cbor_bytes),
    }
}

/// Map lookup helper: core must be a CBOR map.
fn map_get<'a>(core: &'a CborValue, key: &str) -> Option<&'a CborValue> {
    match core {
        CborValue::Map(entries) => entries
            .iter()
            .find_map(|(k, v)| if k == key { Some(v) } else { None }),
        _ => None,
    }
}

/// Require the projected controller to equal the signed core controller set.
fn validate_controller_projection(
    core: &CborValue,
    doc_controller: &Controller,
    errors: &mut Vec<DidValidationIssue>,
) {
    let core_ctrl: Vec<String> = match map_get(core, "controller") {
        Some(CborValue::Array(arr)) => {
            let mut out = Vec::new();
            for v in arr {
                match v {
                    CborValue::String(s) => out.push(s.clone()),
                    _ => {
                        errors.push(issue(
                            DidValidationCode::ControllerInvalid,
                            DidValidationLocation::Controller,
                        ));
                        return;
                    }
                }
            }
            out
        }
        Some(CborValue::String(s)) => vec![s.clone()],
        _ => {
            errors.push(issue(
                DidValidationCode::ControllerInvalid,
                DidValidationLocation::Controller,
            ));
            return;
        }
    };

    if core_ctrl.is_empty() {
        errors.push(issue(
            DidValidationCode::ControllerInvalid,
            DidValidationLocation::Controller,
        ));
        return;
    }

    match (core_ctrl.as_slice(), doc_controller) {
        // ---- Case 1: core has exactly one controller ----
        ([one], Controller::Single(doc_one)) => {
            // The projected controller must be the signed core controller.
            if doc_one != one {
                errors.push(issue(
                    DidValidationCode::ControllerInvalid,
                    DidValidationLocation::Controller,
                ));
            }
        }
        ([one], Controller::Multiple(doc_arr)) => {
            // doc MUST NOT expand single controller into an array (unless identical length=1)
            if !(doc_arr.len() == 1 && doc_arr[0] == *one) {
                errors.push(issue(
                    DidValidationCode::ControllerInvalid,
                    DidValidationLocation::Controller,
                ));
            }
        }

        // ---- Case 2: core has multiple controllers ----
        (_many, Controller::Single(_)) => {
            // The projection never collapses several signed controllers into one;
            // a single-controller document cannot represent a multi-controller core.
            errors.push(issue(
                DidValidationCode::ControllerInvalid,
                DidValidationLocation::Controller,
            ));
        }
        (many, Controller::Multiple(doc_arr)) => {
            let mut core_sorted = many.to_vec();
            let mut doc_sorted = doc_arr.clone();

            core_sorted.sort();
            doc_sorted.sort();

            if core_sorted != doc_sorted {
                errors.push(issue(
                    DidValidationCode::ControllerInvalid,
                    DidValidationLocation::Controller,
                ));
            }
        }
    }
}
