// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{json_object_with_keys, VpProtoError};

pub(super) fn validate_zk_json(value: &serde_json::Value) -> Result<(), VpProtoError> {
    let fields = json_object_with_keys(
        value,
        &[
            "freshness",
            "credential",
            "disclosures",
            "zkProof",
            "zk_proof",
            "qeaa",
            "persona",
            "commonRoot",
            "common_root",
        ],
    )?;
    let persona = fields.get("persona");
    let common_root = fields
        .get("commonRoot")
        .or_else(|| fields.get("common_root"));
    if persona.is_some() || common_root.is_some() {
        if persona.is_some() == common_root.is_some()
            || fields
                .keys()
                .any(|key| !matches!(key.as_str(), "persona" | "commonRoot" | "common_root"))
        {
            return Err(VpProtoError::JsonDeserialize);
        }
        if let Some(persona) = persona {
            return validate_zk_persona_json(persona);
        }
        return validate_zk_common_root_json(common_root.ok_or(VpProtoError::JsonDeserialize)?);
    }
    validate_zk_credential_json(value)
}

fn validate_zk_common_root_json(value: &serde_json::Value) -> Result<(), VpProtoError> {
    let presentation = json_object_with_keys(
        value,
        &[
            "freshness",
            "mode",
            "disclosures",
            "proofPackage",
            "proof_package",
        ],
    )?;
    if let Some(value) = presentation.get("freshness") {
        json_object_with_keys(
            value,
            &[
                "challenge",
                "audienceHash",
                "audience_hash",
                "expiryUnix",
                "expiry_unix",
            ],
        )?;
    }
    if let Some(value) = presentation.get("disclosures") {
        validate_zk_disclosure_json(value)?;
    }
    Ok(())
}

fn validate_zk_persona_json(value: &serde_json::Value) -> Result<(), VpProtoError> {
    let presentation = json_object_with_keys(
        value,
        &[
            "freshness",
            "mode",
            "disclosures",
            "requestBoundProofPackage",
            "request_bound_proof_package",
            "prepared",
        ],
    )?;
    if let Some(value) = presentation.get("freshness") {
        json_object_with_keys(
            value,
            &[
                "challenge",
                "audienceHash",
                "audience_hash",
                "expiryUnix",
                "expiry_unix",
            ],
        )?;
    }
    if let Some(value) = presentation.get("disclosures") {
        validate_zk_disclosure_json(value)?;
    }
    if let Some(value) = presentation.get("prepared") {
        json_object_with_keys(
            value,
            &[
                "preparedEvidencePackage",
                "prepared_evidence_package",
                "currentStatePackage",
                "current_state_package",
                "verifierRequest",
                "verifier_request",
                "holderAuthentication",
                "holder_authentication",
                "holderPublicKey",
                "holder_public_key",
                "holderSignature",
                "holder_signature",
            ],
        )?;
    }
    Ok(())
}

fn validate_zk_credential_json(value: &serde_json::Value) -> Result<(), VpProtoError> {
    let zk = json_object_with_keys(
        value,
        &[
            "freshness",
            "credential",
            "disclosures",
            "zkProof",
            "zk_proof",
            "qeaa",
        ],
    )?;
    if let Some(value) = zk.get("freshness") {
        json_object_with_keys(
            value,
            &[
                "challenge",
                "audienceHash",
                "audience_hash",
                "expiryUnix",
                "expiry_unix",
            ],
        )?;
    }
    if let Some(value) = zk.get("credential") {
        let credential = json_object_with_keys(
            value,
            &[
                "envelopeHash",
                "envelope_hash",
                "issuerDid",
                "issuer_did",
                "status",
            ],
        )?;
        if let Some(status) = credential.get("status") {
            json_object_with_keys(
                status,
                &[
                    "statusListUrl",
                    "status_list_url",
                    "statusListId",
                    "status_list_id",
                    "statusListIndex",
                    "status_list_index",
                    "purpose",
                ],
            )?;
        }
    }
    if let Some(value) = zk.get("disclosures") {
        validate_zk_disclosure_json(value)?;
    }
    if let Some(value) = zk.get("zkProof").or_else(|| zk.get("zk_proof")) {
        let proof = json_object_with_keys(
            value,
            &[
                "circuitId",
                "circuit_id",
                "circuitVersion",
                "circuit_version",
                "vkId",
                "vk_id",
                "proofBytes",
                "proof_bytes",
                "publicInputs",
                "public_inputs",
                "proofSuite",
                "proof_suite",
                "artifactManifestSha256",
                "artifact_manifest_sha256",
            ],
        )?;
        if proof
            .get("publicInputs")
            .or_else(|| proof.get("public_inputs"))
            .is_some_and(|inputs| !inputs.is_object())
        {
            return Err(VpProtoError::JsonDeserialize);
        }
    }
    if let Some(value) = zk.get("qeaa").filter(|value| !value.is_null()) {
        json_object_with_keys(
            value,
            &[
                "required",
                "auditReportHash",
                "audit_report_hash",
                "maxStatusAgeSeconds",
                "max_status_age_seconds",
            ],
        )?;
    }
    Ok(())
}

fn validate_zk_disclosure_json(value: &serde_json::Value) -> Result<(), VpProtoError> {
    if let serde_json::Value::Array(disclosures) = value {
        for disclosure in disclosures {
            let disclosure = json_object_with_keys(
                disclosure,
                &[
                    "claimPath",
                    "claim_path",
                    "mode",
                    "revealedValue",
                    "revealed_value",
                    "threshold",
                    "range",
                    "set",
                ],
            )?;
            if let Some(range) = disclosure.get("range") {
                json_object_with_keys(range, &["min", "max"])?;
            }
            if let Some(set) = disclosure.get("set") {
                json_object_with_keys(set, &["values"])?;
            }
        }
    } else {
        return Err(VpProtoError::JsonDeserialize);
    }
    Ok(())
}
