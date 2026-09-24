// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::did::mapping::{
    attestation::attestation_from_proto, data_integrity_proof::di_proof_from_proto,
    domain_verification::domain_from_proto, service::service_from_proto,
    update_policy::update_policy_from_proto, verification_method::vm_from_proto,
};
use crate::did::DidProtoCodecError;

use buffa_types::google::protobuf::{value::Kind, Value};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_did_types::{Controller, DIDDocument};
use reallyme_ssi_proto::generated::proto::meid::did::v1::DIDDocument as PbDIDDocument;

/// Convert the authoritative did:me protobuf projection into the Rust DID document model.
pub fn proto_to_json(p: &PbDIDDocument) -> Result<DIDDocument, DidProtoCodecError> {
    let controller = project_controller(
        p.controller
            .as_option()
            .ok_or(DidProtoCodecError::MissingRequiredField)?,
    )?;

    Ok(DIDDocument {
        context: p.context.clone(),
        id: p.id.clone(),
        controller,
        also_known_as: p.also_known_as.clone(),
        sequence: p.sequence,
        prev: p.prev.clone(),
        nonce: p.nonce.as_ref().map(|nonce| bytes_to_base64url(nonce)),
        hardware_bound: p.hardware_bound,
        biometric_protected: p.biometric_protected,
        user_verification_method: non_empty(&p.user_verification_method),
        device_model: non_empty(&p.device_model),
        core_cbor: bytes_to_base64url(&p.core_cbor),
        current_core: p.current_core.clone(),
        key_history: p.key_history.clone(),
        verification_method: p
            .verification_method
            .iter()
            .map(vm_from_proto)
            .collect::<Result<_, _>>()?,
        authentication: p.authentication.clone(),
        assertion_method: p.assertion_method.clone(),
        capability_invocation: p.capability_invocation.clone(),
        key_agreement: p.key_agreement.clone(),
        service: p
            .service
            .iter()
            .map(service_from_proto)
            .collect::<Result<_, _>>()?,
        update_policy: p.update_policy.as_option().map(update_policy_from_proto),
        attestations: p
            .attestations
            .iter()
            .map(attestation_from_proto)
            .collect::<Result<_, _>>()?,
        data_integrity_proof: p.proof.as_option().map(di_proof_from_proto),
        domain_verification: p
            .domain_verification
            .iter()
            .map(domain_from_proto)
            .collect::<Result<_, _>>()?,
        eudi_level_of_assurance: non_empty(&p.eudi_level_of_assurance),
        eudi_schema_version: non_empty(&p.eudi_schema_version),
    })
}

fn project_controller(ctrl: &Value) -> Result<Controller, DidProtoCodecError> {
    match ctrl.kind.as_ref() {
        Some(Kind::StringValue(value)) => Ok(Controller::Single(value.clone())),
        Some(Kind::ListValue(list)) => {
            let mut out = Vec::with_capacity(list.values.len());
            for value in &list.values {
                match value.kind.as_ref() {
                    Some(Kind::StringValue(item)) => out.push(item.clone()),
                    _ => return Err(DidProtoCodecError::InvalidController),
                }
            }
            Ok(Controller::Multiple(out))
        }
        _ => Err(DidProtoCodecError::InvalidController),
    }
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}
