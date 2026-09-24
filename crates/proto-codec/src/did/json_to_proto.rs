// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::did::mapping::{
    attestation::attestation_to_proto, data_integrity_proof::di_proof_to_proto,
    domain_verification::domain_to_proto, service::service_to_proto,
    update_policy::policy_to_proto, verification_method::vm_to_proto,
};
use crate::did::DidProtoCodecError;

use buffa::MessageField;
use buffa_types::google::protobuf::{value::Kind, ListValue, Value};
use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_did_types::{Controller, DIDDocument};
use reallyme_ssi_proto::generated::proto::meid::did::v1::DIDDocument as PbDIDDocument;

/// Convert the Rust DID document model into the authoritative did:me protobuf projection.
pub fn json_to_proto(doc: &DIDDocument) -> Result<PbDIDDocument, DidProtoCodecError> {
    let core_cbor =
        base64url_to_bytes(&doc.core_cbor).map_err(|_| DidProtoCodecError::InvalidBase64Url)?;
    let nonce = match doc.nonce.as_deref() {
        Some(nonce) => {
            Some(base64url_to_bytes(nonce).map_err(|_| DidProtoCodecError::InvalidBase64Url)?)
        }
        None => None,
    };

    let mut out = PbDIDDocument {
        id: doc.id.clone(),
        controller: MessageField::some(controller_to_value(&doc.controller)),
        context: doc.context.clone(),
        also_known_as: doc.also_known_as.clone(),
        biometric_protected: doc.biometric_protected,
        hardware_bound: doc.hardware_bound,
        device_model: doc.device_model.clone().unwrap_or_default(),
        user_verification_method: doc.user_verification_method.clone().unwrap_or_default(),
        sequence: doc.sequence,
        prev: doc.prev.clone(),
        current_core: doc.current_core.clone(),
        core_cbor,
        nonce,
        key_history: doc.key_history.clone(),
        eudi_level_of_assurance: doc.eudi_level_of_assurance.clone().unwrap_or_default(),
        eudi_schema_version: doc.eudi_schema_version.clone().unwrap_or_default(),
        ..PbDIDDocument::default()
    };

    out.verification_method = doc
        .verification_method
        .iter()
        .map(vm_to_proto)
        .collect::<Result<_, _>>()?;
    out.authentication = doc.authentication.clone();
    out.assertion_method = doc.assertion_method.clone();
    out.capability_invocation = doc.capability_invocation.clone();
    out.key_agreement = doc.key_agreement.clone();
    out.service = doc
        .service
        .iter()
        .map(service_to_proto)
        .collect::<Result<_, _>>()?;
    out.update_policy = MessageField::some(policy_to_proto(
        doc.update_policy
            .as_ref()
            .ok_or(DidProtoCodecError::MissingRequiredField)?,
    ));
    out.attestations = doc
        .attestations
        .iter()
        .map(attestation_to_proto)
        .collect::<Result<_, _>>()?;
    out.proof = match doc.data_integrity_proof.as_ref() {
        Some(proof) => MessageField::some(di_proof_to_proto(proof)),
        None => MessageField::none(),
    };
    out.domain_verification = doc
        .domain_verification
        .iter()
        .map(domain_to_proto)
        .collect::<Result<_, _>>()?;

    Ok(out)
}

fn controller_to_value(controller: &Controller) -> Value {
    match controller {
        Controller::Single(value) => Value {
            kind: Some(Kind::StringValue(value.clone())),
            ..Value::default()
        },
        Controller::Multiple(values) => Value {
            kind: Some(Kind::ListValue(Box::new(ListValue {
                values: values
                    .iter()
                    .map(|value| Value {
                        kind: Some(Kind::StringValue(value.clone())),
                        ..Value::default()
                    })
                    .collect(),
                ..ListValue::default()
            }))),
            ..Value::default()
        },
    }
}
