// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use buffa::{EnumValue, Enumeration, MessageField};
use reallyme_ssi_proto::generated::proto::identity::credential::v1 as credential_pb;
use reallyme_ssi_proto::generated::proto::identity::presentation::v1 as pb;
use reallyme_ssi_proto::generated::proto::identity::presentation::v1::__buffa::oneof::{
    claim_disclosure, presentation,
};
use reallyme_vp_core as vp;

use crate::presentation::{VpProtoError, MAX_MDOC_DEVICE_RESPONSE_BYTES};

#[path = "validate_disclosure.rs"]
mod validate_disclosure;

use validate_disclosure::{validate_disclosure_model, validate_disclosure_value};

/// Convert the Rust VP model to the generated protobuf model.
#[must_use]
pub fn presentation_to_proto(presentation_model: &vp::Presentation) -> pb::Presentation {
    match presentation_model {
        vp::Presentation::Zk(presentation_model) => pb::Presentation {
            kind: Some(presentation::Kind::Zk(Box::new(zk_to_proto(
                presentation_model,
            )))),
            ..pb::Presentation::default()
        },
        vp::Presentation::SdJwtVc(presentation_model) => pb::Presentation {
            kind: Some(presentation::Kind::SdJwtVc(Box::new(sd_jwt_to_proto(
                presentation_model,
            )))),
            ..pb::Presentation::default()
        },
        vp::Presentation::Mdoc(presentation_model) => pb::Presentation {
            kind: Some(presentation::Kind::Mdoc(Box::new(mdoc_to_proto(
                presentation_model,
            )))),
            ..pb::Presentation::default()
        },
    }
}

/// Convert a generated protobuf model to the Rust VP model.
pub fn proto_to_presentation(
    presentation_model: &pb::Presentation,
) -> Result<vp::Presentation, VpProtoError> {
    match presentation_model
        .kind
        .as_ref()
        .ok_or(VpProtoError::MissingField)?
    {
        presentation::Kind::Zk(model) => Ok(vp::Presentation::Zk(Box::new(zk_from_proto(model)?))),
        presentation::Kind::SdJwtVc(model) => Ok(vp::Presentation::SdJwtVc(Box::new(
            sd_jwt_from_proto(model)?,
        ))),
        presentation::Kind::Mdoc(model) => {
            Ok(vp::Presentation::Mdoc(Box::new(mdoc_from_proto(model)?)))
        }
    }
}

/// Convert a generated protobuf model to the Rust VP model, moving large
/// owned fields out of `presentation_model` instead of copying them.
///
/// Fields are only moved after every fallible check for the selected variant
/// has passed, so an error never leaves moved plaintext outside a zeroizing
/// owner. Remaining material stays in `presentation_model` for its owner to
/// zeroize.
pub(crate) fn take_proto_into_presentation(
    presentation_model: &mut pb::Presentation,
) -> Result<vp::Presentation, VpProtoError> {
    match presentation_model
        .kind
        .as_mut()
        .ok_or(VpProtoError::MissingField)?
    {
        presentation::Kind::Zk(model) => Ok(vp::Presentation::Zk(Box::new(zk_from_proto(model)?))),
        presentation::Kind::SdJwtVc(model) => Ok(vp::Presentation::SdJwtVc(Box::new(
            sd_jwt_take_from_proto(model)?,
        ))),
        presentation::Kind::Mdoc(model) => Ok(vp::Presentation::Mdoc(Box::new(
            mdoc_take_from_proto(model)?,
        ))),
    }
}

/// Validate cross-field semantics of a Rust VP model before encoding.
///
/// `presentation_to_proto` maps the first populated disclosure value, so an
/// inconsistent model must be rejected before it reaches the wire.
pub(crate) fn validate_presentation_semantics(
    presentation_model: &vp::Presentation,
) -> Result<(), VpProtoError> {
    let vp::Presentation::Zk(model) = presentation_model else {
        return Ok(());
    };
    if matches!(
        model.credential.status.purpose,
        vp::StatusPurpose::Unspecified
    ) {
        return Err(VpProtoError::InvalidEnumValue);
    }
    for disclosure in &model.disclosures {
        validate_disclosure_model(disclosure)?;
    }
    Ok(())
}

fn mdoc_to_proto(model: &vp::MdocPresentation) -> pb::MdocPresentation {
    pb::MdocPresentation {
        device_response: model.device_response.clone(),
        envelope_hash: model.envelope_hash.map(Vec::from),
        doc_type: model.doc_type.clone(),
        ..pb::MdocPresentation::default()
    }
}

fn mdoc_from_proto(model: &pb::MdocPresentation) -> Result<vp::MdocPresentation, VpProtoError> {
    if model.device_response.len() > MAX_MDOC_DEVICE_RESPONSE_BYTES {
        return Err(VpProtoError::MdocDeviceResponseTooLarge);
    }
    Ok(vp::MdocPresentation {
        device_response: model.device_response.clone(),
        envelope_hash: optional_slice_to_32(model.envelope_hash.as_deref())?,
        doc_type: model.doc_type.clone(),
    })
}

fn mdoc_take_from_proto(
    model: &mut pb::MdocPresentation,
) -> Result<vp::MdocPresentation, VpProtoError> {
    if model.device_response.len() > MAX_MDOC_DEVICE_RESPONSE_BYTES {
        return Err(VpProtoError::MdocDeviceResponseTooLarge);
    }
    let envelope_hash = optional_slice_to_32(model.envelope_hash.as_deref())?;
    Ok(vp::MdocPresentation {
        device_response: core::mem::take(&mut model.device_response),
        envelope_hash,
        doc_type: core::mem::take(&mut model.doc_type),
    })
}

fn sd_jwt_to_proto(model: &vp::SdJwtVcPresentation) -> pb::SdJwtVcPresentation {
    pb::SdJwtVcPresentation {
        sd_jwt: model.sd_jwt.clone(),
        disclosures: model.disclosures.clone(),
        kb_jwt: model.kb_jwt.clone(),
        vct: model.vct.clone(),
        envelope_hash: model.envelope_hash.map(Vec::from),
        ..pb::SdJwtVcPresentation::default()
    }
}

fn sd_jwt_from_proto(
    model: &pb::SdJwtVcPresentation,
) -> Result<vp::SdJwtVcPresentation, VpProtoError> {
    Ok(vp::SdJwtVcPresentation {
        sd_jwt: model.sd_jwt.clone(),
        disclosures: model.disclosures.clone(),
        kb_jwt: model.kb_jwt.clone(),
        vct: model.vct.clone(),
        envelope_hash: optional_slice_to_32(model.envelope_hash.as_deref())?,
    })
}

fn sd_jwt_take_from_proto(
    model: &mut pb::SdJwtVcPresentation,
) -> Result<vp::SdJwtVcPresentation, VpProtoError> {
    let envelope_hash = optional_slice_to_32(model.envelope_hash.as_deref())?;
    Ok(vp::SdJwtVcPresentation {
        sd_jwt: core::mem::take(&mut model.sd_jwt),
        disclosures: core::mem::take(&mut model.disclosures),
        kb_jwt: model.kb_jwt.take(),
        vct: model.vct.take(),
        envelope_hash,
    })
}

fn zk_to_proto(model: &vp::ZkPresentation) -> pb::ZkPresentation {
    pb::ZkPresentation {
        freshness: MessageField::some(freshness_to_proto(&model.freshness)),
        credential: MessageField::some(credential_to_proto(&model.credential)),
        disclosures: model.disclosures.iter().map(disclosure_to_proto).collect(),
        zk_proof: MessageField::some(zk_proof_to_proto(&model.zk_proof)),
        qeaa: model
            .qeaa
            .as_ref()
            .map(qeaa_to_proto)
            .map(MessageField::some)
            .unwrap_or_else(MessageField::none),
        ..pb::ZkPresentation::default()
    }
}

fn zk_from_proto(model: &pb::ZkPresentation) -> Result<vp::ZkPresentation, VpProtoError> {
    let freshness = model
        .freshness
        .as_option()
        .ok_or(VpProtoError::MissingField)?;
    let credential = model
        .credential
        .as_option()
        .ok_or(VpProtoError::MissingField)?;
    let zk_proof = model
        .zk_proof
        .as_option()
        .ok_or(VpProtoError::MissingField)?;

    Ok(vp::ZkPresentation {
        freshness: freshness_from_proto(freshness)?,
        credential: credential_from_proto(credential)?,
        disclosures: model
            .disclosures
            .iter()
            .map(disclosure_from_proto)
            .collect::<Result<Vec<_>, _>>()?,
        zk_proof: zk_proof_from_proto(zk_proof)?,
        qeaa: model.qeaa.as_option().map(qeaa_from_proto).transpose()?,
    })
}

fn freshness_to_proto(model: &vp::PresentationFreshness) -> pb::PresentationFreshness {
    pb::PresentationFreshness {
        challenge: Vec::from(model.challenge),
        audience_hash: Vec::from(model.audience_hash),
        expiry_unix: model.expiry_unix,
        ..pb::PresentationFreshness::default()
    }
}

fn freshness_from_proto(
    model: &pb::PresentationFreshness,
) -> Result<vp::PresentationFreshness, VpProtoError> {
    Ok(vp::PresentationFreshness {
        challenge: slice_to_32(&model.challenge)?,
        audience_hash: slice_to_32(&model.audience_hash)?,
        expiry_unix: model.expiry_unix,
    })
}

fn credential_to_proto(model: &vp::CredentialReference) -> pb::CredentialReference {
    pb::CredentialReference {
        envelope_hash: Vec::from(model.envelope_hash),
        issuer_did: model.issuer_did.clone(),
        status: MessageField::some(status_to_proto(&model.status)),
        ..pb::CredentialReference::default()
    }
}

fn credential_from_proto(
    model: &pb::CredentialReference,
) -> Result<vp::CredentialReference, VpProtoError> {
    let status = model.status.as_option().ok_or(VpProtoError::MissingField)?;

    Ok(vp::CredentialReference {
        envelope_hash: slice_to_32(&model.envelope_hash)?,
        issuer_did: model.issuer_did.clone(),
        status: status_from_proto(status)?,
    })
}

fn status_to_proto(model: &vp::CredentialStatusRef) -> pb::CredentialStatusRef {
    pb::CredentialStatusRef {
        status_list_url: model.status_list_url.clone(),
        status_list_id: Vec::from(model.status_list_id),
        status_list_index: model.status_list_index,
        purpose: EnumValue::from(status_purpose_to_proto(model.purpose)),
        ..pb::CredentialStatusRef::default()
    }
}

fn status_from_proto(
    model: &pb::CredentialStatusRef,
) -> Result<vp::CredentialStatusRef, VpProtoError> {
    Ok(vp::CredentialStatusRef {
        status_list_url: model.status_list_url.clone(),
        status_list_id: slice_to_32(&model.status_list_id)?,
        status_list_index: model.status_list_index,
        purpose: status_purpose_from_proto(model.purpose.to_i32())?,
    })
}

fn disclosure_to_proto(model: &vp::ClaimDisclosure) -> pb::ClaimDisclosure {
    pb::ClaimDisclosure {
        claim_path: model.claim_path.clone(),
        mode: EnumValue::from(disclosure_mode_to_proto(model.mode)),
        value: disclosure_value_to_proto(model),
        ..pb::ClaimDisclosure::default()
    }
}

fn disclosure_from_proto(model: &pb::ClaimDisclosure) -> Result<vp::ClaimDisclosure, VpProtoError> {
    let mode = disclosure_mode_from_proto(model.mode.to_i32())?;
    validate_disclosure_value(mode, model.value.as_ref())?;

    let mut disclosure = vp::ClaimDisclosure {
        claim_path: model.claim_path.clone(),
        mode,
        revealed_value: None,
        threshold: None,
        range: None,
        set: None,
    };

    match model.value.as_ref() {
        Some(claim_disclosure::Value::RevealedValue(value)) => {
            disclosure.revealed_value = Some(value.clone());
        }
        Some(claim_disclosure::Value::Threshold(value)) => {
            disclosure.threshold = Some(*value);
        }
        Some(claim_disclosure::Value::Range(value)) => {
            disclosure.range = Some(vp::Range {
                min: value.min,
                max: value.max,
            });
        }
        Some(claim_disclosure::Value::Set(value)) => {
            disclosure.set = Some(vp::ValueSet {
                values: value.values.clone(),
            });
        }
        None => {}
    }

    Ok(disclosure)
}

fn disclosure_value_to_proto(model: &vp::ClaimDisclosure) -> Option<claim_disclosure::Value> {
    if let Some(value) = &model.revealed_value {
        return Some(claim_disclosure::Value::RevealedValue(value.clone()));
    }

    if let Some(value) = model.threshold {
        return Some(claim_disclosure::Value::Threshold(value));
    }

    if let Some(value) = &model.range {
        return Some(claim_disclosure::Value::Range(Box::new(pb::Range {
            min: value.min,
            max: value.max,
            ..pb::Range::default()
        })));
    }

    model.set.as_ref().map(|value| {
        claim_disclosure::Value::Set(Box::new(pb::ValueSet {
            values: value.values.clone(),
            ..pb::ValueSet::default()
        }))
    })
}

fn zk_proof_to_proto(model: &vp::ZkProof) -> pb::ZkProof {
    pb::ZkProof {
        circuit_id: model.circuit_id.clone(),
        circuit_version: model.circuit_version.clone(),
        vk_id: model.vk_id.clone(),
        proof_bytes: model.proof_bytes.clone(),
        public_inputs: model
            .public_inputs
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        proof_suite: EnumValue::from(match model.proof_suite {
            vp::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa => {
                pb::ZkProofSuite::BarretenbergUltrahonkKeccakZkNoIpa
            }
        }),
        artifact_manifest_sha256: model.artifact_manifest_sha256.to_vec(),
        ..pb::ZkProof::default()
    }
}

fn zk_proof_from_proto(model: &pb::ZkProof) -> Result<vp::ZkProof, VpProtoError> {
    let proof_suite = match pb::ZkProofSuite::from_i32(model.proof_suite.to_i32()) {
        Some(pb::ZkProofSuite::BarretenbergUltrahonkKeccakZkNoIpa) => {
            vp::ZkProofSuite::BarretenbergUltraHonkKeccakZkNoIpa
        }
        Some(pb::ZkProofSuite::Unspecified) | None => {
            return Err(VpProtoError::InvalidEnumValue);
        }
    };
    Ok(vp::ZkProof {
        circuit_id: model.circuit_id.clone(),
        circuit_version: model.circuit_version.clone(),
        vk_id: model.vk_id.clone(),
        proof_bytes: model.proof_bytes.clone(),
        public_inputs: model
            .public_inputs
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>(),
        proof_suite,
        artifact_manifest_sha256: slice_to_32(&model.artifact_manifest_sha256)?,
    })
}

fn qeaa_to_proto(model: &vp::QeaaVerifierHints) -> pb::QeaaVerifierHints {
    pb::QeaaVerifierHints {
        required: model.required,
        audit_report_hash: model.audit_report_hash.map(Vec::from),
        max_status_age_seconds: model.max_status_age_seconds,
        ..pb::QeaaVerifierHints::default()
    }
}

fn qeaa_from_proto(model: &pb::QeaaVerifierHints) -> Result<vp::QeaaVerifierHints, VpProtoError> {
    Ok(vp::QeaaVerifierHints {
        required: model.required,
        audit_report_hash: optional_slice_to_32(model.audit_report_hash.as_deref())?,
        max_status_age_seconds: model.max_status_age_seconds,
    })
}

fn status_purpose_to_proto(purpose: vp::StatusPurpose) -> credential_pb::StatusPurpose {
    match purpose {
        vp::StatusPurpose::Unspecified => credential_pb::StatusPurpose::Unspecified,
        vp::StatusPurpose::Revocation => credential_pb::StatusPurpose::Revocation,
        vp::StatusPurpose::Suspension => credential_pb::StatusPurpose::Suspension,
    }
}

fn status_purpose_from_proto(value: i32) -> Result<vp::StatusPurpose, VpProtoError> {
    match credential_pb::StatusPurpose::from_i32(value).ok_or(VpProtoError::InvalidEnumValue)? {
        credential_pb::StatusPurpose::STATUS_PURPOSE_UNSPECIFIED => {
            Err(VpProtoError::InvalidEnumValue)
        }
        credential_pb::StatusPurpose::STATUS_PURPOSE_REVOCATION => {
            Ok(vp::StatusPurpose::Revocation)
        }
        credential_pb::StatusPurpose::STATUS_PURPOSE_SUSPENSION => {
            Ok(vp::StatusPurpose::Suspension)
        }
    }
}

fn disclosure_mode_to_proto(mode: vp::DisclosureMode) -> pb::DisclosureMode {
    match mode {
        vp::DisclosureMode::Unspecified => pb::DisclosureMode::Unspecified,
        vp::DisclosureMode::Hidden => pb::DisclosureMode::Hidden,
        vp::DisclosureMode::Reveal => pb::DisclosureMode::Reveal,
        vp::DisclosureMode::Eq => pb::DisclosureMode::Eq,
        vp::DisclosureMode::Gte => pb::DisclosureMode::Gte,
        vp::DisclosureMode::Lte => pb::DisclosureMode::Lte,
        vp::DisclosureMode::Range => pb::DisclosureMode::Range,
        vp::DisclosureMode::MemberOfSet => pb::DisclosureMode::MemberOfSet,
    }
}

fn disclosure_mode_from_proto(value: i32) -> Result<vp::DisclosureMode, VpProtoError> {
    match pb::DisclosureMode::from_i32(value).ok_or(VpProtoError::InvalidEnumValue)? {
        pb::DisclosureMode::DISCLOSURE_MODE_UNSPECIFIED => Err(VpProtoError::InvalidEnumValue),
        pb::DisclosureMode::DISCLOSURE_MODE_HIDDEN => Ok(vp::DisclosureMode::Hidden),
        pb::DisclosureMode::DISCLOSURE_MODE_REVEAL => Ok(vp::DisclosureMode::Reveal),
        pb::DisclosureMode::DISCLOSURE_MODE_EQ => Ok(vp::DisclosureMode::Eq),
        pb::DisclosureMode::DISCLOSURE_MODE_GTE => Ok(vp::DisclosureMode::Gte),
        pb::DisclosureMode::DISCLOSURE_MODE_LTE => Ok(vp::DisclosureMode::Lte),
        pb::DisclosureMode::DISCLOSURE_MODE_RANGE => Ok(vp::DisclosureMode::Range),
        pb::DisclosureMode::DISCLOSURE_MODE_MEMBER_OF_SET => Ok(vp::DisclosureMode::MemberOfSet),
    }
}

fn optional_slice_to_32(value: Option<&[u8]>) -> Result<Option<[u8; 32]>, VpProtoError> {
    value.map(slice_to_32).transpose()
}

/// Copy a fixed-width field without allocating an intermediate heap buffer
/// that would otherwise be released without zeroization.
fn slice_to_32(value: &[u8]) -> Result<[u8; 32], VpProtoError> {
    <[u8; 32]>::try_from(value).map_err(|_| VpProtoError::InvalidBytesLen)
}
