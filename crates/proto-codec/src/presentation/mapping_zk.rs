// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, MessageField};
use reallyme_ssi_proto::generated::proto::identity::presentation::v1 as pb;
use reallyme_ssi_proto::generated::proto::identity::presentation::v1::__buffa::oneof::{
    zk_persona_presentation, zk_presentation,
};
use reallyme_vp_core as vp;

use crate::presentation::VpProtoError;

use super::{
    credential_from_proto, credential_to_proto, disclosure_from_proto, disclosure_to_proto,
    freshness_from_proto, freshness_to_proto, qeaa_from_proto, qeaa_to_proto, zk_proof_from_proto,
    zk_proof_to_proto,
};

pub(super) fn zk_to_proto(model: &vp::ZkPresentation) -> Result<pb::ZkPresentation, VpProtoError> {
    match model {
        vp::ZkPresentation::Credential(value) => Ok(pb::ZkPresentation {
            freshness: MessageField::some(freshness_to_proto(&value.freshness)),
            credential: MessageField::some(credential_to_proto(&value.credential)?),
            disclosures: value
                .disclosures
                .iter()
                .map(disclosure_to_proto)
                .collect::<Result<_, _>>()?,
            zk_proof: MessageField::some(zk_proof_to_proto(&value.zk_proof)?),
            qeaa: value
                .qeaa
                .as_ref()
                .map(qeaa_to_proto)
                .map(MessageField::some)
                .unwrap_or_else(MessageField::none),
            ..pb::ZkPresentation::default()
        }),
        vp::ZkPresentation::Persona(value) => {
            let evidence = match &value.evidence {
                vp::ZkPersonaEvidence::RequestBound { proof_package } => {
                    zk_persona_presentation::Evidence::RequestBoundProofPackage(
                        proof_package.clone(),
                    )
                }
                vp::ZkPersonaEvidence::Prepared(prepared) => {
                    zk_persona_presentation::Evidence::Prepared(Box::new(
                        pb::ZkPreparedPersonaEvidence {
                            prepared_evidence_package: prepared.prepared_evidence_package.clone(),
                            current_state_package: prepared.current_state_package.clone(),
                            verifier_request: prepared.verifier_request.clone(),
                            holder_authentication: prepared.holder_authentication.clone(),
                            holder_public_key: prepared.holder_public_key.to_vec(),
                            holder_signature: prepared.holder_signature.to_vec(),
                            ..pb::ZkPreparedPersonaEvidence::default()
                        },
                    ))
                }
                // New evidence forms need an explicit wire mapping.
                _ => return Err(VpProtoError::InvalidEnumValue),
            };
            Ok(pb::ZkPresentation {
                additional_profile: Some(zk_presentation::AdditionalProfile::Persona(Box::new(
                    pb::ZkPersonaPresentation {
                        freshness: MessageField::some(freshness_to_proto(&value.freshness)),
                        mode: EnumValue::from(persona_mode_to_proto(value.mode)?),
                        disclosures: value
                            .disclosures
                            .iter()
                            .map(disclosure_to_proto)
                            .collect::<Result<_, _>>()?,
                        evidence: Some(evidence),
                        ..pb::ZkPersonaPresentation::default()
                    },
                ))),
                ..pb::ZkPresentation::default()
            })
        }
        vp::ZkPresentation::CommonRoot(value) => Ok(pb::ZkPresentation {
            additional_profile: Some(zk_presentation::AdditionalProfile::CommonRoot(Box::new(
                pb::ZkCommonRootPresentation {
                    freshness: MessageField::some(freshness_to_proto(&value.freshness)),
                    mode: EnumValue::from(persona_mode_to_proto(value.mode)?),
                    disclosures: value
                        .disclosures
                        .iter()
                        .map(disclosure_to_proto)
                        .collect::<Result<_, _>>()?,
                    proof_package: value.proof_package.clone(),
                    ..pb::ZkCommonRootPresentation::default()
                },
            ))),
            ..pb::ZkPresentation::default()
        }),
        // New proof statements need an explicit wire mapping.
        _ => Err(VpProtoError::InvalidEnumValue),
    }
}

pub(super) fn zk_from_proto(
    model: &pb::ZkPresentation,
) -> Result<vp::ZkPresentation, VpProtoError> {
    match model.additional_profile.as_ref() {
        None => Ok(vp::ZkPresentation::Credential(
            vp::ZkCredentialPresentation {
                freshness: freshness_from_proto(
                    model
                        .freshness
                        .as_option()
                        .ok_or(VpProtoError::MissingField)?,
                )?,
                credential: credential_from_proto(
                    model
                        .credential
                        .as_option()
                        .ok_or(VpProtoError::MissingField)?,
                )?,
                disclosures: model
                    .disclosures
                    .iter()
                    .map(disclosure_from_proto)
                    .collect::<Result<Vec<_>, _>>()?,
                zk_proof: zk_proof_from_proto(
                    model
                        .zk_proof
                        .as_option()
                        .ok_or(VpProtoError::MissingField)?,
                )?,
                qeaa: model.qeaa.as_option().map(qeaa_from_proto).transpose()?,
            },
        )),
        Some(zk_presentation::AdditionalProfile::Persona(value)) => {
            reject_mixed_profile(model)?;
            let evidence = match value.evidence.as_ref().ok_or(VpProtoError::MissingField)? {
                zk_persona_presentation::Evidence::RequestBoundProofPackage(proof_package) => {
                    if proof_package.is_empty() {
                        return Err(VpProtoError::MissingField);
                    }
                    vp::ZkPersonaEvidence::RequestBound {
                        proof_package: proof_package.clone(),
                    }
                }
                zk_persona_presentation::Evidence::Prepared(prepared) => {
                    if prepared.prepared_evidence_package.is_empty()
                        || prepared.current_state_package.is_empty()
                        || prepared.verifier_request.is_empty()
                        || prepared.holder_authentication.is_empty()
                    {
                        return Err(VpProtoError::MissingField);
                    }
                    vp::ZkPersonaEvidence::Prepared(vp::ZkPreparedPersonaEvidence {
                        prepared_evidence_package: prepared.prepared_evidence_package.clone(),
                        current_state_package: prepared.current_state_package.clone(),
                        verifier_request: prepared.verifier_request.clone(),
                        holder_authentication: prepared.holder_authentication.clone(),
                        holder_public_key: prepared
                            .holder_public_key
                            .as_slice()
                            .try_into()
                            .map_err(|_| VpProtoError::InvalidBytesLen)?,
                        holder_signature: prepared
                            .holder_signature
                            .as_slice()
                            .try_into()
                            .map_err(|_| VpProtoError::InvalidBytesLen)?,
                    })
                }
            };
            Ok(vp::ZkPresentation::Persona(vp::ZkPersonaPresentation {
                freshness: freshness_from_proto(
                    value
                        .freshness
                        .as_option()
                        .ok_or(VpProtoError::MissingField)?,
                )?,
                mode: persona_mode_from_proto(value.mode)?,
                disclosures: value
                    .disclosures
                    .iter()
                    .map(disclosure_from_proto)
                    .collect::<Result<Vec<_>, _>>()?,
                evidence,
            }))
        }
        Some(zk_presentation::AdditionalProfile::CommonRoot(value)) => {
            reject_mixed_profile(model)?;
            if value.proof_package.is_empty() {
                return Err(VpProtoError::MissingField);
            }
            Ok(vp::ZkPresentation::CommonRoot(
                vp::ZkCommonRootPresentation {
                    freshness: freshness_from_proto(
                        value
                            .freshness
                            .as_option()
                            .ok_or(VpProtoError::MissingField)?,
                    )?,
                    mode: persona_mode_from_proto(value.mode)?,
                    disclosures: value
                        .disclosures
                        .iter()
                        .map(disclosure_from_proto)
                        .collect::<Result<Vec<_>, _>>()?,
                    proof_package: value.proof_package.clone(),
                },
            ))
        }
    }
}

fn reject_mixed_profile(model: &pb::ZkPresentation) -> Result<(), VpProtoError> {
    if model.freshness.as_option().is_some()
        || model.credential.as_option().is_some()
        || !model.disclosures.is_empty()
        || model.zk_proof.as_option().is_some()
        || model.qeaa.as_option().is_some()
    {
        return Err(VpProtoError::InvalidEnumValue);
    }
    Ok(())
}
fn persona_mode_to_proto(mode: vp::ZkPersonaMode) -> Result<pb::ZkPersonaMode, VpProtoError> {
    match mode {
        vp::ZkPersonaMode::Private => Ok(pb::ZkPersonaMode::Private),
        vp::ZkPersonaMode::Public => Ok(pb::ZkPersonaMode::Public),
        _ => Err(VpProtoError::InvalidEnumValue),
    }
}

fn persona_mode_from_proto(
    mode: EnumValue<pb::ZkPersonaMode>,
) -> Result<vp::ZkPersonaMode, VpProtoError> {
    match mode.as_known() {
        Some(pb::ZkPersonaMode::Private) => Ok(vp::ZkPersonaMode::Private),
        Some(pb::ZkPersonaMode::Public) => Ok(vp::ZkPersonaMode::Public),
        _ => Err(VpProtoError::InvalidEnumValue),
    }
}
