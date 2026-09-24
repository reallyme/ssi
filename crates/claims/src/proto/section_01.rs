// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    validate_claims_commitment, validate_public_key_ref, validate_registry,
    validate_subject_private_bundle, ClaimDefinition, ClaimDisclosurePolicy, ClaimOpening,
    ClaimType, ClaimsCommitment, ClaimsError, ClaimsInvalidReason, ClaimsRegistry,
    CommitmentLimits, CredentialAlgorithm, DisclosureMode, DomainTags, KeyAssurance, KeyReference,
    MerkleTreeInfo, PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization, Signature,
    SubjectPrivateBundle,
};
use buffa::{EnumValue, Enumeration, MessageField};
use reallyme_ssi_proto::generated::proto::identity::credential::v1 as pb;
use std::collections::BTreeMap;

/// Convert a native claims registry into the generated protobuf boundary.
pub fn registry_to_proto(registry: &ClaimsRegistry) -> Result<pb::ClaimsRegistry, ClaimsError> {
    validate_registry(registry)?;
    let mut out = pb::ClaimsRegistry {
        claimset_id: registry.claimset_id.clone(),
        ..pb::ClaimsRegistry::default()
    };
    for (key, value) in &registry.claims {
        out.claims
            .insert(key.clone(), claim_definition_to_proto(value));
    }
    Ok(out)
}

/// Convert a generated claims registry into the native semantic model.
pub fn registry_from_proto(registry: &pb::ClaimsRegistry) -> Result<ClaimsRegistry, ClaimsError> {
    let mut claims = BTreeMap::new();
    for (key, value) in &registry.claims {
        claims.insert(key.clone(), claim_definition_from_proto(value)?);
    }
    let out = ClaimsRegistry {
        claimset_id: registry.claimset_id.clone(),
        claims,
    };
    validate_registry(&out)?;
    Ok(out)
}

/// Convert a native claim definition into the generated protobuf boundary.
pub fn claim_definition_to_proto(definition: &ClaimDefinition) -> pb::ClaimDefinition {
    pb::ClaimDefinition {
        claim_id: definition.claim_id.clone(),
        r#type: EnumValue::from(claim_type_to_proto(definition.claim_type)),
        encoding: definition.encoding.clone(),
        disclosure: MessageField::some(disclosure_policy_to_proto(&definition.disclosure)),
        ..pb::ClaimDefinition::default()
    }
}

/// Convert a generated claim definition into the native semantic model.
pub fn claim_definition_from_proto(
    definition: &pb::ClaimDefinition,
) -> Result<ClaimDefinition, ClaimsError> {
    let disclosure = definition
        .disclosure
        .as_option()
        .ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidDisclosureMode,
        ))?;
    Ok(ClaimDefinition {
        claim_id: definition.claim_id.clone(),
        claim_type: claim_type_from_proto(definition.r#type.to_i32())?,
        encoding: definition.encoding.clone(),
        disclosure: disclosure_policy_from_proto(disclosure)?,
    })
}

/// Convert a native disclosure policy into the generated protobuf boundary.
pub fn disclosure_policy_to_proto(policy: &ClaimDisclosurePolicy) -> pb::ClaimDisclosurePolicy {
    pb::ClaimDisclosurePolicy {
        allow_reveal: policy.allow_reveal,
        predicates: policy
            .predicates
            .iter()
            .copied()
            .map(disclosure_mode_to_proto)
            .map(EnumValue::from)
            .collect(),
        ..pb::ClaimDisclosurePolicy::default()
    }
}

/// Convert a generated disclosure policy into the native semantic model.
pub fn disclosure_policy_from_proto(
    policy: &pb::ClaimDisclosurePolicy,
) -> Result<ClaimDisclosurePolicy, ClaimsError> {
    Ok(ClaimDisclosurePolicy {
        allow_reveal: policy.allow_reveal,
        predicates: policy
            .predicates
            .iter()
            .map(|mode| disclosure_mode_from_proto(mode.to_i32()))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Convert a native claims commitment into the generated protobuf boundary.
pub fn claims_commitment_to_proto(
    commitment: &ClaimsCommitment,
) -> Result<pb::ClaimsCommitment, ClaimsError> {
    validate_claims_commitment(commitment)?;
    Ok(pb::ClaimsCommitment {
        merkle_root: commitment.merkle_root.clone(),
        claimset_id: commitment.claimset_id.clone(),
        hash_alg: commitment.hash_alg.clone(),
        value_encoding: commitment.value_encoding.clone(),
        domain_tags: MessageField::some(domain_tags_to_proto(&commitment.domain_tags)),
        limits: MessageField::some(commitment_limits_to_proto(commitment.limits)),
        ..pb::ClaimsCommitment::default()
    })
}

/// Convert a generated claims commitment into the native semantic model.
pub fn claims_commitment_from_proto(
    commitment: &pb::ClaimsCommitment,
) -> Result<ClaimsCommitment, ClaimsError> {
    let domain_tags = commitment
        .domain_tags
        .as_option()
        .ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentDomainTags,
        ))?;
    let limits = commitment
        .limits
        .as_option()
        .ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentMaterial,
        ))?;
    let out = ClaimsCommitment {
        merkle_root: commitment.merkle_root.clone(),
        claimset_id: commitment.claimset_id.clone(),
        hash_alg: commitment.hash_alg.clone(),
        value_encoding: commitment.value_encoding.clone(),
        domain_tags: domain_tags_from_proto(domain_tags),
        limits: commitment_limits_from_proto(limits),
    };
    validate_claims_commitment(&out)?;
    Ok(out)
}

/// Convert a holder-private bundle into the generated protobuf boundary.
pub fn subject_private_bundle_to_proto(
    commitment: &ClaimsCommitment,
    bundle: &SubjectPrivateBundle,
) -> Result<pb::SubjectPrivateBundle, ClaimsError> {
    validate_subject_private_bundle(commitment, bundle)?;
    Ok(pb::SubjectPrivateBundle {
        holder_key: bundle
            .holder_key
            .as_ref()
            .map(public_key_ref_to_proto)
            .into(),
        envelope_hash: bundle.envelope_hash.clone(),
        issuer_signature: MessageField::some(signature_to_proto(&bundle.issuer_signature)),
        tree: MessageField::some(merkle_tree_info_to_proto(bundle.tree)),
        claims: bundle.claims.iter().map(claim_opening_to_proto).collect(),
        ..pb::SubjectPrivateBundle::default()
    })
}

/// Convert a generated holder-private bundle into the native semantic model.
pub fn subject_private_bundle_from_proto(
    commitment: &ClaimsCommitment,
    bundle: &pb::SubjectPrivateBundle,
) -> Result<SubjectPrivateBundle, ClaimsError> {
    let tree = bundle.tree.as_option().ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::InvalidPrivateBundleTree,
    ))?;
    let issuer_signature = bundle
        .issuer_signature
        .as_option()
        .ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentMaterial,
        ))?;
    let out = SubjectPrivateBundle {
        holder_key: bundle
            .holder_key
            .as_option()
            .map(public_key_ref_from_proto)
            .transpose()?,
        envelope_hash: bundle.envelope_hash.clone(),
        issuer_signature: signature_from_proto(issuer_signature)?,
        tree: merkle_tree_info_from_proto(tree),
        claims: bundle.claims.iter().map(claim_opening_from_proto).collect(),
    };
    validate_subject_private_bundle(commitment, &out)?;
    Ok(out)
}

fn claim_opening_to_proto(opening: &ClaimOpening) -> pb::ClaimOpening {
    pb::ClaimOpening {
        claim_path: opening.claim_path.clone(),
        salt: opening.salt.clone(),
        value: opening.value.clone(),
        index: opening.index,
        merkle_path: opening.merkle_path.clone(),
        ..pb::ClaimOpening::default()
    }
}

/// Convert a semantic public key reference into its protobuf boundary.
pub fn public_key_ref_to_proto(key: &PublicKeyRef) -> pb::PublicKeyRef {
    pb::PublicKeyRef {
        reference: MessageField::some(key_reference_to_proto(&key.reference)),
        public_key: MessageField::some(public_key_material_to_proto(key.alg, &key.public_key)),
        assurance: MessageField::some(key_assurance_to_proto(&key.assurance)),
        ..pb::PublicKeyRef::default()
    }
}

/// Convert and validate a protobuf public key reference.
pub fn public_key_ref_from_proto(key: &pb::PublicKeyRef) -> Result<PublicKeyRef, ClaimsError> {
    let reference = key.reference.as_option().ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::InvalidCommitmentMaterial,
    ))?;
    let public_key = key.public_key.as_option().ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::InvalidCommitmentMaterial,
    ))?;
    let assurance = key.assurance.as_option().ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::InvalidCommitmentMaterial,
    ))?;
    let out = PublicKeyRef {
        alg: algorithm_from_proto(public_key.alg.to_i32())?,
        reference: key_reference_from_proto(reference)?,
        public_key: public_key_material_from_proto(public_key)?.1,
        assurance: key_assurance_from_proto(assurance)?,
    };
    validate_public_key_ref(&out)?;
    Ok(out)
}

fn signature_to_proto(signature: &Signature) -> pb::Signature {
    pb::Signature {
        verification_key: MessageField::some(public_key_ref_to_proto(&signature.verification_key)),
        raw_rs: signature.raw_rs.clone(),
        ..pb::Signature::default()
    }
}

fn signature_from_proto(signature: &pb::Signature) -> Result<Signature, ClaimsError> {
    let verification_key =
        signature
            .verification_key
            .as_option()
            .ok_or(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidCommitmentMaterial,
            ))?;
    Ok(Signature {
        verification_key: public_key_ref_from_proto(verification_key)?,
        raw_rs: signature.raw_rs.clone(),
    })
}

/// Convert algorithm-tagged public material into protobuf.
pub fn public_key_material_to_proto(
    algorithm: CredentialAlgorithm,
    public_key: &PublicKeyRepresentation,
) -> pb::PublicKeyMaterial {
    use pb::__buffa::oneof::public_key_material::Representation;

    let representation = match public_key {
        PublicKeyRepresentation::JwkJson(value) => Representation::JwkJson(value.clone()),
        PublicKeyRepresentation::CoseKey(value) => Representation::CoseKey(value.clone()),
        PublicKeyRepresentation::Multikey(value) => Representation::Multikey(value.clone()),
        PublicKeyRepresentation::SubjectPublicKeyInfoDer(value) => {
            Representation::SubjectPublicKeyInfoDer(value.clone())
        }
        PublicKeyRepresentation::Raw {
            serialization,
            bytes,
        } => Representation::Raw(Box::new(pb::RawPublicKey {
            serialization: EnumValue::from(raw_serialization_to_proto(*serialization)),
            bytes: bytes.clone(),
            ..pb::RawPublicKey::default()
        })),
    };
    pb::PublicKeyMaterial {
        alg: EnumValue::from(algorithm_to_proto(algorithm)),
        representation: Some(representation),
        ..pb::PublicKeyMaterial::default()
    }
}

/// Convert protobuf public material into its algorithm and representation.
pub fn public_key_material_from_proto(
    key: &pb::PublicKeyMaterial,
) -> Result<(CredentialAlgorithm, PublicKeyRepresentation), ClaimsError> {
    use pb::__buffa::oneof::public_key_material::Representation;

    let algorithm = algorithm_from_proto(key.alg.to_i32())?;
    let representation = match key
        .representation
        .as_ref()
        .ok_or(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentMaterial,
        ))? {
        Representation::JwkJson(value) => PublicKeyRepresentation::JwkJson(value.clone()),
        Representation::CoseKey(value) => PublicKeyRepresentation::CoseKey(value.clone()),
        Representation::Multikey(value) => PublicKeyRepresentation::Multikey(value.clone()),
        Representation::SubjectPublicKeyInfoDer(value) => {
            PublicKeyRepresentation::SubjectPublicKeyInfoDer(value.clone())
        }
        Representation::Raw(value) => PublicKeyRepresentation::Raw {
            serialization: raw_serialization_from_proto(value.serialization.to_i32())?,
            bytes: value.bytes.clone(),
        },
    };
    Ok((algorithm, representation))
}

fn key_reference_to_proto(reference: &KeyReference) -> pb::KeyReference {
    use pb::__buffa::oneof::key_reference::Kind;

    let kind = match reference {
        KeyReference::DidVerificationMethod(value) => Kind::DidVerificationMethod(value.clone()),
        KeyReference::X509Certificate(value) => Kind::X509CertificateDer(value.clone()),
        KeyReference::DirectPublicKey => Kind::DirectPublicKey(Box::default()),
    };
    pb::KeyReference {
        kind: Some(kind),
        ..pb::KeyReference::default()
    }
}

fn key_reference_from_proto(reference: &pb::KeyReference) -> Result<KeyReference, ClaimsError> {
    use pb::__buffa::oneof::key_reference::Kind;

    match reference.kind.as_ref().ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::InvalidCommitmentMaterial,
    ))? {
        Kind::DidVerificationMethod(value) => {
            Ok(KeyReference::DidVerificationMethod(value.clone()))
        }
        Kind::X509CertificateDer(value) => Ok(KeyReference::X509Certificate(value.clone())),
        Kind::DirectPublicKey(_) => Ok(KeyReference::DirectPublicKey),
    }
}

fn key_assurance_to_proto(assurance: &KeyAssurance) -> pb::KeyAssurance {
    use pb::__buffa::oneof::key_assurance::Kind;

    let kind = match assurance {
        KeyAssurance::None => Kind::None(Box::default()),
        KeyAssurance::KeyAttestation(value) => Kind::KeyAttestation(value.clone()),
        KeyAssurance::HardwareAttestation(value) => Kind::HardwareAttestation(value.clone()),
        KeyAssurance::X509Chain(values) => Kind::X509Chain(Box::new(pb::X509CertificateChain {
            certificates_der: values.clone(),
            ..pb::X509CertificateChain::default()
        })),
    };
    pb::KeyAssurance {
        kind: Some(kind),
        ..pb::KeyAssurance::default()
    }
}

fn key_assurance_from_proto(assurance: &pb::KeyAssurance) -> Result<KeyAssurance, ClaimsError> {
    use pb::__buffa::oneof::key_assurance::Kind;

    match assurance.kind.as_ref().ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::InvalidCommitmentMaterial,
    ))? {
        Kind::None(_) => Ok(KeyAssurance::None),
        Kind::KeyAttestation(value) => Ok(KeyAssurance::KeyAttestation(value.clone())),
        Kind::HardwareAttestation(value) => Ok(KeyAssurance::HardwareAttestation(value.clone())),
        Kind::X509Chain(value) => Ok(KeyAssurance::X509Chain(value.certificates_der.clone())),
    }
}

fn raw_serialization_to_proto(value: RawPublicKeySerialization) -> pb::RawPublicKeySerialization {
    match value {
        RawPublicKeySerialization::FixedWidth => pb::RawPublicKeySerialization::FixedWidth,
        RawPublicKeySerialization::Sec1Compressed => pb::RawPublicKeySerialization::Sec1Compressed,
        RawPublicKeySerialization::Sec1Uncompressed => {
            pb::RawPublicKeySerialization::Sec1Uncompressed
        }
    }
}

fn raw_serialization_from_proto(value: i32) -> Result<RawPublicKeySerialization, ClaimsError> {
    match pb::RawPublicKeySerialization::from_i32(value) {
        Some(pb::RawPublicKeySerialization::FixedWidth) => {
            Ok(RawPublicKeySerialization::FixedWidth)
        }
        Some(pb::RawPublicKeySerialization::Sec1Compressed) => {
            Ok(RawPublicKeySerialization::Sec1Compressed)
        }
        Some(pb::RawPublicKeySerialization::Sec1Uncompressed) => {
            Ok(RawPublicKeySerialization::Sec1Uncompressed)
        }
        _ => Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentMaterial,
        )),
    }
}

fn claim_opening_from_proto(opening: &pb::ClaimOpening) -> ClaimOpening {
    ClaimOpening {
        claim_path: opening.claim_path.clone(),
        salt: opening.salt.clone(),
        value: opening.value.clone(),
        index: opening.index,
        merkle_path: opening.merkle_path.clone(),
    }
}

fn domain_tags_to_proto(tags: &DomainTags) -> pb::DomainTags {
    pb::DomainTags {
        clm: tags.clm.clone(),
        leaf: tags.leaf.clone(),
        node: tags.node.clone(),
        ..pb::DomainTags::default()
    }
}

fn domain_tags_from_proto(tags: &pb::DomainTags) -> DomainTags {
    DomainTags {
        clm: tags.clm.clone(),
        leaf: tags.leaf.clone(),
        node: tags.node.clone(),
    }
}

fn commitment_limits_to_proto(limits: CommitmentLimits) -> pb::CommitmentLimits {
    pb::CommitmentLimits {
        max_value_len: limits.max_value_len,
        salt_len: limits.salt_len,
        ..pb::CommitmentLimits::default()
    }
}
