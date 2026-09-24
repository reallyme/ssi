// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn commitment_limits_from_proto(limits: &pb::CommitmentLimits) -> CommitmentLimits {
    CommitmentLimits {
        max_value_len: limits.max_value_len,
        salt_len: limits.salt_len,
    }
}

fn merkle_tree_info_to_proto(tree: MerkleTreeInfo) -> pb::MerkleTreeInfo {
    pb::MerkleTreeInfo {
        depth: tree.depth,
        count: tree.count,
        ..pb::MerkleTreeInfo::default()
    }
}

fn merkle_tree_info_from_proto(tree: &pb::MerkleTreeInfo) -> MerkleTreeInfo {
    MerkleTreeInfo {
        depth: tree.depth,
        count: tree.count,
    }
}

fn claim_type_to_proto(claim_type: ClaimType) -> pb::ClaimType {
    match claim_type {
        ClaimType::Unspecified => pb::ClaimType::Unspecified,
        ClaimType::String => pb::ClaimType::String,
        ClaimType::Boolean => pb::ClaimType::Boolean,
        ClaimType::Integer => pb::ClaimType::Integer,
        ClaimType::SignedInteger => pb::ClaimType::SignedInteger,
        ClaimType::UnsignedInteger => pb::ClaimType::UnsignedInteger,
        ClaimType::Number => pb::ClaimType::Number,
        ClaimType::Decimal => pb::ClaimType::Decimal,
        ClaimType::Bytes => pb::ClaimType::Bytes,
        ClaimType::Date => pb::ClaimType::Date,
        ClaimType::DateTime => pb::ClaimType::DateTime,
        ClaimType::Null => pb::ClaimType::Null,
        ClaimType::Object => pb::ClaimType::Object,
        ClaimType::Array => pb::ClaimType::Array,
    }
}

fn claim_type_from_proto(value: i32) -> Result<ClaimType, ClaimsError> {
    match pb::ClaimType::from_i32(value).ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::InvalidClaimType,
    ))? {
        pb::ClaimType::Unspecified => Ok(ClaimType::Unspecified),
        pb::ClaimType::String => Ok(ClaimType::String),
        pb::ClaimType::Boolean => Ok(ClaimType::Boolean),
        pb::ClaimType::Integer => Ok(ClaimType::Integer),
        pb::ClaimType::SignedInteger => Ok(ClaimType::SignedInteger),
        pb::ClaimType::UnsignedInteger => Ok(ClaimType::UnsignedInteger),
        pb::ClaimType::Number => Ok(ClaimType::Number),
        pb::ClaimType::Decimal => Ok(ClaimType::Decimal),
        pb::ClaimType::Bytes => Ok(ClaimType::Bytes),
        pb::ClaimType::Date => Ok(ClaimType::Date),
        pb::ClaimType::DateTime => Ok(ClaimType::DateTime),
        pb::ClaimType::Null => Ok(ClaimType::Null),
        pb::ClaimType::Object => Ok(ClaimType::Object),
        pb::ClaimType::Array => Ok(ClaimType::Array),
    }
}

fn disclosure_mode_to_proto(mode: DisclosureMode) -> pb::DisclosureMode {
    match mode {
        DisclosureMode::Unspecified => pb::DisclosureMode::Unspecified,
        DisclosureMode::Hidden => pb::DisclosureMode::Hidden,
        DisclosureMode::Reveal => pb::DisclosureMode::Reveal,
        DisclosureMode::Eq => pb::DisclosureMode::Eq,
        DisclosureMode::Gte => pb::DisclosureMode::Gte,
        DisclosureMode::Lte => pb::DisclosureMode::Lte,
        DisclosureMode::Range => pb::DisclosureMode::Range,
        DisclosureMode::MemberOfSet => pb::DisclosureMode::MemberOfSet,
    }
}

fn disclosure_mode_from_proto(value: i32) -> Result<DisclosureMode, ClaimsError> {
    match pb::DisclosureMode::from_i32(value).ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::InvalidDisclosureMode,
    ))? {
        pb::DisclosureMode::Unspecified => Ok(DisclosureMode::Unspecified),
        pb::DisclosureMode::Hidden => Ok(DisclosureMode::Hidden),
        pb::DisclosureMode::Reveal => Ok(DisclosureMode::Reveal),
        pb::DisclosureMode::Eq => Ok(DisclosureMode::Eq),
        pb::DisclosureMode::Gte => Ok(DisclosureMode::Gte),
        pb::DisclosureMode::Lte => Ok(DisclosureMode::Lte),
        pb::DisclosureMode::Range => Ok(DisclosureMode::Range),
        pb::DisclosureMode::MemberOfSet => Ok(DisclosureMode::MemberOfSet),
    }
}

fn algorithm_to_proto(algorithm: CredentialAlgorithm) -> pb::Algorithm {
    match algorithm {
        CredentialAlgorithm::Unspecified => pb::Algorithm::Unspecified,
        CredentialAlgorithm::Ed25519 => pb::Algorithm::Ed25519,
        CredentialAlgorithm::X25519 => pb::Algorithm::X25519,
        CredentialAlgorithm::P256 => pb::Algorithm::P256,
        CredentialAlgorithm::Secp256k1 => pb::Algorithm::Secp256k1,
        CredentialAlgorithm::Es256kRecovery => pb::Algorithm::Es256kRecovery,
        CredentialAlgorithm::MlDsa65 => pb::Algorithm::MlDsa65,
        CredentialAlgorithm::MlDsa87 => pb::Algorithm::MlDsa87,
        CredentialAlgorithm::MlKem768 => pb::Algorithm::MlKem768,
        CredentialAlgorithm::MlKem1024 => pb::Algorithm::MlKem1024,
        CredentialAlgorithm::MlDsa44 => pb::Algorithm::MlDsa44,
    }
}

fn algorithm_from_proto(value: i32) -> Result<CredentialAlgorithm, ClaimsError> {
    match pb::Algorithm::from_i32(value).ok_or(ClaimsError::InvalidInput(
        ClaimsInvalidReason::InvalidCommitmentMaterial,
    ))? {
        pb::Algorithm::Unspecified => Ok(CredentialAlgorithm::Unspecified),
        pb::Algorithm::Ed25519 => Ok(CredentialAlgorithm::Ed25519),
        pb::Algorithm::X25519 => Ok(CredentialAlgorithm::X25519),
        pb::Algorithm::P256 => Ok(CredentialAlgorithm::P256),
        pb::Algorithm::Secp256k1 => Ok(CredentialAlgorithm::Secp256k1),
        pb::Algorithm::Es256kRecovery => Ok(CredentialAlgorithm::Es256kRecovery),
        pb::Algorithm::MlDsa65 => Ok(CredentialAlgorithm::MlDsa65),
        pb::Algorithm::MlDsa87 => Ok(CredentialAlgorithm::MlDsa87),
        pb::Algorithm::MlKem768 => Ok(CredentialAlgorithm::MlKem768),
        pb::Algorithm::MlKem1024 => Ok(CredentialAlgorithm::MlKem1024),
        pb::Algorithm::MlDsa44 => Ok(CredentialAlgorithm::MlDsa44),
    }
}
