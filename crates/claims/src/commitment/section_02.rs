// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

impl ZeroizeOnDrop for ClaimsCommitment {}

impl Zeroize for DomainTags {
    fn zeroize(&mut self) {
        self.clm.zeroize();
        self.leaf.zeroize();
        self.node.zeroize();
    }
}

impl Drop for DomainTags {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DomainTags {}

impl Zeroize for SubjectPrivateBundle {
    fn zeroize(&mut self) {
        self.holder_key.zeroize();
        self.envelope_hash.zeroize();
        self.issuer_signature.zeroize();
        self.claims.zeroize();
    }
}

impl Drop for SubjectPrivateBundle {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SubjectPrivateBundle {}

impl Zeroize for PublicKeyRef {
    fn zeroize(&mut self) {
        self.alg = CredentialAlgorithm::Unspecified;
        self.reference.zeroize();
        self.public_key.zeroize();
        self.assurance.zeroize();
    }
}

impl Drop for PublicKeyRef {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PublicKeyRef {}

impl Zeroize for Signature {
    fn zeroize(&mut self) {
        self.verification_key.zeroize();
        self.raw_rs.zeroize();
    }
}

impl Drop for Signature {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Signature {}

impl Zeroize for PublicKeyRepresentation {
    fn zeroize(&mut self) {
        match self {
            Self::JwkJson(value) | Self::CoseKey(value) | Self::SubjectPublicKeyInfoDer(value) => {
                value.zeroize();
            }
            Self::Multikey(value) => value.zeroize(),
            Self::Raw { bytes, .. } => bytes.zeroize(),
        }
    }
}

impl Drop for PublicKeyRepresentation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PublicKeyRepresentation {}

impl Zeroize for KeyReference {
    fn zeroize(&mut self) {
        match self {
            Self::DidVerificationMethod(value) => value.zeroize(),
            Self::X509Certificate(value) => value.zeroize(),
            Self::DirectPublicKey => {}
        }
    }
}

impl Drop for KeyReference {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyReference {}

impl Zeroize for KeyAssurance {
    fn zeroize(&mut self) {
        match self {
            Self::None => {}
            Self::KeyAttestation(value) | Self::HardwareAttestation(value) => value.zeroize(),
            Self::X509Chain(values) => values.zeroize(),
        }
    }
}

impl Drop for KeyAssurance {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyAssurance {}

impl Zeroize for ClaimOpening {
    fn zeroize(&mut self) {
        self.claim_path.zeroize();
        self.salt.zeroize();
        self.value.zeroize();
        self.merkle_path.zeroize();
    }
}

impl Drop for ClaimOpening {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ClaimOpening {}

/// Return the default claim commitment resource limits.
pub fn default_commitment_limits() -> CommitmentLimits {
    CommitmentLimits {
        max_value_len: DEFAULT_COMMITMENT_MAX_VALUE_LEN,
        salt_len: DEFAULT_COMMITMENT_SALT_LEN,
    }
}

/// Return the default domain separation tags used for new commitments.
pub fn default_commitment_domain_tags() -> DomainTags {
    DomainTags {
        clm: "RMCLM1".to_owned(),
        leaf: "RMLEAF1".to_owned(),
        node: "RMNODE1".to_owned(),
    }
}

/// Build a production-grade claim commitment and matching private openings.
pub fn build_claims_commitment(
    input: ClaimCommitmentBuildInput<'_>,
    salt_source: &mut dyn ClaimSaltSource,
) -> Result<BuiltClaimsCommitment, ClaimsError> {
    validate_claim_payload(input.registry, input.payload)?;
    validate_commitment_limits(input.limits)?;
    validate_domain_tags(&input.domain_tags)?;
    validate_hash(input.envelope_hash.as_slice())?;
    if let Some(holder_key) = &input.holder_key {
        validate_public_key_ref(holder_key)?;
    }
    validate_signature(&input.issuer_signature)?;

    let salt_len = usize::try_from(input.limits.salt_len)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentMaterial))?;
    let max_value_len = usize::try_from(input.limits.max_value_len)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentMaterial))?;

    let mut leaves = Vec::with_capacity(input.registry.claims.len());
    let mut openings = Vec::with_capacity(input.registry.claims.len());

    for definition in input.registry.claims.values() {
        let Some(path_text) = claim_path(definition.claim_id.as_str()) else {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidClaimPath,
            ));
        };
        let path = parse_claim_path(path_text.as_str())?;
        let Some(value) = input.payload.resolve_path(&path)? else {
            continue;
        };

        validate_claim_value(definition, value)?;
        let canonical_value = canonical_typed_claim_value_bytes(definition.claim_type, value)?;
        if canonical_value.len() > max_value_len {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::ClaimValueLimitExceeded,
            ));
        }

        let mut salt = vec![0_u8; salt_len];
        salt_source.fill_salt(path_text.as_str(), salt.as_mut_slice())?;
        let leaf = claim_leaf_hash(
            &input.domain_tags,
            path_text.as_str(),
            canonical_value.as_slice(),
            salt.as_slice(),
        )?;
        let index = u32::try_from(openings.len())
            .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::TooManyClaims))?;

        leaves.push(leaf);
        openings.push(ClaimOpening {
            claim_path: path_text,
            salt,
            value: canonical_value,
            index,
            merkle_path: Vec::new(),
        });
    }

    if leaves.is_empty() {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    }

    let tree = build_merkle_tree(&input.domain_tags, leaves)?;
    for opening in &mut openings {
        let index = usize::try_from(opening.index).map_err(|_| {
            ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidPrivateBundleTree)
        })?;
        opening.merkle_path = merkle_proof_for_index(&tree.levels, index)?;
    }

    let count = u32::try_from(openings.len())
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::TooManyClaims))?;
    let commitment = ClaimsCommitment {
        merkle_root: tree.root,
        claimset_id: input.registry.claimset_id.clone(),
        hash_alg: CLAIM_COMMITMENT_HASH_ALG_SHA256.to_owned(),
        value_encoding: CLAIM_COMMITMENT_VALUE_ENCODING.to_owned(),
        domain_tags: input.domain_tags,
        limits: input.limits,
    };
    let bundle = SubjectPrivateBundle {
        holder_key: input.holder_key,
        envelope_hash: input.envelope_hash,
        issuer_signature: input.issuer_signature,
        tree: MerkleTreeInfo {
            depth: tree.depth,
            count,
        },
        claims: openings,
    };

    verify_subject_private_bundle(&commitment, &bundle)?;
    Ok(BuiltClaimsCommitment { commitment, bundle })
}

/// Validate public claims commitment metadata.
pub fn validate_claims_commitment(commitment: &ClaimsCommitment) -> Result<(), ClaimsError> {
    validate_hash(commitment.merkle_root.as_slice())?;
    validate_required_label(commitment.claimset_id.as_str(), MAX_CLAIM_BYTES_VALUE_BYTES)?;
    validate_required_label(commitment.hash_alg.as_str(), MAX_COMMITMENT_LABEL_BYTES)?;
    validate_required_label(
        commitment.value_encoding.as_str(),
        MAX_COMMITMENT_LABEL_BYTES,
    )?;
    validate_domain_tags(&commitment.domain_tags)?;
    validate_commitment_limits(commitment.limits)
}

/// Validate a holder-private claim bundle against a public commitment.
pub fn validate_subject_private_bundle(
    commitment: &ClaimsCommitment,
    bundle: &SubjectPrivateBundle,
) -> Result<(), ClaimsError> {
    validate_claims_commitment(commitment)?;
    validate_hash(bundle.envelope_hash.as_slice())?;
    if let Some(holder_key) = &bundle.holder_key {
        validate_public_key_ref(holder_key)?;
    }
    validate_signature(&bundle.issuer_signature)?;
    if bundle.claims.len() > MAX_CLAIM_OPENINGS_PER_BUNDLE {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::TooManyClaims,
        ));
    }
    let count = usize::try_from(bundle.tree.count)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidPrivateBundleTree))?;
    if count != bundle.claims.len() {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    }
    for opening in &bundle.claims {
        validate_claim_opening(commitment, opening)?;
    }

    Ok(())
}

/// Verify every holder-private opening against a public claim commitment.
pub fn verify_subject_private_bundle(
    commitment: &ClaimsCommitment,
    bundle: &SubjectPrivateBundle,
) -> Result<(), ClaimsError> {
    validate_subject_private_bundle(commitment, bundle)?;
    validate_supported_commitment(commitment)?;
    if bundle.tree.count == 0 || bundle.claims.is_empty() {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    }

    let mut seen_paths = BTreeSet::new();
    let mut seen_indexes = BTreeSet::new();
    for opening in &bundle.claims {
        if !seen_paths.insert(opening.claim_path.as_str()) || !seen_indexes.insert(opening.index) {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidPrivateBundleTree,
            ));
        }
        verify_claim_opening(commitment, &bundle.tree, opening)?;
    }

    Ok(())
}

/// Verify one holder-private opening against a public claim commitment.
///
/// `tree` is the Merkle shape recorded in the holder-private bundle. The
/// opening index must address a real leaf and the sibling path must have
/// exactly the depth implied by the leaf count, so a truncated or padded path
/// cannot be presented as an opening.
pub fn verify_claim_opening(
    commitment: &ClaimsCommitment,
    tree: &MerkleTreeInfo,
    opening: &ClaimOpening,
) -> Result<(), ClaimsError> {
    validate_claim_opening(commitment, opening)?;
    validate_supported_commitment(commitment)?;
    validate_opening_tree_position(tree, opening)?;

    let mut node = claim_leaf_hash(
        &commitment.domain_tags,
        opening.claim_path.as_str(),
        &opening.value,
        &opening.salt,
    )?;
    let mut index = opening.index;
    for sibling in &opening.merkle_path {
        node = if index.is_multiple_of(2) {
            merkle_node_hash(&commitment.domain_tags, node.as_slice(), sibling.as_slice())?
        } else {
            merkle_node_hash(&commitment.domain_tags, sibling.as_slice(), node.as_slice())?
        };
        index /= 2;
    }

    if node == commitment.merkle_root {
        Ok(())
    } else {
        Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentProof,
        ))
    }
}

fn validate_opening_tree_position(
    tree: &MerkleTreeInfo,
    opening: &ClaimOpening,
) -> Result<(), ClaimsError> {
    let count = usize::try_from(tree.count)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidPrivateBundleTree))?;
    if count == 0 || count > MAX_CLAIM_OPENINGS_PER_BUNDLE {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    }
    if tree.depth != merkle_depth_for_leaf_count(count)? {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    }
    let depth = usize::try_from(tree.depth)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidPrivateBundleTree))?;
    let index = usize::try_from(opening.index)
        .map_err(|_| ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidPrivateBundleTree))?;
    if index >= count || opening.merkle_path.len() != depth {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidPrivateBundleTree,
        ));
    }
    Ok(())
}

/// Validate a public key's independent reference, representation, and
/// assurance axes without resolving external trust data.
pub fn validate_public_key_ref(key: &PublicKeyRef) -> Result<(), ClaimsError> {
    if matches!(key.alg, CredentialAlgorithm::Unspecified)
        || !valid_key_reference(&key.reference)
        || !valid_key_assurance(&key.assurance)
    {
        return Err(ClaimsError::InvalidInput(
            ClaimsInvalidReason::InvalidCommitmentMaterial,
        ));
    }
    validate_public_key_representation(key.alg, &key.public_key)?;
    if let KeyReference::X509Certificate(certificate_der) = &key.reference {
        let certificate_public_key =
            certificate_subject_public_key_info(certificate_der).map_err(|_| {
                ClaimsError::InvalidInput(ClaimsInvalidReason::InvalidCommitmentMaterial)
            })?;
        let public_key = decode_public_key_bytes(&key.public_key)?;
        if !subject_public_key_algorithm_matches(key.alg, certificate_public_key.algorithm)
            || certificate_public_key.public_key.as_slice() != public_key.as_slice()
        {
            return Err(ClaimsError::InvalidInput(
                ClaimsInvalidReason::InvalidCommitmentMaterial,
            ));
        }
    }
    Ok(())
}

/// Normalize a validated public-key representation to the algorithm-specific
/// bytes consumed by cryptographic providers.
pub fn public_key_bytes(key: &PublicKeyRef) -> Result<Vec<u8>, ClaimsError> {
    validate_public_key_ref(key)?;
    decode_public_key_bytes(&key.public_key)
}
