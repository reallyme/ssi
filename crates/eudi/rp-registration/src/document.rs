// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::json::canonical_json;
use crate::{
    ArtifactDigest, BoundedText, ProtocolProfile, RegistrationError, RegistrationErrorReason,
    WalletRelyingParty,
};

/// Strictly encoded registrar document bound to local desired state.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PreparedRegistrarRegistrationDocument {
    profile: ProtocolProfile,
    internal_relying_party_id: BoundedText,
    desired_state_revision: u64,
    normalized_content_digest: ArtifactDigest,
    encoded_document_digest: ArtifactDigest,
    encoded_document: Vec<u8>,
}

impl PreparedRegistrarRegistrationDocument {
    /// Returns the exact encoder profile.
    #[must_use]
    pub const fn profile(&self) -> ProtocolProfile {
        self.profile
    }

    /// Returns the local RP identifier bound to this document.
    #[must_use]
    pub fn internal_relying_party_id(&self) -> &str {
        self.internal_relying_party_id.expose()
    }

    /// Returns the non-zero desired-state revision.
    #[must_use]
    pub const fn desired_state_revision(&self) -> u64 {
        self.desired_state_revision
    }

    /// Returns the digest of normalized WRP content.
    #[must_use]
    pub const fn normalized_content_digest(&self) -> ArtifactDigest {
        self.normalized_content_digest
    }

    /// Returns the digest of exact transport bytes.
    #[must_use]
    pub const fn encoded_document_digest(&self) -> ArtifactDigest {
        self.encoded_document_digest
    }

    /// Borrows bytes for the transport adapter. Administrative credentials are
    /// intentionally absent and must be injected only at that boundary.
    #[must_use]
    pub fn expose_encoded_document(&self) -> &[u8] {
        &self.encoded_document
    }
}

/// Encodes a current TS5 object or the explicit one-element legacy array.
pub fn prepare_registration_document(
    profile: ProtocolProfile,
    internal_relying_party_id: &str,
    desired_state_revision: u64,
    relying_party: &WalletRelyingParty,
) -> Result<PreparedRegistrarRegistrationDocument, RegistrationError> {
    if desired_state_revision == 0 {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        ));
    }
    let normalized = Zeroizing::new(canonical_json(relying_party)?);
    let mut encoded_document = match profile {
        ProtocolProfile::Ts5V1_5 => normalized.clone(),
        ProtocolProfile::EuReferenceLegacyV0_2_2 => {
            Zeroizing::new(canonical_json(&[relying_party])?)
        }
    };
    Ok(PreparedRegistrarRegistrationDocument {
        profile,
        internal_relying_party_id: BoundedText::try_new(internal_relying_party_id)?,
        desired_state_revision,
        normalized_content_digest: ArtifactDigest::of(&normalized),
        encoded_document_digest: ArtifactDigest::of(&encoded_document),
        encoded_document: core::mem::take(&mut *encoded_document),
    })
}
