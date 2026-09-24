// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::json::{canonical_json, MAX_JSON_BYTES};
use crate::{ArtifactDigest, BoundedText, RegistrationError, RegistrationErrorReason};

mod parse;
#[cfg(any(feature = "native", feature = "wasm"))]
mod proof;

pub use parse::parse_registration_certificate;
#[cfg(any(feature = "native", feature = "wasm"))]
pub use proof::{
    authenticate_wrprc_cose_sign1, authenticate_wrprc_jades, RegistrationCertificateCoseAlgorithm,
    RegistrationCertificateCoseAuthenticationInput,
    RegistrationCertificateJadesAuthenticationInput, RegistrationCertificateJadesPolicy,
};

const MAX_REPRESENTATION_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_SIGNER_CERTIFICATE_BYTES: usize = 65_536;
const MAX_REPRESENTATIONS: usize = 2;
const ETSI_TS_119_475_WRPRC_POLICY_OID: &str = "0.4.0.19475.3.1";

/// Closed certificate-policy identity admitted for an ETSI WRPRC.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum RegistrationCertificatePolicy {
    /// ETSI TS 119 475 clause 6.1.3 `wrprc` policy identifier.
    EtsiTs119475Wrprc,
}

impl RegistrationCertificatePolicy {
    /// Returns the normative dotted-decimal policy object identifier.
    #[must_use]
    pub const fn as_oid(self) -> &'static str {
        match self {
            Self::EtsiTs119475Wrprc => ETSI_TS_119_475_WRPRC_POLICY_OID,
        }
    }
}

/// ETSI TS 119 475 representation authenticated by a cryptographic backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum RegistrationCertificateFormat {
    /// Compact JWT authenticated under the JAdES profile.
    JadesJwt,
    /// CWT authenticated as a COSE message.
    CoseCwt,
}

/// Local issuance bindings not represented as standalone TS 119 475 claims.
///
/// A backend must include the canonical digest of this object in its signed
/// authority receipt. This avoids manufacturing service or intended-use claims
/// that TS 119 475 does not define.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct RegistrationCertificateBinding {
    relying_party_id: BoundedText,
    service_id: BoundedText,
    intended_use_id: BoundedText,
    intermediary_association_id: Option<BoundedText>,
    national_register_reference_digest: ArtifactDigest,
    registration_snapshot_digest: ArtifactDigest,
}

impl RegistrationCertificateBinding {
    /// Constructs the complete reviewed issuance binding.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        relying_party_id: &str,
        service_id: &str,
        intended_use_id: &str,
        intermediary_association_id: Option<&str>,
        national_register_reference_digest: ArtifactDigest,
        registration_snapshot_digest: ArtifactDigest,
    ) -> Result<Self, RegistrationError> {
        Ok(Self {
            relying_party_id: BoundedText::try_new(relying_party_id)?,
            service_id: BoundedText::try_new(service_id)?,
            intended_use_id: BoundedText::try_new(intended_use_id)?,
            intermediary_association_id: intermediary_association_id
                .map(BoundedText::try_new)
                .transpose()?,
            national_register_reference_digest,
            registration_snapshot_digest,
        })
    }

    /// Returns the canonical digest a verifier receipt must authenticate.
    pub fn digest(&self) -> Result<ArtifactDigest, RegistrationError> {
        let canonical = Zeroizing::new(canonical_json(self)?);
        Ok(ArtifactDigest::of(&canonical))
    }

    /// Returns the bound relying-party identifier.
    #[must_use]
    pub fn relying_party_id(&self) -> &str {
        self.relying_party_id.expose()
    }

    /// Returns the bound service identifier.
    #[must_use]
    pub fn service_id(&self) -> &str {
        self.service_id.expose()
    }

    /// Returns the bound intended-use identifier.
    #[must_use]
    pub fn intended_use_id(&self) -> &str {
        self.intended_use_id.expose()
    }

    /// Returns the optional bound intermediary association.
    #[must_use]
    pub fn intermediary_association_id(&self) -> Option<&str> {
        self.intermediary_association_id
            .as_ref()
            .map(BoundedText::expose)
    }

    /// Returns the bound national-register reference digest.
    #[must_use]
    pub const fn national_register_reference_digest(&self) -> ArtifactDigest {
        self.national_register_reference_digest
    }

    /// Returns the bound reviewed registration snapshot digest.
    #[must_use]
    pub const fn registration_snapshot_digest(&self) -> ArtifactDigest {
        self.registration_snapshot_digest
    }
}

/// Proof receipt released only after JAdES or COSE signature verification.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RegistrationCertificateProof {
    format: RegistrationCertificateFormat,
    representation_digest: ArtifactDigest,
    payload: Vec<u8>,
    signer_certificate_der: Vec<u8>,
    binding_digest: ArtifactDigest,
}

impl RegistrationCertificateProof {
    /// Constructs a receipt after the crate-owned verifier has authenticated it.
    fn from_verified(
        format: RegistrationCertificateFormat,
        signed_representation: &[u8],
        authenticated_payload: &[u8],
        signer_certificate_der: &[u8],
        authenticated_binding_digest: ArtifactDigest,
    ) -> Result<Self, RegistrationError> {
        if signed_representation.is_empty()
            || signed_representation.len() > MAX_REPRESENTATION_BYTES
            || authenticated_payload.is_empty()
            || authenticated_payload.len() > MAX_JSON_BYTES
        {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InputTooLarge,
            ));
        }
        if signer_certificate_der.is_empty()
            || signer_certificate_der.len() > MAX_SIGNER_CERTIFICATE_BYTES
        {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::MissingSignerCertificate,
            ));
        }
        if !reallyme_trust_x509::validate_certificate_der(signer_certificate_der) {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidCertificate,
            ));
        }
        Ok(Self {
            format,
            representation_digest: ArtifactDigest::of(signed_representation),
            payload: authenticated_payload.to_vec(),
            signer_certificate_der: signer_certificate_der.to_vec(),
            binding_digest: authenticated_binding_digest,
        })
    }
}

/// Parsed TS 119 475 claims. Parsing alone does not authenticate them.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ParsedRegistrationCertificate {
    payload_digest: ArtifactDigest,
    relying_party_id: BoundedText,
    intermediary_id: Option<BoundedText>,
    registry_reference_digest: ArtifactDigest,
    status_list_uri_digest: ArtifactDigest,
    status_list_index: u64,
    issued_at: u64,
    expires_at: u64,
    certificate_policy: RegistrationCertificatePolicy,
    certificate_policy_uri_digest: ArtifactDigest,
    semantic_content_digest: ArtifactDigest,
}

impl ParsedRegistrationCertificate {
    /// Returns the digest of exact authenticated payload bytes.
    #[must_use]
    pub const fn payload_digest(&self) -> ArtifactDigest {
        self.payload_digest
    }

    /// Returns the semantic WRP identifier from `sub`.
    #[must_use]
    pub fn relying_party_id(&self) -> &str {
        self.relying_party_id.expose()
    }

    /// Returns the optional semantic intermediary identifier.
    #[must_use]
    pub fn intermediary_id(&self) -> Option<&str> {
        self.intermediary_id.as_ref().map(BoundedText::expose)
    }

    /// Returns the digest of the canonical status-list URI.
    #[must_use]
    pub const fn status_list_uri_digest(&self) -> ArtifactDigest {
        self.status_list_uri_digest
    }

    /// Returns the exact status-list index.
    #[must_use]
    pub const fn status_list_index(&self) -> u64 {
        self.status_list_index
    }

    /// Returns the positive issue time.
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Returns the bounded expiration time.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns the exact normative WRPRC certificate-policy identity.
    #[must_use]
    pub const fn certificate_policy(&self) -> RegistrationCertificatePolicy {
        self.certificate_policy
    }

    /// Returns the digest of the canonical HTTPS CP/CPS location.
    #[must_use]
    pub const fn certificate_policy_uri_digest(&self) -> ArtifactDigest {
        self.certificate_policy_uri_digest
    }

    /// Returns the canonical registry-reference digest.
    #[must_use]
    pub const fn registry_reference_digest(&self) -> ArtifactDigest {
        self.registry_reference_digest
    }
}

/// One authenticated encoded representation digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub struct AuthenticatedRepresentation {
    /// Authenticated encoding format.
    pub format: RegistrationCertificateFormat,
    /// Digest of the exact signed representation.
    pub digest: ArtifactDigest,
}

/// Format-authenticated WRPRC facts without an issuer-trust assertion.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthenticatedRegistrationCertificate {
    representations: Vec<AuthenticatedRepresentation>,
    signer_certificate_digest: ArtifactDigest,
    parsed: ParsedRegistrationCertificate,
    binding: RegistrationCertificateBinding,
}

impl AuthenticatedRegistrationCertificate {
    /// Returns all authenticated encodings.
    #[must_use]
    pub fn representations(&self) -> &[AuthenticatedRepresentation] {
        &self.representations
    }

    /// Returns the common signer certificate digest.
    #[must_use]
    pub const fn signer_certificate_digest(&self) -> ArtifactDigest {
        self.signer_certificate_digest
    }

    /// Returns the strictly parsed common claims.
    #[must_use]
    pub const fn parsed(&self) -> &ParsedRegistrationCertificate {
        &self.parsed
    }

    /// Returns the authenticated local issuance binding.
    #[must_use]
    pub const fn binding(&self) -> &RegistrationCertificateBinding {
        &self.binding
    }
}

/// Parses strict TS 119 475 WRPRC payload claims without authenticating them.
pub fn authenticate_registration_certificate(
    proofs: Vec<RegistrationCertificateProof>,
    binding: RegistrationCertificateBinding,
) -> Result<AuthenticatedRegistrationCertificate, RegistrationError> {
    if proofs.is_empty() || proofs.len() > MAX_REPRESENTATIONS {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::ResourceLimitExceeded,
        ));
    }
    let canonical_binding = Zeroizing::new(canonical_json(&binding)?);
    let expected_binding_digest = ArtifactDigest::of(&canonical_binding);
    let mut parsed_result: Option<ParsedRegistrationCertificate> = None;
    let mut signer_digest: Option<ArtifactDigest> = None;
    let mut representations = Vec::new();
    for proof in proofs {
        if proof.binding_digest != expected_binding_digest {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::SemanticBindingMismatch,
            ));
        }
        if representations
            .iter()
            .any(|item: &AuthenticatedRepresentation| item.format == proof.format)
        {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            ));
        }
        let parsed = parse_registration_certificate(&proof.payload)?;
        if parsed.relying_party_id() != binding.relying_party_id.expose()
            || parsed.registry_reference_digest != binding.national_register_reference_digest
        {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::SemanticBindingMismatch,
            ));
        }
        let current_signer = ArtifactDigest::of(&proof.signer_certificate_der);
        if signer_digest.is_some_and(|existing| existing != current_signer) {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::AuthenticationReceiptMismatch,
            ));
        }
        if let Some(existing) = parsed_result.as_ref() {
            if existing.semantic_content_digest != parsed.semantic_content_digest
                || existing.relying_party_id != parsed.relying_party_id
                || existing.intermediary_id != parsed.intermediary_id
                || existing.registry_reference_digest != parsed.registry_reference_digest
                || existing.status_list_uri_digest != parsed.status_list_uri_digest
                || existing.status_list_index != parsed.status_list_index
                || existing.issued_at != parsed.issued_at
                || existing.expires_at != parsed.expires_at
            {
                return Err(RegistrationError::from_reason(
                    RegistrationErrorReason::SemanticBindingMismatch,
                ));
            }
        } else {
            parsed_result = Some(parsed);
        }
        signer_digest = Some(current_signer);
        representations.push(AuthenticatedRepresentation {
            format: proof.format,
            digest: proof.representation_digest,
        });
    }
    let parsed = parsed_result
        .ok_or_else(|| RegistrationError::from_reason(RegistrationErrorReason::MissingField))?;
    let signer_certificate_digest = signer_digest.ok_or_else(|| {
        RegistrationError::from_reason(RegistrationErrorReason::MissingSignerCertificate)
    })?;
    Ok(AuthenticatedRegistrationCertificate {
        representations,
        signer_certificate_digest,
        parsed,
        binding,
    })
}
