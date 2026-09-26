// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::json::canonical_json;
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

/// Credential format that a signed WRPRC authorizes the relying party to request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum RegisteredCredentialFormat {
    /// IETF SD-JWT VC using the `dc+sd-jwt` format identifier.
    DcSdJwt,
    /// ISO/IEC 18013-5 mobile document using the `mso_mdoc` identifier.
    MsoMdoc,
}

/// Locally reviewed issuance binding for one WRPRC.
///
/// [`authenticate_registration_certificate`] checks every field that has a
/// counterpart in the signed TS 119 475 claims:
///
/// - `relying_party_id` must equal the signed `sub`;
/// - `intermediary_association_id` must equal the signed intermediary `sub`
///   (both absent, or both present and equal);
/// - `national_register_reference_digest` must equal the digest of the
///   canonical signed `registry_uri`.
///
/// TS 119 475 defines no standalone service, intended-use, or registration
/// snapshot claims, and the signed WRPRC does not carry this binding's digest.
/// `service_id`, `intended_use_id`, and `registration_snapshot_digest` are
/// therefore caller-asserted local context retained for audit correlation;
/// they are not authenticated by the WRPRC signature.
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

    /// Returns the canonical digest of this local binding for audit records.
    ///
    /// The digest is computed locally; it is not carried in or authenticated
    /// by the signed WRPRC.
    pub fn digest(&self) -> Result<ArtifactDigest, RegistrationError> {
        let canonical = Zeroizing::new(canonical_json(self)?);
        Ok(ArtifactDigest::of(&canonical))
    }

    /// Returns the bound relying-party identifier.
    #[must_use]
    pub fn relying_party_id(&self) -> &str {
        self.relying_party_id.expose()
    }

    /// Returns the caller-asserted, unauthenticated service identifier.
    #[must_use]
    pub fn service_id(&self) -> &str {
        self.service_id.expose()
    }

    /// Returns the caller-asserted, unauthenticated intended-use identifier.
    #[must_use]
    pub fn intended_use_id(&self) -> &str {
        self.intended_use_id.expose()
    }

    /// Returns the optional intermediary identifier checked against the
    /// signed intermediary `sub`.
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

    /// Returns the caller-asserted, unauthenticated registration snapshot
    /// digest.
    #[must_use]
    pub const fn registration_snapshot_digest(&self) -> ArtifactDigest {
        self.registration_snapshot_digest
    }
}

/// Proof receipt released only after JAdES or COSE signature verification
/// and evaluation of the signed validity period at a trusted time.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RegistrationCertificateProof {
    format: RegistrationCertificateFormat,
    representation_digest: ArtifactDigest,
    parsed: Option<ParsedRegistrationCertificate>,
    signer_certificate_der: Vec<u8>,
}

impl RegistrationCertificateProof {
    /// Constructs a receipt after the crate-owned verifier has authenticated
    /// the representation and parsed and time-checked its signed claims.
    #[cfg(any(feature = "native", feature = "wasm"))]
    fn from_verified(
        format: RegistrationCertificateFormat,
        signed_representation: &[u8],
        parsed: ParsedRegistrationCertificate,
        signer_certificate_der: &[u8],
    ) -> Result<Self, RegistrationError> {
        if signed_representation.is_empty()
            || signed_representation.len() > MAX_REPRESENTATION_BYTES
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
            parsed: Some(parsed),
            signer_certificate_der: signer_certificate_der.to_vec(),
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
    registered_credentials: Vec<crate::CredentialRequest>,
    registered_credential_formats: Vec<RegisteredCredentialFormat>,
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

    /// Returns the credential formats authenticated by the WRPRC signature.
    #[must_use]
    pub fn registered_credential_formats(&self) -> &[RegisteredCredentialFormat] {
        &self.registered_credential_formats
    }

    /// Returns the signed, strictly validated credential authorizations.
    #[must_use]
    pub fn registered_credentials(&self) -> &[crate::CredentialRequest] {
        &self.registered_credentials
    }

    /// Reports whether every metadata value and claim path in `requested` is
    /// covered by one signed WRPRC credential authorization.
    #[must_use]
    pub fn authorizes_credential_request(&self, requested: &crate::CredentialRequest) -> bool {
        self.registered_credentials
            .iter()
            .any(|registered| registered.authorizes(requested))
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

    /// Returns the local issuance binding.
    ///
    /// Only the relying-party, intermediary, and national-register fields
    /// were checked against signed claims; see
    /// [`RegistrationCertificateBinding`].
    #[must_use]
    pub const fn binding(&self) -> &RegistrationCertificateBinding {
        &self.binding
    }
}

/// Combines one or both proof receipts for the same WRPRC and checks the
/// local binding fields that have counterparts in the signed claims.
///
/// Each receipt already proved signature validity and that its trusted
/// evaluation time fell within the signed `iat`/`exp` period. This function
/// asserts neither issuer nor certification-path trust.
pub fn authenticate_registration_certificate(
    proofs: Vec<RegistrationCertificateProof>,
    binding: RegistrationCertificateBinding,
) -> Result<AuthenticatedRegistrationCertificate, RegistrationError> {
    if proofs.is_empty() || proofs.len() > MAX_REPRESENTATIONS {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::ResourceLimitExceeded,
        ));
    }
    let mut parsed_result: Option<ParsedRegistrationCertificate> = None;
    let mut signer_digest: Option<ArtifactDigest> = None;
    let mut representations = Vec::new();
    for mut proof in proofs {
        if representations
            .iter()
            .any(|item: &AuthenticatedRepresentation| item.format == proof.format)
        {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            ));
        }
        let parsed = proof
            .parsed
            .take()
            .ok_or_else(|| RegistrationError::from_reason(RegistrationErrorReason::MissingField))?;
        if parsed.relying_party_id() != binding.relying_party_id()
            || parsed.intermediary_id() != binding.intermediary_association_id()
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
