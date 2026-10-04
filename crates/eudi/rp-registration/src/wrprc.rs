// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::json::canonical_json;
use crate::{ArtifactDigest, BoundedText, RegistrationError, RegistrationErrorReason};

mod authenticate;
mod parse;
#[cfg(any(feature = "native", feature = "wasm"))]
mod proof;

pub use authenticate::authenticate_registration_certificate;
pub use parse::parse_registration_certificate;
#[cfg(any(feature = "native", feature = "wasm"))]
pub use proof::{
    authenticate_presented_wrprc_cose_sign1, authenticate_presented_wrprc_jades,
    authenticate_wrprc_cose_sign1, authenticate_wrprc_jades, RegistrationCertificateCoseAlgorithm,
    RegistrationCertificateCoseAuthenticationInput,
    RegistrationCertificateJadesAuthenticationInput, RegistrationCertificateJadesPolicy,
};

#[cfg(any(feature = "native", feature = "wasm"))]
const MAX_REPRESENTATION_BYTES: usize = 2 * 1_024 * 1_024;
#[cfg(any(feature = "native", feature = "wasm"))]
const MAX_SIGNER_CERTIFICATE_BYTES: usize = 65_536;
#[cfg(any(feature = "native", feature = "wasm"))]
const MAX_SIGNER_CERTIFICATE_CHAIN_LENGTH: usize = 10;
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

/// Registrar-provided text authenticated by a WRPRC signature.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignedLocalizedText {
    language: BoundedText,
    content: BoundedText,
}

impl SignedLocalizedText {
    /// Borrow the registered language tag.
    #[must_use]
    pub fn language(&self) -> &str {
        self.language.expose()
    }

    /// Borrow the registered, human-readable text.
    #[must_use]
    pub fn content(&self) -> &str {
        self.content.expose()
    }

    pub(super) fn new(language: BoundedText, content: BoundedText) -> Self {
        Self { language, content }
    }
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
    presented_certificate_chain_der: Vec<Vec<u8>>,
}

impl RegistrationCertificateProof {
    /// Borrow signature-authenticated and time-checked claims before this
    /// proof is consumed by a higher-level registration binding.
    ///
    /// The receipt does not establish issuer trust or current status.
    #[must_use]
    pub fn authenticated_claims(&self) -> Option<&ParsedRegistrationCertificate> {
        self.parsed.as_ref()
    }

    /// Borrow the exact candidate signer path carried by the authenticated
    /// representation. A trust evaluator must validate its purpose and path.
    #[must_use]
    pub fn presented_certificate_chain_der(&self) -> &[Vec<u8>] {
        &self.presented_certificate_chain_der
    }

    /// Return the digest of the exact signed representation.
    #[must_use]
    pub const fn representation_digest(&self) -> ArtifactDigest {
        self.representation_digest
    }

    /// Constructs a receipt after the crate-owned verifier has authenticated
    /// the representation and parsed and time-checked its signed claims.
    #[cfg(any(feature = "native", feature = "wasm"))]
    fn from_verified(
        format: RegistrationCertificateFormat,
        signed_representation: &[u8],
        parsed: ParsedRegistrationCertificate,
        signer_certificate_der: &[u8],
        presented_certificate_chain_der: Vec<Vec<u8>>,
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
        if presented_certificate_chain_der.is_empty()
            || presented_certificate_chain_der.len() > MAX_SIGNER_CERTIFICATE_CHAIN_LENGTH
            || presented_certificate_chain_der.first().map(Vec::as_slice)
                != Some(signer_certificate_der)
            || presented_certificate_chain_der.iter().any(|certificate| {
                certificate.is_empty()
                    || certificate.len() > MAX_SIGNER_CERTIFICATE_BYTES
                    || !reallyme_trust_x509::validate_certificate_der(certificate)
            })
        {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidCertificate,
            ));
        }
        Ok(Self {
            format,
            representation_digest: ArtifactDigest::of(signed_representation),
            parsed: Some(parsed),
            presented_certificate_chain_der,
        })
    }
}

/// Parsed TS 119 475 claims. Parsing alone does not authenticate them.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ParsedRegistrationCertificate {
    payload_digest: ArtifactDigest,
    relying_party_id: BoundedText,
    intermediary_id: Option<BoundedText>,
    registry_uri: BoundedText,
    registry_reference_digest: ArtifactDigest,
    status_list_uri: BoundedText,
    status_list_uri_digest: ArtifactDigest,
    status_list_index: u64,
    issued_at: u64,
    expires_at: u64,
    certificate_policy: RegistrationCertificatePolicy,
    certificate_policy_uri_digest: ArtifactDigest,
    semantic_content_digest: ArtifactDigest,
    intended_use_id: Option<BoundedText>,
    purpose: Vec<SignedLocalizedText>,
    service_description: Vec<SignedLocalizedText>,
    privacy_policy_uris: Vec<BoundedText>,
    registered_credentials: Vec<crate::CredentialRequest>,
    registered_credential_formats: Vec<RegisteredCredentialFormat>,
}

impl ParsedRegistrationCertificate {
    /// Returns the digest of exact authenticated payload bytes.
    #[must_use]
    pub const fn payload_digest(&self) -> ArtifactDigest {
        self.payload_digest
    }

    /// Return the signed intended-use identifier, when the registrar assigned one.
    #[must_use]
    pub fn intended_use_id(&self) -> Option<&str> {
        self.intended_use_id.as_ref().map(BoundedText::expose)
    }

    /// Return the signed purpose descriptions shown to the user.
    #[must_use]
    pub fn purpose(&self) -> &[SignedLocalizedText] {
        &self.purpose
    }

    /// Return the signed service descriptions shown to the user.
    #[must_use]
    pub fn service_description(&self) -> &[SignedLocalizedText] {
        &self.service_description
    }

    /// Return the signed privacy-policy URIs.
    #[must_use]
    pub fn privacy_policy_uris(&self) -> &[BoundedText] {
        &self.privacy_policy_uris
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

    /// Return the canonical URI signed into the WRPRC for registrar lookup.
    #[must_use]
    pub fn registry_uri(&self) -> &str {
        self.registry_uri.expose()
    }

    /// Return the canonical signed status-list URI for current-status checks.
    #[must_use]
    pub fn status_list_uri(&self) -> &str {
        self.status_list_uri.expose()
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

    fn authorizes_credential_request(&self, requested: &crate::CredentialRequest) -> bool {
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
    presented_certificate_chain_der: Vec<Vec<u8>>,
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

    /// Borrows the exact leaf certificate that authenticated every WRPRC
    /// representation. A trust evaluator must still validate its path and
    /// registration-signing purpose independently of this proof receipt.
    #[must_use]
    pub fn signer_certificate_der(&self) -> Option<&[u8]> {
        self.presented_certificate_chain_der
            .first()
            .map(Vec::as_slice)
    }

    /// Borrow the bounded leaf-first candidate path from the first WRPRC
    /// representation. Other encodings may present different intermediates;
    /// the common leaf is checked across all of them. Path trust and status
    /// still require independent evaluation.
    #[must_use]
    pub fn presented_certificate_chain_der(&self) -> &[Vec<u8>] {
        &self.presented_certificate_chain_der
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

    /// Reports whether every metadata value and claim path in `requested` is
    /// covered by one signature-authenticated WRPRC credential authorization.
    #[must_use]
    pub fn authorizes_credential_request(&self, requested: &crate::CredentialRequest) -> bool {
        self.parsed.authorizes_credential_request(requested)
    }
}
