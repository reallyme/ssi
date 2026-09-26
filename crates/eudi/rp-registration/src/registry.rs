// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::json::{deserialize_strict, MAX_JSON_BYTES};
use crate::{
    ArtifactDigest, ProtocolProfile, RegistrationError, RegistrationErrorReason, RegistryPayload,
    RegistryPayloadShape,
};

mod jose;
mod payload;

#[cfg(test)]
mod tests;

pub use jose::{JoseRegistryJwsVerifier, ValidatedJwks};

use jose::{parse_protected_header, select_signing_key, JwksDocument};
use payload::{
    decode_compact_payload, parse_selected_payload, validate_compact, validate_profile_shape,
    FreshnessPolicy,
};

const MAX_SIGNER_CERTIFICATE_BYTES: usize = 65_536;
const MAX_SIGNER_CERTIFICATE_CHAIN_BYTES: usize = 262_144;
const MAX_SIGNER_CERTIFICATE_CHAIN_LENGTH: usize = 10;

/// Input to strict registrar-response authentication.
pub struct RegistryAuthenticationInput<'a> {
    /// Pinned protocol profile.
    pub profile: ProtocolProfile,
    /// Exact expected authenticated payload shape.
    pub payload_shape: RegistryPayloadShape,
    /// Exact compact JWS returned by the registrar, including legacy responses.
    pub compact_jws: &'a [u8],
    /// Bounded JWKS fetched from the application-accepted `x-jku-url`.
    pub jwks: &'a ValidatedJwks,
    /// Trusted evaluation time used to judge the freshness of the answer.
    pub evaluation_time: OffsetDateTime,
    /// Maximum accepted age, in seconds, of a current envelope's signed `iat`.
    ///
    /// Must be positive and at most one day. Legacy shapes carry no signed
    /// issue time and therefore fail closed with
    /// [`RegistrationErrorReason::UnboundLegacyAnswer`].
    pub max_response_age_seconds: u64,
    /// Service and intended use a single-WRP answer must register.
    ///
    /// Only [`RegistryPayloadShape::Ts5SignedWrp`] and
    /// [`RegistryPayloadShape::LegacyRawWrp`] carry the identifiers needed for
    /// this check. TS5 intended-use-check results and WRP arrays do not echo
    /// the queried identifiers in the signed payload, so supplying a query for
    /// those shapes is rejected; their answers are bounded only by signature
    /// authentication and freshness.
    pub expected_intended_use: Option<RegistryIntendedUseQuery<'a>>,
}

/// Queried service and intended-use identifiers for a single-WRP lookup.
#[derive(Clone, Copy)]
pub struct RegistryIntendedUseQuery<'a> {
    /// Exact expected `serviceIdentifier`.
    pub service_id: &'a str,
    /// Exact expected `intendedUseIdentifier` within that service.
    pub intended_use_id: &'a str,
}

/// Bytes released by a cryptographic backend only after JWS verification.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthenticatedJws {
    compact_digest: ArtifactDigest,
    payload: Vec<u8>,
    signer_certificate_chain: Option<RegistrarCertificateChain>,
}

impl AuthenticatedJws {
    /// Constructs a receipt at the cryptographic-verifier boundary.
    ///
    /// The outer authenticator independently checks the compact digest and the
    /// decoded payload bytes before accepting this receipt.
    pub fn try_new(
        compact_jws: &[u8],
        payload: &[u8],
        signer_certificate_chain_der: Vec<Vec<u8>>,
    ) -> Result<Self, RegistrationError> {
        if payload.is_empty() || payload.len() > MAX_JSON_BYTES {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InputTooLarge,
            ));
        }
        Ok(Self {
            compact_digest: ArtifactDigest::of(compact_jws),
            payload: payload.to_vec(),
            signer_certificate_chain: Some(RegistrarCertificateChain::try_from_der(
                signer_certificate_chain_der,
            )?),
        })
    }
}

/// Exact bounded leaf-first signer chain retained by an authenticated record.
///
/// This type deliberately has no `Debug`, `Clone`, or serialization surface.
/// A caller takes it exactly once and transfers the owned DER values directly
/// into a zeroizing certificate-artifact repository.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RegistrarCertificateChain {
    certificates_der: Vec<Vec<u8>>,
    leaf_digest: ArtifactDigest,
}

impl RegistrarCertificateChain {
    fn try_from_der(certificates_der: Vec<Vec<u8>>) -> Result<Self, RegistrationError> {
        let mut certificates_der = Zeroizing::new(certificates_der);
        if certificates_der.is_empty() {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::MissingSignerCertificate,
            ));
        }
        if certificates_der.len() > MAX_SIGNER_CERTIFICATE_CHAIN_LENGTH {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::ResourceLimitExceeded,
            ));
        }
        let mut total = 0_usize;
        let mut parsed_certificates = Vec::new();
        parsed_certificates
            .try_reserve_exact(certificates_der.len())
            .map_err(|_error| {
                RegistrationError::from_reason(RegistrationErrorReason::CapacityUnavailable)
            })?;
        for certificate_der in certificates_der.iter() {
            if certificate_der.is_empty() {
                return Err(RegistrationError::from_reason(
                    RegistrationErrorReason::InvalidCertificate,
                ));
            }
            if certificate_der.len() > MAX_SIGNER_CERTIFICATE_BYTES {
                return Err(RegistrationError::from_reason(
                    RegistrationErrorReason::ResourceLimitExceeded,
                ));
            }
            let parsed =
                reallyme_trust_x509::parse_cert_der(certificate_der).map_err(|_error| {
                    RegistrationError::from_reason(RegistrationErrorReason::InvalidCertificate)
                })?;
            let Some(next_total) = total.checked_add(certificate_der.len()) else {
                return Err(RegistrationError::from_reason(
                    RegistrationErrorReason::ResourceLimitExceeded,
                ));
            };
            total = next_total;
            if total > MAX_SIGNER_CERTIFICATE_CHAIN_BYTES {
                return Err(RegistrationError::from_reason(
                    RegistrationErrorReason::ResourceLimitExceeded,
                ));
            }
            parsed_certificates.push(parsed);
        }
        for (index, certificate) in certificates_der.iter().enumerate() {
            if certificates_der
                .iter()
                .skip(index.checked_add(1).ok_or_else(|| {
                    RegistrationError::from_reason(RegistrationErrorReason::ResourceLimitExceeded)
                })?)
                .any(|candidate| candidate == certificate)
            {
                return Err(RegistrationError::from_reason(
                    RegistrationErrorReason::CertificateProfileMismatch,
                ));
            }
        }
        for pair in parsed_certificates.windows(2) {
            let child = pair.first().ok_or_else(|| {
                RegistrationError::from_reason(RegistrationErrorReason::CertificateProfileMismatch)
            })?;
            let issuer = pair.get(1).ok_or_else(|| {
                RegistrationError::from_reason(RegistrationErrorReason::CertificateProfileMismatch)
            })?;
            let authority_key_mismatch = child
                .authority_key_identifier
                .as_ref()
                .zip(issuer.subject_key_identifier.as_ref())
                .is_some_and(|(authority, subject)| authority != subject);
            if child.profile.issuer != issuer.profile.subject || authority_key_mismatch {
                return Err(RegistrationError::from_reason(
                    RegistrationErrorReason::CertificateProfileMismatch,
                ));
            }
        }
        let leaf_digest = certificates_der
            .first()
            .map(|leaf| ArtifactDigest::of(leaf))
            .ok_or_else(|| {
                RegistrationError::from_reason(RegistrationErrorReason::MissingSignerCertificate)
            })?;
        Ok(Self {
            certificates_der: core::mem::take(&mut *certificates_der),
            leaf_digest,
        })
    }

    /// Returns the number of exact DER elements in the presented chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.certificates_der.len()
    }

    /// Reports whether the chain is empty.
    ///
    /// An authenticated chain is never empty; this method supports ordinary
    /// collection-style handling at adapter boundaries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certificates_der.is_empty()
    }

    /// Returns the digest of the exact leaf certificate.
    #[must_use]
    pub const fn leaf_certificate_digest(&self) -> ArtifactDigest {
        self.leaf_digest
    }

    /// Consumes the owner and transfers the exact leaf-first DER chain in a
    /// zeroizing container.
    ///
    /// No additional copy is made. The returned container keeps the material
    /// zeroizing while an adapter persists it or transfers it to another
    /// zeroizing owner.
    #[must_use]
    pub fn into_der_certificates(mut self) -> Zeroizing<Vec<Vec<u8>>> {
        Zeroizing::new(core::mem::take(&mut self.certificates_der))
    }

    fn exactly_matches(&self, expected: &Self) -> bool {
        self.certificates_der == expected.certificates_der
    }

    fn leaf_der(&self) -> Result<&[u8], RegistrationError> {
        self.certificates_der
            .first()
            .map(Vec::as_slice)
            .ok_or_else(|| {
                RegistrationError::from_reason(RegistrationErrorReason::MissingSignerCertificate)
            })
    }
}

/// Injected cryptographic backend for registrar compact-JWS verification.
///
/// Implementations select a key only from a JWKS response already constrained
/// by the application's accepted `x-jku-url` policy. This trait proves format
/// authentication; issuer trust remains a separate application decision.
pub trait RegistryJwsVerifier {
    /// Verifies the compact JWS using only the supplied validated JWKS.
    fn verify(
        &self,
        compact_jws: &[u8],
        jwks: &ValidatedJwks,
    ) -> Result<AuthenticatedJws, RegistrationError>;
}

/// Authenticated current-envelope metadata or explicit legacy absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum RegistryMetadata {
    /// Mandatory metadata from a current TS5 envelope.
    Current {
        /// SHA-256 of the JCS-encoded authenticated `iss` string.
        issuer_digest: ArtifactDigest,
        /// Exact positive NumericDate from `iat`.
        issued_at: u64,
    },
    /// Legacy raw shapes have no authenticated `iss` or `iat`.
    LegacyUnavailable,
}

/// Authenticated registrar response with exact profile provenance.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthenticatedRegistryRecord {
    profile: ProtocolProfile,
    payload_shape: RegistryPayloadShape,
    payload_digest: ArtifactDigest,
    signer_certificate_digest: ArtifactDigest,
    signer_certificate_chain: Option<RegistrarCertificateChain>,
    metadata: RegistryMetadata,
    payload: RegistryPayload,
}

impl AuthenticatedRegistryRecord {
    /// Returns the selected protocol profile.
    #[must_use]
    pub const fn profile(&self) -> ProtocolProfile {
        self.profile
    }

    /// Returns the selected payload shape.
    #[must_use]
    pub const fn payload_shape(&self) -> RegistryPayloadShape {
        self.payload_shape
    }

    /// Returns the digest of exact authenticated payload bytes.
    #[must_use]
    pub const fn payload_digest(&self) -> ArtifactDigest {
        self.payload_digest
    }

    /// Returns the digest of the signature-bound leaf certificate.
    #[must_use]
    pub const fn signer_certificate_digest(&self) -> ArtifactDigest {
        self.signer_certificate_digest
    }

    /// Takes the exact authenticated leaf-first signer chain once.
    ///
    /// This is a consuming material handoff: subsequent calls return `None`,
    /// while the record keeps the signer digest needed for lifecycle state.
    #[must_use]
    pub fn take_signer_certificate_chain(&mut self) -> Option<RegistrarCertificateChain> {
        self.signer_certificate_chain.take()
    }

    /// Returns current envelope metadata or explicit legacy absence.
    #[must_use]
    pub const fn metadata(&self) -> RegistryMetadata {
        self.metadata
    }

    /// Borrows the validated semantic payload.
    #[must_use]
    pub const fn payload(&self) -> &RegistryPayload {
        &self.payload
    }
}

/// Authenticates and parses exactly the caller-selected registrar shape.
pub fn authenticate_registry_record(
    input: RegistryAuthenticationInput<'_>,
    verifier: &dyn RegistryJwsVerifier,
) -> Result<AuthenticatedRegistryRecord, RegistrationError> {
    validate_profile_shape(input.profile, input.payload_shape)?;
    validate_query_shape(input.payload_shape, input.expected_intended_use.as_ref())?;
    let freshness =
        FreshnessPolicy::try_new(input.evaluation_time, input.max_response_age_seconds)?;
    validate_compact(input.compact_jws)?;
    let mut receipt = verifier.verify(input.compact_jws, input.jwks)?;
    if receipt.compact_digest != ArtifactDigest::of(input.compact_jws) {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::AuthenticationReceiptMismatch,
        ));
    }
    let decoded_payload = decode_compact_payload(input.compact_jws)?;
    if decoded_payload.as_slice() != receipt.payload.as_slice() {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::AuthenticationReceiptMismatch,
        ));
    }
    let protected_header = parse_protected_header(input.compact_jws)?;
    let document: JwksDocument = deserialize_strict(input.jwks.expose_body())?;
    let (_jwk, expected_chain) = select_signing_key(document, &protected_header)?;
    let receipt_chain = receipt.signer_certificate_chain.as_ref().ok_or_else(|| {
        RegistrationError::from_reason(RegistrationErrorReason::MissingSignerCertificate)
    })?;
    if !receipt_chain.exactly_matches(&expected_chain) {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::AuthenticationReceiptMismatch,
        ));
    }
    let (payload, metadata) =
        parse_selected_payload(input.payload_shape, &receipt.payload, freshness)?;
    if let Some(query) = input.expected_intended_use.as_ref() {
        validate_intended_use_query(&payload, query)?;
    }
    let signer_certificate_digest = receipt_chain.leaf_certificate_digest();
    let signer_certificate_chain = receipt.signer_certificate_chain.take().ok_or_else(|| {
        RegistrationError::from_reason(RegistrationErrorReason::MissingSignerCertificate)
    })?;
    Ok(AuthenticatedRegistryRecord {
        profile: input.profile,
        payload_shape: input.payload_shape,
        payload_digest: ArtifactDigest::of(&receipt.payload),
        signer_certificate_digest,
        signer_certificate_chain: Some(signer_certificate_chain),
        metadata,
        payload,
    })
}

fn validate_query_shape(
    shape: RegistryPayloadShape,
    query: Option<&RegistryIntendedUseQuery<'_>>,
) -> Result<(), RegistrationError> {
    let bindable = matches!(
        shape,
        RegistryPayloadShape::Ts5SignedWrp | RegistryPayloadShape::LegacyRawWrp
    );
    if query.is_some() && !bindable {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::PayloadShapeMismatch,
        ));
    }
    Ok(())
}

fn validate_intended_use_query(
    payload: &RegistryPayload,
    query: &RegistryIntendedUseQuery<'_>,
) -> Result<(), RegistrationError> {
    let RegistryPayload::Wrp(record) = payload else {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::PayloadShapeMismatch,
        ));
    };
    let registered = record.services().iter().any(|service| {
        service.service_identifier() == query.service_id
            && service
                .intended_uses()
                .iter()
                .any(|intended_use| intended_use.intended_use_identifier() == query.intended_use_id)
    });
    if !registered {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::SemanticBindingMismatch,
        ));
    }
    Ok(())
}
