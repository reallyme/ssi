// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_credential_audit::QeaaCompliance;
use reallyme_credential_claims::{
    ClaimsCommitment, CredentialAlgorithm, PublicKeyRef, PublicKeyRepresentation, Signature,
};
use reallyme_credential_status::StatusPurpose;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum accepted UTF-8 bytes for credential identifiers.
pub const MAX_CREDENTIAL_TEXT_BYTES: usize = 2048;

/// Maximum accepted UTF-8 bytes for status-list URLs.
pub const MAX_STATUS_LIST_URL_BYTES: usize = 4096;

/// Maximum accepted issuer-country code bytes.
pub const MAX_CREDENTIAL_COUNTRY_BYTES: usize = 3;

/// Maximum accepted cached public key bytes in one credential key reference.
pub const MAX_PUBLIC_KEY_BYTES: usize = 4096;

/// Maximum accepted raw signature bytes.
pub(crate) const MAX_SIGNATURE_BYTES: usize = 8192;

/// Unix timestamp seconds used by the semantic credential model.
pub type UnixSeconds = i64;

/// Credential family represented by the public envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum CredentialKind {
    /// General credential governed by issuer policy rather than an eIDAS category.
    Generic,

    /// EUDI Personal Identification Data credential.
    Pid,

    /// Electronic Attestation of Attributes.
    Eaa,

    /// Qualified Electronic Attestation of Attributes.
    Qeaa,
}

/// EUDI assurance level represented by the credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum AssuranceLevel {
    /// Baseline assurance for credentials outside a regulated assurance profile.
    Basic,

    /// Substantial assurance.
    Substantial,

    /// High assurance.
    High,
}

/// Signed public credential envelope.
#[derive(Eq, PartialEq)]
pub struct CredentialEnvelope {
    /// Credential family.
    pub kind: CredentialKind,

    /// Profile or claimset identifier for the credential.
    pub profile_id: String,

    /// Assurance level asserted by the issuer.
    pub assurance: AssuranceLevel,

    /// Identity reference for the issuing party.
    pub issuer_reference: PartyReference,

    /// Issuer country or trust-framework jurisdiction code.
    pub issuer_country: String,

    /// Inclusive validity start as Unix seconds.
    pub valid_from: UnixSeconds,

    /// Exclusive validity end as Unix seconds.
    pub valid_until: UnixSeconds,

    /// Status-list pointer for revocation or suspension checks.
    pub status: CredentialStatus,

    /// Subject identifier and public-key binding.
    pub subject: CredentialSubject,

    /// Public commitment to the normalized claim set.
    pub claims_commitment: ClaimsCommitment,

    /// QEAA compliance evidence. Required only when [`CredentialKind::Qeaa`].
    pub qeaa_compliance: Option<QeaaCompliance>,

    /// Issuer signature over the canonical public envelope.
    pub issuer_signature: Signature,
}

/// Reference used to identify a party independently from holder binding.
#[derive(Clone, Eq, PartialEq)]
pub enum PartyReference {
    /// DID or DID URL.
    Did(String),
    /// Subject identified by validated X.509 material.
    X509Subject(X509SubjectReference),
    /// Party identified only by a public key or profile-defined thumbprint.
    PublicKey(PublicKeyIdentity),
    /// Federation profile entity identifier.
    FederationEntityId(String),
    /// Profile-scoped opaque identifier.
    OpaqueIdentifier(String),
    /// Absolute URI identifier.
    Uri(String),
    /// The credential format deliberately omits an encoded subject reference.
    Absent,
}

/// Public-key party reference with explicit algorithm and representation.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicKeyIdentity {
    /// Algorithm associated with the public key.
    pub alg: CredentialAlgorithm,
    /// Explicitly tagged public-key material.
    pub public_key: PublicKeyRepresentation,
}

/// Validated X.509 reference form used to identify a certificate subject.
#[derive(Clone, Eq, PartialEq)]
pub enum X509SubjectReference {
    /// SHA-256 fingerprint of the referenced certificate.
    CertificateSha256([u8; 32]),
    /// Issuer name DER and positive serial-number bytes.
    IssuerAndSerial {
        /// DER-encoded issuer distinguished name.
        issuer_name_der: Vec<u8>,
        /// Minimal unsigned serial-number octets.
        serial_number: Vec<u8>,
    },
    /// Certificate already validated under the caller's trust policy.
    ValidatedCertificateDer(Vec<u8>),
}

/// Explicit holder-authorisation mode.
#[derive(Clone, Eq, PartialEq)]
pub enum HolderBinding {
    /// Holder proves possession of this key.
    CryptographicKey(PublicKeyRef),
    /// Profile-defined claims identify or constrain the authorised holder.
    ClaimsBased(Vec<String>),
    /// No holder proof is required; verifier policy must allow bearer use.
    BearerWithoutBinding,
}

/// Credential subject and independently selected holder binding.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialSubject {
    /// Optional encoded identity reference for the subject.
    pub subject_reference: PartyReference,

    /// Holder-authorisation mode, independent from the subject reference.
    pub holder_binding: HolderBinding,
}

/// Credential status-list pointer.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialStatus {
    /// URL or typed URI where the status list is obtained.
    pub status_list_url: String,

    /// Fixed status-list identifier or SHA-256 digest.
    pub status_list_id: [u8; 32],

    /// Index inside the status list.
    pub status_list_index: u64,

    /// Status semantic represented by the referenced list.
    pub purpose: StatusPurpose,
}

impl core::fmt::Debug for CredentialEnvelope {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialEnvelope")
            .field("kind", &self.kind)
            .field("profile_id", &self.profile_id)
            .field("assurance", &self.assurance)
            .field("issuer_reference", &self.issuer_reference)
            .field("issuer_country", &self.issuer_country)
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .field("status", &self.status)
            .field("subject", &self.subject)
            .field("claims_commitment", &self.claims_commitment)
            .field("qeaa_compliance", &self.qeaa_compliance.is_some())
            .field("issuer_signature", &self.issuer_signature)
            .finish()
    }
}

impl core::fmt::Debug for CredentialSubject {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialSubject")
            .field("subject_reference", &self.subject_reference)
            .field("holder_binding", &self.holder_binding)
            .finish()
    }
}

impl core::fmt::Debug for PartyReference {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Did(value) => formatter
                .debug_tuple("Did")
                .field(&redacted_len(value.len()))
                .finish(),
            Self::X509Subject(value) => formatter.debug_tuple("X509Subject").field(value).finish(),
            Self::PublicKey(value) => formatter.debug_tuple("PublicKey").field(value).finish(),
            Self::FederationEntityId(value) => formatter
                .debug_tuple("FederationEntityId")
                .field(&redacted_len(value.len()))
                .finish(),
            Self::OpaqueIdentifier(value) => formatter
                .debug_tuple("OpaqueIdentifier")
                .field(&redacted_len(value.len()))
                .finish(),
            Self::Uri(value) => formatter
                .debug_tuple("Uri")
                .field(&redacted_len(value.len()))
                .finish(),
            Self::Absent => formatter.write_str("Absent"),
        }
    }
}

impl core::fmt::Debug for PublicKeyIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PublicKeyIdentity")
            .field("alg", &self.alg)
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl core::fmt::Debug for X509SubjectReference {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CertificateSha256(_) => formatter.write_str("CertificateSha256([REDACTED])"),
            Self::IssuerAndSerial {
                issuer_name_der,
                serial_number,
            } => formatter
                .debug_struct("IssuerAndSerial")
                .field("issuer_name_der", &redacted_len(issuer_name_der.len()))
                .field("serial_number", &redacted_len(serial_number.len()))
                .finish(),
            Self::ValidatedCertificateDer(value) => formatter
                .debug_tuple("ValidatedCertificateDer")
                .field(&redacted_len(value.len()))
                .finish(),
        }
    }
}

impl core::fmt::Debug for HolderBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CryptographicKey(key) => formatter
                .debug_tuple("CryptographicKey")
                .field(key)
                .finish(),
            Self::ClaimsBased(claims) => formatter
                .debug_tuple("ClaimsBased")
                .field(&redacted_len(claims.len()))
                .finish(),
            Self::BearerWithoutBinding => formatter.write_str("BearerWithoutBinding"),
        }
    }
}

impl core::fmt::Debug for CredentialStatus {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialStatus")
            .field("status_list_url", &redacted_len(self.status_list_url.len()))
            .field("status_list_id", &redacted_len(self.status_list_id.len()))
            .field("status_list_index", &self.status_list_index)
            .field("purpose", &self.purpose)
            .finish()
    }
}

impl Zeroize for CredentialEnvelope {
    fn zeroize(&mut self) {
        self.profile_id.zeroize();
        self.issuer_reference.zeroize();
        self.issuer_country.zeroize();
        self.status.zeroize();
        self.subject.zeroize();
        self.claims_commitment.zeroize();
        if let Some(qeaa) = &mut self.qeaa_compliance {
            zeroize_qeaa(qeaa);
        }
        self.issuer_signature.zeroize();
    }
}

impl Drop for CredentialEnvelope {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CredentialEnvelope {}

impl Zeroize for CredentialSubject {
    fn zeroize(&mut self) {
        self.subject_reference.zeroize();
        self.holder_binding.zeroize();
    }
}

impl Drop for CredentialSubject {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CredentialSubject {}

impl Zeroize for PartyReference {
    fn zeroize(&mut self) {
        match self {
            Self::Did(value)
            | Self::FederationEntityId(value)
            | Self::OpaqueIdentifier(value)
            | Self::Uri(value) => value.zeroize(),
            Self::X509Subject(value) => value.zeroize(),
            Self::PublicKey(value) => value.zeroize(),
            Self::Absent => {}
        }
    }
}

impl Drop for PartyReference {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PartyReference {}

impl Zeroize for X509SubjectReference {
    fn zeroize(&mut self) {
        match self {
            Self::CertificateSha256(value) => value.zeroize(),
            Self::IssuerAndSerial {
                issuer_name_der,
                serial_number,
            } => {
                issuer_name_der.zeroize();
                serial_number.zeroize();
            }
            Self::ValidatedCertificateDer(value) => value.zeroize(),
        }
    }
}

impl Drop for X509SubjectReference {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for X509SubjectReference {}

impl Zeroize for PublicKeyIdentity {
    fn zeroize(&mut self) {
        self.alg = CredentialAlgorithm::Unspecified;
        self.public_key.zeroize();
    }
}

impl Drop for PublicKeyIdentity {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PublicKeyIdentity {}

impl Zeroize for HolderBinding {
    fn zeroize(&mut self) {
        match self {
            Self::CryptographicKey(value) => value.zeroize(),
            Self::ClaimsBased(values) => values.zeroize(),
            Self::BearerWithoutBinding => {}
        }
    }
}

impl Drop for HolderBinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for HolderBinding {}

impl Zeroize for CredentialStatus {
    fn zeroize(&mut self) {
        self.status_list_url.zeroize();
        self.status_list_id.zeroize();
    }
}

impl Drop for CredentialStatus {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CredentialStatus {}

fn zeroize_qeaa(qeaa: &mut QeaaCompliance) {
    qeaa.qtsp.tsp_name.zeroize();
    qeaa.qtsp.tsp_id.zeroize();
    qeaa.policies.policy_id.zeroize();
    qeaa.policies.standards.zeroize();
    qeaa.issuer_credential.cert_fingerprint_sha256.zeroize();
    qeaa.issuer_credential.cert_chain_der.zeroize();
    qeaa.issuer_credential.trusted_list_ref.zeroize();
    qeaa.issuer_credential.policy_oids.zeroize();
    qeaa.issuer_credential.qcstatements_oids.zeroize();
    qeaa.key_management.signing_key_id.zeroize();
    qeaa.identity_proofing.standard.zeroize();
    qeaa.identity_proofing.evidence_ref.zeroize();
    qeaa.identity_proofing.evidence_hash.zeroize();
    qeaa.audit.audit_standard.zeroize();
    qeaa.audit.audit_report_ref.zeroize();
    qeaa.audit.audit_report_hash.zeroize();
    qeaa.revocation.signing_key_id.zeroize();
}

fn redacted_len(len: usize) -> RedactedLen {
    RedactedLen { len }
}

struct RedactedLen {
    len: usize,
}

impl core::fmt::Debug for RedactedLen {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("redacted")
            .field("len", &self.len)
            .finish()
    }
}
