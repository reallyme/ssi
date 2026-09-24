// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod chain;
pub use chain::X509Chain;

/// Maximum certificate count accepted for a presented X.509 chain.
///
/// Typical eIDAS/QTSP paths are short. This bound keeps parsing, policy
/// screening, and signature verification deterministic for hostile inputs.
pub const MAX_X509_CHAIN_CERTIFICATES: usize = 10;
/// Maximum DER size accepted for one certificate at the parser boundary.
pub const MAX_X509_CERTIFICATE_DER_BYTES: usize = 65_536;
/// Maximum PEM size accepted for one encoded certificate.
pub const MAX_X509_CERTIFICATE_PEM_BYTES: usize = 98_304;
/// Maximum PEM bundle size accepted before certificate extraction.
pub const MAX_X509_CHAIN_PEM_BYTES: usize = 1_048_576;
/// Maximum number of extensions accepted from one certificate.
pub const MAX_X509_EXTENSIONS: usize = 64;
/// Maximum dotted-decimal OID length retained for an unknown identifier.
pub const MAX_X509_OID_CHARS: usize = 128;
/// RFC 5280 Section 4.1.2.2 maximum serial-number content length.
pub const MAX_X509_SERIAL_BYTES: usize = 20;

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct X509Certificate {
    pub der: Vec<u8>,
    pub subject: String,
    pub issuer: String,
    pub serial: Vec<u8>,
    #[zeroize(skip)]
    pub not_before: OffsetDateTime,
    #[zeroize(skip)]
    pub not_after: OffsetDateTime,
    pub spki_der: Vec<u8>,
    pub signature_algorithm_oid: String,

    pub basic_constraints: Option<BasicConstraints>,
    pub key_usage: Option<KeyUsage>,
    pub extended_key_usage: Option<Vec<String>>, // EKU OIDs

    pub subject_key_identifier: Option<Vec<u8>>,
    pub authority_key_identifier: Option<Vec<u8>>,

    pub san_dns: Vec<String>,
    pub san_ip: Vec<Vec<u8>>,

    // NEW: CertificatePolicies (policyIdentifier OIDs)
    pub certificate_policies: Vec<String>,

    // NEW: qcStatements (RFC3739 / ETSI EN 319 412-5)
    pub qc_statements: QcStatements,

    /// Lossless, typed projection used by audit-facing profile evaluation.
    pub profile: CertificateProfile,
}

impl core::fmt::Debug for X509Certificate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("X509Certificate")
            .field("der", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("issuer", &"<redacted>")
            .field("serial", &"<redacted>")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("spki_der", &"<redacted>")
            .field("signature_algorithm_oid", &self.signature_algorithm_oid)
            .field("basic_constraints", &self.basic_constraints)
            .field("key_usage", &self.key_usage)
            .field("extended_key_usage", &"<redacted>")
            .field("subject_key_identifier", &"<redacted>")
            .field("authority_key_identifier", &"<redacted>")
            .field("san_dns", &"<redacted>")
            .field("san_ip", &"<redacted>")
            .field("certificate_policies", &"<redacted>")
            .field("qc_statements", &"<redacted>")
            .field("profile", &self.profile)
            .finish()
    }
}

/// Bounded dotted-decimal object identifier.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop)]
pub struct ObjectIdentifier(String);

impl ObjectIdentifier {
    /// Parse and bound a dotted-decimal OID.
    pub fn parse(value: &str) -> Option<Self> {
        if value.is_empty()
            || value.len() > MAX_X509_OID_CHARS
            || value.starts_with('.')
            || value.ends_with('.')
            || value
                .split('.')
                .any(|arc| arc.is_empty() || !arc.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return None;
        }
        Some(Self(value.to_owned()))
    }

    /// Borrow the canonical dotted-decimal form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for ObjectIdentifier {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ObjectIdentifier")
            .field(&self.0)
            .finish()
    }
}

/// X.509 certificate syntax version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Zeroize)]
pub enum CertificateVersion {
    V1,
    V2,
    #[default]
    V3,
}

/// Known certificate extension or a bounded unknown OID.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum CertificateExtensionKind {
    BasicConstraints,
    KeyUsage,
    ExtendedKeyUsage,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
    SubjectAlternativeName,
    CertificatePolicies,
    AuthorityInformationAccess,
    CrlDistributionPoints,
    QcStatements,
    NoRevAvail,
    Other(ObjectIdentifier),
}

/// Extension identity and criticality retained for policy enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CertificateExtension {
    pub kind: CertificateExtensionKind,
    pub critical: bool,
}

/// Typed RDN attribute identifier.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum NameAttributeKind {
    CommonName,
    CountryName,
    GivenName,
    Surname,
    Pseudonym,
    OrganizationName,
    OrganizationalUnitName,
    LocalityName,
    StateOrProvinceName,
    SerialNumber,
    StreetAddress,
    PostalCode,
    DomainComponent,
    EmailAddress,
    OrganizationIdentifier,
    TelephoneNumber,
    Other(ObjectIdentifier),
}

/// Typed attribute value without flattening multi-valued RDNs.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum NameAttributeValue {
    Text(String),
    Binary(Vec<u8>),
}

impl core::fmt::Debug for NameAttributeValue {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Text(_) => formatter.write_str("Text(<redacted>)"),
            Self::Binary(_) => formatter.write_str("Binary(<redacted>)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct NameAttribute {
    pub kind: NameAttributeKind,
    pub value: NameAttributeValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct RelativeDistinguishedName {
    pub attributes: Vec<NameAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct DistinguishedName {
    pub rdns: Vec<RelativeDistinguishedName>,
}

/// Typed `otherName` subject-alt-name value.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct OtherName {
    pub type_id: ObjectIdentifier,
    pub value_der: Vec<u8>,
}

impl core::fmt::Debug for OtherName {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OtherName")
            .field("type_id", &self.type_id)
            .field("value_der", &"<redacted>")
            .finish()
    }
}

/// Additional subject alternative names required by relying-party profiles.
#[derive(Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct SubjectAlternativeNames {
    pub uris: Vec<String>,
    pub email_addresses: Vec<String>,
    pub other_names: Vec<OtherName>,
}

impl core::fmt::Debug for SubjectAlternativeNames {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SubjectAlternativeNames")
            .field("uris", &"<redacted>")
            .field("email_addresses", &"<redacted>")
            .field("other_names", &"<redacted>")
            .finish()
    }
}

/// Authority Information Access method.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum AuthorityAccessMethod {
    Ocsp,
    CaIssuers,
    Other(ObjectIdentifier),
}

/// URI-valued Authority Information Access descriptor.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AuthorityAccessDescription {
    pub method: AuthorityAccessMethod,
    pub uri: String,
}

impl core::fmt::Debug for AuthorityAccessDescription {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthorityAccessDescription")
            .field("method", &self.method)
            .field("uri", &"<redacted>")
            .finish()
    }
}

/// Public-key algorithm and measured strength.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum PublicKeyProfile {
    Rsa {
        bits: u16,
    },
    Ec {
        bits: u16,
        curve: Option<ObjectIdentifier>,
    },
    Ed25519,
    Ed448,
    Dsa {
        bits: u16,
    },
    Other {
        algorithm: ObjectIdentifier,
        bits: u16,
    },
}

/// Closed public-key algorithm family used by versioned profile policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum PublicKeyAlgorithm {
    Rsa,
    Ec,
    Ed25519,
    Ed448,
    Dsa,
    Other,
}

impl PublicKeyProfile {
    /// Returns the typed algorithm family without reparsing an OID.
    pub const fn algorithm(&self) -> PublicKeyAlgorithm {
        match self {
            Self::Rsa { .. } => PublicKeyAlgorithm::Rsa,
            Self::Ec { .. } => PublicKeyAlgorithm::Ec,
            Self::Ed25519 => PublicKeyAlgorithm::Ed25519,
            Self::Ed448 => PublicKeyAlgorithm::Ed448,
            Self::Dsa { .. } => PublicKeyAlgorithm::Dsa,
            Self::Other { .. } => PublicKeyAlgorithm::Other,
        }
    }
}

impl Default for PublicKeyProfile {
    fn default() -> Self {
        Self::Other {
            algorithm: ObjectIdentifier("0.0".to_owned()),
            bits: 0,
        }
    }
}

/// Typed certificate-signature algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum SignatureAlgorithm {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPss,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    Ed25519,
    Ed448,
    Other(ObjectIdentifier),
}

/// Hash algorithm carried by an RSA-PSS algorithm identifier.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum RsaPssHashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Other(ObjectIdentifier),
}

/// Mask-generation algorithm carried by RSA-PSS parameters.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum RsaPssMaskGenerationAlgorithm {
    Mgf1(RsaPssHashAlgorithm),
    Other(ObjectIdentifier),
}

/// Lossless security-relevant projection of RFC 4055 RSA-PSS parameters.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RsaPssParameters {
    pub hash_algorithm: RsaPssHashAlgorithm,
    pub mask_generation_algorithm: RsaPssMaskGenerationAlgorithm,
    pub salt_length: u32,
    pub trailer_field: u32,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::Other(ObjectIdentifier("0.0".to_owned()))
    }
}

/// Typed certificate policy identifier.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum CertificatePolicyId {
    QcpNaturalPerson,
    QcpLegalPerson,
    QcpNaturalPersonQscd,
    QcpLegalPersonQscd,
    QevcpWeb,
    QncpWeb,
    QncpWebGeneric,
    /// ETSI TS 119 411-8 NCP for a natural-person wallet relying party.
    WrpacNcpNatural,
    /// ETSI TS 119 411-8 NCP for a legal-person wallet relying party.
    WrpacNcpLegal,
    /// ETSI TS 119 411-8 QCP for a natural-person wallet relying party.
    WrpacQcpNatural,
    /// ETSI TS 119 411-8 QCP for a legal-person wallet relying party.
    WrpacQcpLegal,
    Other(ObjectIdentifier),
}

/// Extended Key Usage purpose with bounded unknown preservation.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum ExtendedKeyUsagePurpose {
    Any,
    ServerAuthentication,
    ClientAuthentication,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
    Other(ObjectIdentifier),
}

/// Typed QC statement identifier.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum QcStatementId {
    Compliance,
    LimitValue,
    RetentionPeriod,
    QcSscd,
    Pds,
    Type,
    Other(ObjectIdentifier),
}

/// Typed ETSI QcType value.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum QcType {
    ElectronicSignature,
    ElectronicSeal,
    WebAuthentication,
    /// ETSI TS 119 412-6 PID-provider sign/seal certificate.
    PidProvider,
    /// ETSI TS 119 412-6 wallet-provider sign/seal certificate.
    WalletProvider,
    Other(ObjectIdentifier),
}

/// Audit-facing, typed X.509 projection.
#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct CertificateProfile {
    pub version: CertificateVersion,
    pub subject: DistinguishedName,
    pub issuer: DistinguishedName,
    pub extensions: Vec<CertificateExtension>,
    pub subject_alternative_names: SubjectAlternativeNames,
    pub authority_information_access: Vec<AuthorityAccessDescription>,
    pub crl_distribution_point_uris: Vec<String>,
    pub no_rev_avail: bool,
    pub public_key: PublicKeyProfile,
    /// RFC 8017 Section 3.1 RSA public exponent, when the SPKI is RSA.
    pub rsa_public_exponent: Option<Vec<u8>>,
    pub signature_algorithm: SignatureAlgorithm,
    /// RFC 4055 parameters when `signature_algorithm` is RSA-PSS.
    pub rsa_pss_parameters: Option<RsaPssParameters>,
    pub extended_key_usage: Vec<ExtendedKeyUsagePurpose>,
    pub certificate_policies: Vec<CertificatePolicyId>,
    /// RFC 5280 Section 4.2.1.4 CPS pointer qualifiers, preserved as IA5 URIs.
    pub certificate_policy_cps_uris: Vec<String>,
    pub qc_statement_ids: Vec<QcStatementId>,
    pub qc_types: Vec<QcType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct QcStatements {
    /// All QCStatement statementId OIDs present in qcStatements extension
    pub statement_ids: Vec<String>,

    /// For QcType statement, the contained qcType OIDs (e.g., qct-web / qct-esign / qct-eseal)
    pub qc_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len_constraint: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub content_commitment: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}
