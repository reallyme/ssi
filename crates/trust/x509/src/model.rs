// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

mod chain;
mod describe_certificate;
mod key_identifier;
pub use chain::X509Chain;
pub use describe_certificate::X509Certificate;

/// Maximum certificate count accepted for a presented X.509 chain.
///
/// Typical eIDAS/QTSP paths are short; this bound keeps hostile-input work deterministic.
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

/// Bounded dotted-decimal object identifier.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct ObjectIdentifier(String);

impl ObjectIdentifier {
    /// Parses a length-bounded dotted-decimal object identifier.
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

    /// Borrows the canonical dotted-decimal form.
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
#[non_exhaustive]
pub enum CertificateVersion {
    /// X.509 version 1.
    V1,
    /// X.509 version 2.
    V2,
    /// X.509 version 3.
    #[default]
    V3,
}

/// Known certificate extension or a bounded unknown OID.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum CertificateExtensionKind {
    /// Basic Constraints extension.
    BasicConstraints,
    /// Key Usage extension.
    KeyUsage,
    /// Extended Key Usage extension.
    ExtendedKeyUsage,
    /// Subject Key Identifier extension.
    SubjectKeyIdentifier,
    /// Authority Key Identifier extension.
    AuthorityKeyIdentifier,
    /// Subject Alternative Name extension.
    SubjectAlternativeName,
    /// Certificate Policies extension.
    CertificatePolicies,
    /// Authority Information Access extension.
    AuthorityInformationAccess,
    /// CRL Distribution Points extension.
    CrlDistributionPoints,
    /// ETSI QCStatements extension.
    QcStatements,
    /// RFC 9608 `noRevAvail` extension.
    NoRevAvail,
    /// Unrecognized extension retained by object identifier.
    Other(ObjectIdentifier),
}

/// Extension identity and criticality retained for policy enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CertificateExtension {
    /// Extension identity.
    pub kind: CertificateExtensionKind,
    /// Criticality bit from the extension wrapper.
    pub critical: bool,
}

/// Typed RDN attribute identifier.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum NameAttributeKind {
    /// Common Name (`CN`).
    CommonName,
    /// Country Name (`C`).
    CountryName,
    /// Given Name.
    GivenName,
    /// Surname.
    Surname,
    /// Pseudonym.
    Pseudonym,
    /// Organization Name (`O`).
    OrganizationName,
    /// Organizational Unit Name (`OU`).
    OrganizationalUnitName,
    /// Locality Name (`L`).
    LocalityName,
    /// State or Province Name (`ST`).
    StateOrProvinceName,
    /// Serial Number.
    SerialNumber,
    /// Street Address.
    StreetAddress,
    /// Postal Code.
    PostalCode,
    /// Domain Component (`DC`).
    DomainComponent,
    /// Email Address.
    EmailAddress,
    /// Organization Identifier.
    OrganizationIdentifier,
    /// Telephone Number.
    TelephoneNumber,
    /// Unrecognized attribute retained by object identifier.
    Other(ObjectIdentifier),
}

/// Typed attribute value without flattening multi-valued RDNs.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum NameAttributeValue {
    /// Decoded textual value.
    Text(String),
    /// DER content bytes for a non-textual value.
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

/// One typed attribute from a relative distinguished name.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct NameAttribute {
    /// Attribute type.
    pub kind: NameAttributeKind,
    /// Attribute value.
    pub value: NameAttributeValue,
}

/// Ordered attributes from one relative distinguished name.
#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct RelativeDistinguishedName {
    /// Attributes belonging to this relative distinguished name.
    pub attributes: Vec<NameAttribute>,
}

/// Ordered relative distinguished names from an X.509 Name.
#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct DistinguishedName {
    /// Relative distinguished names in encoded order.
    pub rdns: Vec<RelativeDistinguishedName>,
}

/// Typed `otherName` subject-alt-name value.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct OtherName {
    /// Object identifier naming the `otherName` syntax.
    pub type_id: ObjectIdentifier,
    /// DER-encoded value.
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
    /// URIs from the authenticated certificate.
    pub uris: Vec<String>,
    /// Email addresses from the authenticated certificate.
    pub email_addresses: Vec<String>,
    /// Other names from the authenticated certificate.
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
#[non_exhaustive]
pub enum AuthorityAccessMethod {
    /// Online Certificate Status Protocol endpoint.
    Ocsp,
    /// CA Issuers certificate-discovery endpoint.
    CaIssuers,
    /// Unrecognized access method retained by object identifier.
    Other(ObjectIdentifier),
}

/// URI-valued Authority Information Access descriptor.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AuthorityAccessDescription {
    /// Access method.
    pub method: AuthorityAccessMethod,
    /// Access-location URI.
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

include!("model/describe_algorithms.rs");

/// Typed certificate policy identifier.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum CertificatePolicyId {
    /// ETSI QCP for a natural person.
    QcpNaturalPerson,
    /// ETSI QCP for a legal person.
    QcpLegalPerson,
    /// ETSI QCP for a natural person using a QSCD.
    QcpNaturalPersonQscd,
    /// ETSI QCP for a legal person using a QSCD.
    QcpLegalPersonQscd,
    /// ETSI QEVCP-w website-authentication policy.
    QevcpWeb,
    /// ETSI QNCP-w website-authentication policy.
    QncpWeb,
    /// ETSI generic QNCP-w website-authentication policy.
    QncpWebGeneric,
    /// ETSI TS 119 411-8 NCP for a natural-person wallet relying party.
    WrpacNcpNatural,
    /// ETSI TS 119 411-8 NCP for a legal-person wallet relying party.
    WrpacNcpLegal,
    /// ETSI TS 119 411-8 QCP for a natural-person wallet relying party.
    WrpacQcpNatural,
    /// ETSI TS 119 411-8 QCP for a legal-person wallet relying party.
    WrpacQcpLegal,
    /// Unrecognized policy retained by object identifier.
    Other(ObjectIdentifier),
}

/// Extended Key Usage purpose with bounded unknown preservation.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum ExtendedKeyUsagePurpose {
    /// Any Extended Key Usage purpose.
    Any,
    /// TLS server authentication.
    ServerAuthentication,
    /// TLS client authentication.
    ClientAuthentication,
    /// Code signing.
    CodeSigning,
    /// Email protection.
    EmailProtection,
    /// Time stamping.
    TimeStamping,
    /// OCSP response signing.
    OcspSigning,
    /// Unrecognized purpose retained by object identifier.
    Other(ObjectIdentifier),
}

/// Typed QC statement identifier.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum QcStatementId {
    /// ETSI QcCompliance statement.
    Compliance,
    /// ETSI QcLimitValue statement.
    LimitValue,
    /// ETSI QcRetentionPeriod statement.
    RetentionPeriod,
    /// ETSI QcSSCD statement.
    QcSscd,
    /// ETSI QcPDS statement.
    Pds,
    /// ETSI QcType statement.
    Type,
    /// Unrecognized statement retained by object identifier.
    Other(ObjectIdentifier),
}

/// Typed ETSI QcType value.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum QcType {
    /// Electronic-signature certificate.
    ElectronicSignature,
    /// Electronic-seal certificate.
    ElectronicSeal,
    /// Website-authentication certificate.
    WebAuthentication,
    /// ETSI TS 119 412-6 PID-provider sign/seal certificate.
    PidProvider,
    /// ETSI TS 119 412-6 wallet-provider sign/seal certificate.
    WalletProvider,
    /// Unrecognized QC type retained by object identifier.
    Other(ObjectIdentifier),
}

/// Audit-facing, typed X.509 projection.
#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct CertificateProfile {
    /// Certificate syntax version.
    pub version: CertificateVersion,
    /// Subject distinguished name.
    pub subject: DistinguishedName,
    /// Issuer distinguished name.
    pub issuer: DistinguishedName,
    /// Extension identities and criticality bits.
    pub extensions: Vec<CertificateExtension>,
    /// Typed Subject Alternative Name values.
    pub subject_alternative_names: SubjectAlternativeNames,
    /// Authority Information Access descriptors.
    pub authority_information_access: Vec<AuthorityAccessDescription>,
    /// Validated CRL Distribution Point URIs.
    pub crl_distribution_point_uris: Vec<String>,
    /// Whether the certificate asserts RFC 9608 `noRevAvail`.
    pub no_rev_avail: bool,
    /// Subject public-key algorithm and measured strength.
    pub public_key: PublicKeyProfile,
    /// RFC 8017 Section 3.1 RSA public exponent, when the SPKI is RSA.
    pub rsa_public_exponent: Option<Vec<u8>>,
    /// Certificate signature algorithm.
    pub signature_algorithm: SignatureAlgorithm,
    /// RFC 4055 parameters when `signature_algorithm` is RSA-PSS.
    pub rsa_pss_parameters: Option<RsaPssParameters>,
    /// Extended Key Usage purposes.
    pub extended_key_usage: Vec<ExtendedKeyUsagePurpose>,
    /// Certificate-policy object identifiers asserted by the certificate.
    pub certificate_policies: Vec<CertificatePolicyId>,
    /// RFC 5280 Section 4.2.1.4 CPS pointer qualifiers, preserved as IA5 URIs.
    pub certificate_policy_cps_uris: Vec<String>,
    /// ETSI QC statement identifiers.
    pub qc_statement_ids: Vec<QcStatementId>,
    /// ETSI QcType values.
    pub qc_types: Vec<QcType>,
}

/// Statement and type OIDs from the ETSI QCStatements extension.
#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct QcStatements {
    /// All `statementId` OIDs in the extension.
    pub statement_ids: Vec<String>,

    /// QcType OIDs contained in an ETSI QcType statement.
    pub qc_types: Vec<String>,
}

/// Security-relevant values from the Basic Constraints extension.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct BasicConstraints {
    /// Whether the certificate asserts `CA:TRUE`.
    pub ca: bool,
    /// Maximum subordinate CA depth, when present.
    pub path_len_constraint: Option<u32>,
}

/// Bit-level projection of the X.509 Key Usage extension.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KeyUsage {
    /// `digitalSignature` bit.
    pub digital_signature: bool,
    /// `contentCommitment` bit.
    pub content_commitment: bool,
    /// `keyCertSign` bit.
    pub key_cert_sign: bool,
    /// `cRLSign` bit.
    pub crl_sign: bool,
    /// `keyEncipherment` bit.
    pub key_encipherment: bool,
    /// `dataEncipherment` bit.
    pub data_encipherment: bool,
    /// `keyAgreement` bit.
    pub key_agreement: bool,
    /// `encipherOnly` bit.
    pub encipher_only: bool,
    /// `decipherOnly` bit.
    pub decipher_only: bool,
}
