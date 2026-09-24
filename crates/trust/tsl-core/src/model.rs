// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Canonical European Commission URL for the EU List of Trusted Lists.
pub const EU_LOTL_URL: &str = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

/// Maximum accepted URI length at a trusted-list boundary.
pub const MAX_TSL_URI_BYTES: usize = 2_048;

/// Supported trusted-list semantic version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum TslVersion {
    /// ETSI TS 119 612 v2.4.1 clause 5.3.1 trusted-list format version.
    V6,
}

/// UTC timestamp represented without retaining attacker-controlled source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct TslTimestamp {
    unix_seconds: i64,
    nanosecond: u32,
}

impl TslTimestamp {
    pub(crate) fn new(unix_seconds: i64, nanosecond: u32) -> Self {
        Self {
            unix_seconds,
            nanosecond,
        }
    }

    /// Whole seconds since the Unix epoch.
    pub fn unix_seconds(self) -> i64 {
        self.unix_seconds
    }

    /// Fractional nanoseconds from the source timestamp.
    pub fn nanosecond(self) -> u32 {
        self.nanosecond
    }
}

/// Length-bounded absolute URI.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop)]
pub struct TslUri(String);

impl TslUri {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// Borrow the validated URI source form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the URI uses HTTPS.
    pub fn is_https(&self) -> bool {
        url::Url::parse(&self.0).is_ok_and(|value| value.scheme().eq_ignore_ascii_case("https"))
    }

    /// Normalized network origin, when the URI has an authority.
    pub fn origin(&self) -> Option<TslOrigin> {
        TslOrigin::from_uri(&self.0)
    }
}

impl core::fmt::Debug for TslUri {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TslUri(<redacted>)")
    }
}

/// Canonical network origin used to authorize pointer fetch targets.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TslOrigin(String);

impl TslOrigin {
    /// Parse an HTTP(S) origin and discard all path, query, and fragment data.
    pub fn parse(value: &str) -> Option<Self> {
        Self::from_uri(value)
    }

    fn from_uri(value: &str) -> Option<Self> {
        let parsed = url::Url::parse(value).ok()?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return None;
        }
        let origin = parsed.origin().ascii_serialization();
        if origin == "null" {
            return None;
        }
        Some(Self(origin))
    }
}

impl core::fmt::Debug for TslOrigin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TslOrigin(<redacted>)")
    }
}

/// Media type established by the app-owned pointer fetch boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum TslMediaType {
    /// Normative TS 119 612 clause 6.2.1.1 media type.
    EtsiTrustedListXml,
    /// Human-readable representation carried by the EU LOTL profile.
    Pdf,
    ApplicationXml,
    TextXml,
    Unsupported,
}

impl TslMediaType {
    /// Parse a bounded Content-Type value without retaining attacker text.
    pub fn parse(value: &str) -> Self {
        const MAX_CONTENT_TYPE_BYTES: usize = 128;
        if value.is_empty() || value.len() > MAX_CONTENT_TYPE_BYTES {
            return Self::Unsupported;
        }
        let essence = value.split(';').next().map(str::trim).unwrap_or_default();
        if essence.eq_ignore_ascii_case("application/vnd.etsi.tsl+xml") {
            Self::EtsiTrustedListXml
        } else if essence.eq_ignore_ascii_case("application/pdf") {
            Self::Pdf
        } else if essence.eq_ignore_ascii_case("application/xml") {
            Self::ApplicationXml
        } else if essence.eq_ignore_ascii_case("text/xml") {
            Self::TextXml
        } else {
            Self::Unsupported
        }
    }
}

/// Language-tagged TSL name or notice.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct LocalizedText {
    pub language: String,
    pub value: String,
}

/// Language-tagged, length-bounded absolute URI.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct LocalizedUri {
    pub language: String,
    pub uri: TslUri,
}

impl core::fmt::Debug for LocalizedUri {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LocalizedUri")
            .field("language", &self.language)
            .field("uri", &"<redacted>")
            .finish()
    }
}

/// Length-bounded postal address retained at the authenticated TSL boundary.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TslPostalAddress {
    pub language: String,
    pub street_address: String,
    pub locality: String,
    pub state_or_province: Option<String>,
    pub postal_code: Option<String>,
    pub country_code: String,
}

impl core::fmt::Debug for TslPostalAddress {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TslPostalAddress")
            .field("language", &self.language)
            .field("country_code", &self.country_code)
            .field("address", &"<redacted>")
            .finish()
    }
}

/// Postal and electronic address tuple from TS 119 612 clauses 5.3.5 and 5.4.3.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TslAddress {
    pub postal_addresses: Vec<TslPostalAddress>,
    pub electronic_addresses: Vec<LocalizedUri>,
}

/// Registration-identifier namespace used by TS 119 612 clause 5.4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum TspRegistrationIdentifierKind {
    ValueAddedTax,
    NationalTradeRegister,
    Passport,
    IdentityCard,
    PersonalNumber,
    TaxIdentificationNumber,
}

/// One TSP registration identity projected from `TSPTradeName`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TspRegistrationIdentifier {
    pub kind: TspRegistrationIdentifierKind,
    pub country_code: String,
    pub value: String,
}

impl core::fmt::Debug for TspRegistrationIdentifier {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TspRegistrationIdentifier")
            .field("kind", &self.kind)
            .field("country_code", &self.country_code)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl core::fmt::Debug for LocalizedText {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LocalizedText")
            .field("language", &self.language)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Known service type or a bounded future URI retained without reclassification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop)]
pub enum TrustServiceType {
    CaQualifiedCertificates,
    OcspQualifiedCertificates,
    QualifiedTimestamp,
    QualifiedElectronicAttestation,
    Other(TslUri),
}

/// Known ETSI service status or a bounded future URI.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum TrustServiceStatus {
    Granted,
    Expired,
    Withdrawn,
    DeprecatedAtNationalLevel,
    RecognisedAtNationalLevel,
    UnderSupervision,
    SupervisionCeased,
    SupervisionRevoked,
    Accredited,
    AccreditationCeased,
    AccreditationRevoked,
    Other(TslUri),
}

/// Known TS 119 612 service classification or a bounded scheme-specific URI.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum AdditionalServiceInformationKind {
    ForElectronicSignatures,
    ForElectronicSeals,
    ForWebsiteAuthentication,
    RootCaQualifiedCertificates,
    Other(TslUri),
}

/// Additional service classification retained from a service extension.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AdditionalServiceInformation {
    pub kind: AdditionalServiceInformationKind,
    pub information_value: Option<String>,
}

/// Known qualifier from TS 119 612 clause 5.5.9.2.3.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum ServiceQualifierKind {
    QualifiedCertificateWithSscd,
    QualifiedCertificateWithoutSscd,
    SscdStatusAsInCertificate,
    QualifiedCertificateWithQscd,
    QualifiedCertificateWithoutQscd,
    QscdStatusAsInCertificate,
    QscdManagedOnBehalf,
    QualifiedCertificateForLegalPerson,
    QualifiedCertificateForElectronicSignature,
    QualifiedCertificateForElectronicSeal,
    QualifiedCertificateForWebsiteAuthentication,
    NotQualified,
    QualifiedCertificateStatement,
    Other(TslUri),
}

/// Qualification result assigned when its complete criteria tree matches.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ServiceQualifier {
    pub kind: ServiceQualifierKind,
}

/// Boolean composition mode for one TS 119 612 `CriteriaList`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum QualificationAssertion {
    All,
    AtLeastOne,
    None,
}

/// X.509 key-usage bit named by a qualification assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum QualificationKeyUsageBit {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

/// Expected value for one X.509 key-usage bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct QualificationKeyUsage {
    pub bit: QualificationKeyUsageBit,
    pub expected: bool,
}

/// Length-bounded, syntactically validated object identifier.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop)]
pub struct TslObjectIdentifier(String);

/// Maximum dotted-decimal OID length retained from a qualification.
pub const MAX_TSL_OBJECT_IDENTIFIER_BYTES: usize = 128;

/// Fixed reason for rejecting a dotted-decimal qualification OID.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum TslObjectIdentifierError {
    #[error("object identifier is not canonical dotted-decimal syntax")]
    InvalidSyntax,
}

impl TslObjectIdentifier {
    /// Parse a bounded, canonical dotted-decimal object identifier.
    pub fn parse(value: &str) -> Result<Self, TslObjectIdentifierError> {
        if value.is_empty() || value.len() > MAX_TSL_OBJECT_IDENTIFIER_BYTES {
            return Err(TslObjectIdentifierError::InvalidSyntax);
        }
        let mut arcs = value.split('.');
        let first = arcs.next().ok_or(TslObjectIdentifierError::InvalidSyntax)?;
        let second = arcs.next().ok_or(TslObjectIdentifierError::InvalidSyntax)?;
        if !matches!(first, "0" | "1" | "2")
            || !valid_object_identifier_arc(second)
            || !arcs.all(valid_object_identifier_arc)
        {
            return Err(TslObjectIdentifierError::InvalidSyntax);
        }
        if matches!(first, "0" | "1")
            && second
                .parse::<u32>()
                .map_or(true, |second_arc| second_arc > 39)
        {
            return Err(TslObjectIdentifierError::InvalidSyntax);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_object_identifier_arc(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|character| character.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

impl core::fmt::Debug for TslObjectIdentifier {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TslObjectIdentifier(<redacted>)")
    }
}

/// One certificate assertion contained in a qualification criteria list.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum QualificationCriterion {
    KeyUsage(Vec<QualificationKeyUsage>),
    CertificatePolicies(Vec<TslObjectIdentifier>),
    ExtendedKeyUsage(Vec<TslObjectIdentifier>),
    SubjectDistinguishedNameAttributes(Vec<TslObjectIdentifier>),
    Nested(QualificationCriteria),
}

/// Recursively composed, bounded certificate-filter criteria.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct QualificationCriteria {
    pub assertion: QualificationAssertion,
    pub criteria: Vec<QualificationCriterion>,
    pub description: Option<String>,
}

/// One complete qualification element: filters plus resulting qualifiers.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ServiceQualification {
    pub qualifiers: Vec<ServiceQualifier>,
    pub criteria: QualificationCriteria,
}

/// XMLDSig public-key representation retained for cross-representation checks.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum XmlDsigKeyValue {
    Rsa {
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    },
    Dsa {
        p: Option<Vec<u8>>,
        q: Option<Vec<u8>>,
        g: Option<Vec<u8>>,
        y: Vec<u8>,
        j: Option<Vec<u8>>,
        seed: Option<Vec<u8>>,
        pgen_counter: Option<Vec<u8>>,
    },
    /// XML Signature 1.1 named-curve public key.
    Ec {
        named_curve: TslObjectIdentifier,
        public_key: Vec<u8>,
    },
}

impl core::fmt::Debug for XmlDsigKeyValue {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rsa { .. } => formatter.write_str("XmlDsigKeyValue::Rsa(<redacted>)"),
            Self::Dsa { .. } => formatter.write_str("XmlDsigKeyValue::Dsa(<redacted>)"),
            Self::Ec { .. } => formatter.write_str("XmlDsigKeyValue::Ec(<redacted>)"),
        }
    }
}

mod digital_identity;
pub use digital_identity::{
    PkiServiceDigitalIdentity, ServiceDigitalIdentity, TslNonPkiIdentifier,
};

include!("model/records.rs");
