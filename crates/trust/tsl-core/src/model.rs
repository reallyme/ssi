// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Canonical European Commission URL for the EU List of Trusted Lists.
pub const EU_LOTL_URL: &str = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

/// ETSI list-type URI for the EU List of Trusted Lists.
pub const EU_LOTL_TSL_TYPE: &str =
    "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";

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
    /// Parses an HTTP(S) origin and discards path, query, and fragment data.
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
    /// Generic `application/xml` media type.
    ApplicationXml,
    /// Generic `text/xml` media type.
    TextXml,
    /// Media type not accepted for trusted-list processing.
    Unsupported,
}

impl TslMediaType {
    /// Parses a bounded Content-Type value without retaining attacker text.
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
    /// Language tag associated with the value.
    pub language: String,
    /// Localized text.
    pub value: String,
}

/// Language-tagged, length-bounded absolute URI.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct LocalizedUri {
    /// Language tag associated with the URI.
    pub language: String,
    /// Validated absolute URI.
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
    /// Language tag associated with the address.
    pub language: String,
    /// Street-address component.
    pub street_address: String,
    /// Locality or city component.
    pub locality: String,
    /// State or province when present.
    pub state_or_province: Option<String>,
    /// Postal code when present.
    pub postal_code: Option<String>,
    /// ISO country code.
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
    /// Localized postal addresses.
    pub postal_addresses: Vec<TslPostalAddress>,
    /// Localized electronic-address URIs.
    pub electronic_addresses: Vec<LocalizedUri>,
}

/// Registration-identifier namespace used by TS 119 612 clause 5.4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum TspRegistrationIdentifierKind {
    /// Value-added tax identifier.
    ValueAddedTax,
    /// National trade-register identifier.
    NationalTradeRegister,
    /// Passport identifier.
    Passport,
    /// Identity-card identifier.
    IdentityCard,
    /// Personal-number identifier.
    PersonalNumber,
    /// Tax-identification number.
    TaxIdentificationNumber,
}

/// One TSP registration identity projected from `TSPTradeName`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TspRegistrationIdentifier {
    /// Registration-identifier namespace.
    pub kind: TspRegistrationIdentifierKind,
    /// Country code embedded in the identifier.
    pub country_code: String,
    /// Identifier value without its namespace and country prefix.
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
    /// Qualified-certificate certification authority.
    CaQualifiedCertificates,
    /// OCSP service for qualified certificates.
    OcspQualifiedCertificates,
    /// Qualified timestamp service.
    QualifiedTimestamp,
    /// Qualified electronic attestation service.
    QualifiedElectronicAttestation,
    /// Unrecognized service-type URI retained for forward compatibility.
    Other(TslUri),
}

/// Known ETSI service status or a bounded future URI.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum TrustServiceStatus {
    /// Service is granted.
    Granted,
    /// Service is expired.
    Expired,
    /// Service is withdrawn.
    Withdrawn,
    /// Service is deprecated at national level.
    DeprecatedAtNationalLevel,
    /// Service is recognized at national level.
    RecognisedAtNationalLevel,
    /// Service is under supervision.
    UnderSupervision,
    /// Supervision of the service has ceased.
    SupervisionCeased,
    /// Supervision of the service has been revoked.
    SupervisionRevoked,
    /// Service is accredited.
    Accredited,
    /// Accreditation of the service has ceased.
    AccreditationCeased,
    /// Accreditation of the service has been revoked.
    AccreditationRevoked,
    /// Unrecognized status URI retained for forward compatibility.
    Other(TslUri),
}

/// Known TS 119 612 service classification or a bounded scheme-specific URI.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum AdditionalServiceInformationKind {
    /// Service is intended for electronic signatures.
    ForElectronicSignatures,
    /// Service is intended for electronic seals.
    ForElectronicSeals,
    /// Service is intended for website authentication.
    ForWebsiteAuthentication,
    /// Root certification authority for qualified certificates.
    RootCaQualifiedCertificates,
    /// Unrecognized classification URI retained for forward compatibility.
    Other(TslUri),
}

/// Additional service classification retained from a service extension.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AdditionalServiceInformation {
    /// Typed service classification.
    pub kind: AdditionalServiceInformationKind,
    /// Scheme-defined value associated with the classification.
    pub information_value: Option<String>,
}

/// Known qualifier from TS 119 612 clause 5.5.9.2.3.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum ServiceQualifierKind {
    /// Qualified certificate with a secure signature-creation device.
    QualifiedCertificateWithSscd,
    /// Qualified certificate without a secure signature-creation device.
    QualifiedCertificateWithoutSscd,
    /// SSCD status is determined from the certificate.
    SscdStatusAsInCertificate,
    /// Qualified certificate with a qualified signature-creation device.
    QualifiedCertificateWithQscd,
    /// Qualified certificate without a qualified signature-creation device.
    QualifiedCertificateWithoutQscd,
    /// QSCD status is determined from the certificate.
    QscdStatusAsInCertificate,
    /// QSCD is managed on behalf of the subject.
    QscdManagedOnBehalf,
    /// Qualified certificate for a legal person.
    QualifiedCertificateForLegalPerson,
    /// Qualified certificate for an electronic signature.
    QualifiedCertificateForElectronicSignature,
    /// Qualified certificate for an electronic seal.
    QualifiedCertificateForElectronicSeal,
    /// Qualified certificate for website authentication.
    QualifiedCertificateForWebsiteAuthentication,
    /// Certificate is not qualified.
    NotQualified,
    /// Certificate satisfies the qualified-certificate statement.
    QualifiedCertificateStatement,
    /// Unrecognized qualifier URI retained for forward compatibility.
    Other(TslUri),
}

/// Qualification result assigned when its complete criteria tree matches.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ServiceQualifier {
    /// Qualification assigned when the associated criteria match.
    pub kind: ServiceQualifierKind,
}

include!("model/define_qualifications.rs");

/// XMLDSig public-key representation retained for cross-representation checks.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum XmlDsigKeyValue {
    /// RSA public key.
    Rsa {
        /// Unsigned RSA modulus.
        modulus: Vec<u8>,
        /// Unsigned RSA public exponent.
        exponent: Vec<u8>,
    },
    /// DSA public key and optional domain parameters.
    Dsa {
        /// DSA prime modulus `p`.
        p: Option<Vec<u8>>,
        /// DSA subgroup order `q`.
        q: Option<Vec<u8>>,
        /// DSA generator `g`.
        g: Option<Vec<u8>>,
        /// DSA public value `y`.
        y: Vec<u8>,
        /// Optional DSA validation parameter `j`.
        j: Option<Vec<u8>>,
        /// Optional DSA validation seed.
        seed: Option<Vec<u8>>,
        /// Optional DSA parameter-generation counter.
        pgen_counter: Option<Vec<u8>>,
    },
    /// XML Signature 1.1 named-curve public key.
    Ec {
        /// Named-curve object identifier.
        named_curve: TslObjectIdentifier,
        /// Encoded elliptic-curve public point.
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
