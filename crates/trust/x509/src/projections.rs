// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lossless, bounded views of certificate names and distribution points.
//!
//! These views borrow the original DER, never the mutable legacy profile fields.
//! They do not authenticate a certificate or choose an application profile.

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod project_certificate;
mod project_extensions;
mod project_name;
mod read_der;

pub use project_certificate::project_certificate;

/// Maximum attributes across all names in one projection.
pub const MAX_PROJECTION_NAME_ATTRIBUTES: usize = 128;
/// Maximum GeneralNames across all selected extensions and distribution points.
pub const MAX_PROJECTION_GENERAL_NAMES: usize = 128;
/// Maximum CRL distribution points in one certificate.
pub const MAX_PROJECTION_DISTRIBUTION_POINTS: usize = 64;
/// Maximum constructed DER nesting accepted by the projection boundary.
pub const MAX_PROJECTION_DER_DEPTH: usize = 32;
/// Maximum DER elements examined by the projection boundary.
pub const MAX_PROJECTION_DER_ELEMENTS: usize = 8192;

/// Fixed, non-identifying failure from a lossless certificate projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("certificate projection failed: {reason}")]
pub struct ProjectionError {
    /// Stable failure category, without certificate content.
    pub reason: ProjectionErrorReason,
}

/// Projection syntax and resource failures; profile decisions belong to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProjectionErrorReason {
    /// Non-canonical, truncated, or structurally invalid DER.
    #[error("invalid DER")]
    InvalidDer,
    /// A string violates its declared ASN.1 encoding.
    #[error("invalid string encoding")]
    InvalidStringEncoding,
    /// A certificate repeats an extension OID.
    #[error("duplicate extension")]
    DuplicateExtension,
    /// Certificate input exceeds the certificate DER byte limit.
    #[error("certificate too large")]
    CertificateTooLarge,
    /// Certificate has too many extensions.
    #[error("too many extensions")]
    TooManyExtensions,
    /// Names exceed the shared attribute budget.
    #[error("too many name attributes")]
    TooManyNameAttributes,
    /// GeneralNames exceed the shared name budget.
    #[error("too many general names")]
    TooManyGeneralNames,
    /// CRL distribution points exceed their budget.
    #[error("too many distribution points")]
    TooManyDistributionPoints,
    /// DER nesting or element count exceeds the structural budget.
    #[error("DER complexity limit")]
    DerComplexityLimit,
}

impl From<ProjectionErrorReason> for ProjectionError {
    fn from(reason: ProjectionErrorReason) -> Self {
        Self { reason }
    }
}

/// ASN.1 identifier class, retained independently from its tag number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
#[non_exhaustive]
pub enum Asn1Class {
    /// ASN.1 universal class.
    Universal,
    /// Application-defined class.
    Application,
    /// Context-specific class.
    ContextSpecific,
    /// Private class.
    Private,
}

/// Exact identifier properties of an encoded attribute value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct AttributeEncoding {
    /// Original identifier class.
    pub class: Asn1Class,
    /// Original tag number, including high-tag-number identifiers.
    pub tag_number: u32,
    /// Whether the source identifier has the constructed bit set.
    pub constructed: bool,
}

/// One DER element borrowed from the certificate, with redacted diagnostics.
#[derive(PartialEq, Eq)]
pub struct EncodedValue<'a> {
    encoding: AttributeEncoding,
    der: &'a [u8],
    content: &'a [u8],
}

impl EncodedValue<'_> {
    /// Original class, tag number and constructed form.
    pub fn encoding(&self) -> AttributeEncoding {
        self.encoding
    }
    /// Complete original identifier, length and value octets.
    pub fn der(&self) -> &[u8] {
        self.der
    }
    /// Original content octets, without identifier or length.
    pub fn content(&self) -> &[u8] {
        self.content
    }
}

impl core::fmt::Debug for EncodedValue<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncodedValue")
            .field("encoding", &self.encoding)
            .field("der", &"<redacted>")
            .finish()
    }
}

/// Decoded identifying text with zeroization on drop and redacted diagnostics.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProtectedNameText(Zeroizing<String>);

impl ProtectedNameText {
    /// Borrows the validated text without transferring ownership.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl core::fmt::Debug for ProtectedNameText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProtectedNameText(<redacted>)")
    }
}

/// Validated decoded text, or explicitly uninterpreted source content.
#[non_exhaustive]
pub enum DecodedNameValue<'a> {
    /// UTF-8-compatible ASN.1 string, borrowed without normalization.
    Text(&'a str),
    /// BMPString or UniversalString decoded into a zeroizing owner.
    Unicode(ProtectedNameText),
    /// Non-text or unsupported string syntax, retained without guessing a charset.
    Unsupported,
}

impl DecodedNameValue<'_> {
    /// Validated text when its declared string syntax is supported.
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Unicode(text) => Some(text.as_str()),
            Self::Unsupported => None,
        }
    }
}

impl core::fmt::Debug for DecodedNameValue<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DecodedNameValue(<redacted>)")
    }
}

/// One ordered Name attribute with its original type and value encoding.
#[derive(Debug)]
pub struct EncodedNameAttribute<'a> {
    oid: EncodedValue<'a>,
    value: EncodedValue<'a>,
    decoded: DecodedNameValue<'a>,
}
impl EncodedNameAttribute<'_> {
    /// Attribute-type OBJECT IDENTIFIER, in its exact original DER form.
    pub fn oid(&self) -> &EncodedValue<'_> {
        &self.oid
    }
    /// Attribute value, including original identifier and content.
    pub fn value(&self) -> &EncodedValue<'_> {
        &self.value
    }
    /// Text validated according to the source tag; unsupported syntax is explicit.
    pub fn decoded(&self) -> &DecodedNameValue<'_> {
        &self.decoded
    }
}

/// One relative distinguished name, preserving order and multiplicity.
#[derive(Debug)]
pub struct EncodedRelativeName<'a> {
    encoded: EncodedValue<'a>,
    attributes: Vec<EncodedNameAttribute<'a>>,
}
impl EncodedRelativeName<'_> {
    /// Original SET element, or context-specific relative-name choice element.
    pub fn encoded(&self) -> &EncodedValue<'_> {
        &self.encoded
    }
    /// Attributes in DER order, including duplicates.
    pub fn attributes(&self) -> &[EncodedNameAttribute<'_>] {
        &self.attributes
    }
}

/// Ordered, unnormalized distinguished name borrowed from a certificate.
#[derive(Debug)]
pub struct EncodedDistinguishedName<'a> {
    encoded: EncodedValue<'a>,
    rdns: Vec<EncodedRelativeName<'a>>,
}
impl EncodedDistinguishedName<'_> {
    /// Original Name SEQUENCE.
    pub fn encoded(&self) -> &EncodedValue<'_> {
        &self.encoded
    }
    /// Relative names in source order; no flattening or deduplication.
    pub fn rdns(&self) -> &[EncodedRelativeName<'_>] {
        &self.rdns
    }
}

/// A GeneralName alternative; unsupported structured forms retain their raw DER.
#[derive(Debug)]
#[non_exhaustive]
pub enum GeneralNameValue<'a> {
    /// OtherName type OID and explicit value wrapper, without interpretation.
    OtherName {
        /// Original type identifier.
        type_id: EncodedValue<'a>,
        /// Original context-specific explicit value wrapper.
        value: EncodedValue<'a>,
    },
    /// RFC 822 mailbox, validated as IA5String.
    Rfc822Name(RedactedIa5<'a>),
    /// DNS name, validated as IA5String without profile normalization.
    DnsName(RedactedIa5<'a>),
    /// X.400 syntax is not interpreted; use the enclosing original DER.
    UnsupportedX400Address,
    /// Explicit X.509 Name.
    DirectoryName(EncodedDistinguishedName<'a>),
    /// EDI syntax is not interpreted; use the enclosing original DER.
    UnsupportedEdiPartyName,
    /// URI, validated as IA5String without URI profile decisions.
    UniformResourceIdentifier(RedactedIa5<'a>),
    /// IP-address octets; address-family/profile decisions remain with callers.
    IpAddress(EncodedValue<'a>),
    /// Registered identifier in its original context-specific OID encoding.
    RegisteredId(EncodedValue<'a>),
}

/// Borrowed IA5 value with redacted diagnostics.
pub struct RedactedIa5<'a>(&'a str);
impl RedactedIa5<'_> {
    /// Exact ASCII source text, without case folding or normalization.
    pub fn as_str(&self) -> &str {
        self.0
    }
}
impl core::fmt::Debug for RedactedIa5<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ia5(<redacted>)")
    }
}

/// One GeneralName and its complete, original tagged encoding.
#[derive(Debug)]
pub struct GeneralNameProjection<'a> {
    encoded: EncodedValue<'a>,
    value: GeneralNameValue<'a>,
}
impl GeneralNameProjection<'_> {
    /// Complete GeneralName element, including its choice tag.
    pub fn encoded(&self) -> &EncodedValue<'_> {
        &self.encoded
    }
    /// Typed alternative; no alternatives are silently discarded.
    pub fn value(&self) -> &GeneralNameValue<'_> {
        &self.value
    }
}

/// Present SAN or IAN extension, including criticality and ordered GeneralNames.
#[derive(Debug)]
pub struct AlternativeNamesProjection<'a> {
    critical: bool,
    names: Vec<GeneralNameProjection<'a>>,
}
impl AlternativeNamesProjection<'_> {
    /// Extension-level criticality.
    pub fn critical(&self) -> bool {
        self.critical
    }
    /// Ordered alternatives, including multiplicity and unsupported forms.
    pub fn names(&self) -> &[GeneralNameProjection<'_>] {
        &self.names
    }
}

/// DistributionPointName choice, without application-specific URI requirements.
#[derive(Debug)]
#[non_exhaustive]
pub enum DistributionPointNameProjection<'a> {
    /// Ordered GeneralNames from the fullName choice.
    FullName(Vec<GeneralNameProjection<'a>>),
    /// Relative name from the nameRelativeToCRLIssuer choice.
    RelativeName(EncodedRelativeName<'a>),
}

/// Exact ReasonFlags content, including a present zero-valued bit string.
#[derive(Debug)]
pub struct ReasonFlagsProjection<'a> {
    encoded: EncodedValue<'a>,
}
impl ReasonFlagsProjection<'_> {
    /// Original implicit BIT STRING, including unused-bit count.
    pub fn encoded(&self) -> &EncodedValue<'_> {
        &self.encoded
    }
    /// Tests an ASN.1 bit index (bit zero is the most significant source bit).
    /// Returns false for indices beyond the encoded bit string.
    pub fn contains(&self, bit: usize) -> bool {
        let Some(index) = bit.checked_div(8).and_then(|n| n.checked_add(1)) else {
            return false;
        };
        self.encoded
            .content
            .get(index)
            .is_some_and(|byte| byte & (0x80 >> (bit % 8)) != 0)
    }
}

/// One distribution point; each optional field preserves source presence.
#[derive(Debug)]
pub struct CrlDistributionPointProjection<'a> {
    encoded: EncodedValue<'a>,
    name: Option<DistributionPointNameProjection<'a>>,
    reasons: Option<ReasonFlagsProjection<'a>>,
    issuer: Option<Vec<GeneralNameProjection<'a>>>,
}
impl CrlDistributionPointProjection<'_> {
    /// Complete original DistributionPoint SEQUENCE.
    pub fn encoded(&self) -> &EncodedValue<'_> {
        &self.encoded
    }
    /// DistributionPointName choice, or None if absent.
    pub fn distribution_point(&self) -> Option<&DistributionPointNameProjection<'_>> {
        self.name.as_ref()
    }
    /// ReasonFlags, or None if absent (distinct from present zero).
    pub fn reasons(&self) -> Option<&ReasonFlagsProjection<'_>> {
        self.reasons.as_ref()
    }
    /// CRL issuer GeneralNames, or None if the field is absent.
    pub fn crl_issuer(&self) -> Option<&[GeneralNameProjection<'_>]> {
        self.issuer.as_deref()
    }
}

/// Present CRL Distribution Points extension.
#[derive(Debug)]
pub struct CrlDistributionPointsProjection<'a> {
    critical: bool,
    points: Vec<CrlDistributionPointProjection<'a>>,
}
impl CrlDistributionPointsProjection<'_> {
    /// Extension-level criticality.
    pub fn critical(&self) -> bool {
        self.critical
    }
    /// Distribution points in source order.
    pub fn points(&self) -> &[CrlDistributionPointProjection<'_>] {
        &self.points
    }
}

/// Immutable projections tied by lifetime to exactly one source certificate.
///
/// ```compile_fail
/// use reallyme_trust_x509::projections::project_certificate;
/// let projection = { let der = vec![0u8]; project_certificate(&der).unwrap() };
/// let _ = projection.der(); // A projection cannot outlive its DER owner.
/// ```
#[derive(Debug)]
pub struct CertificateProjections<'a> {
    source: EncodedValue<'a>,
    subject: EncodedDistinguishedName<'a>,
    issuer: EncodedDistinguishedName<'a>,
    san: Option<AlternativeNamesProjection<'a>>,
    ian: Option<AlternativeNamesProjection<'a>>,
    crl: Option<CrlDistributionPointsProjection<'a>>,
}
impl CertificateProjections<'_> {
    /// Exact original certificate DER; diagnostics never render its content.
    pub fn der(&self) -> &[u8] {
        self.source.der()
    }
    /// Subject Name with lossless attribute identifiers and validated text.
    pub fn subject(&self) -> &EncodedDistinguishedName<'_> {
        &self.subject
    }
    /// Issuer Name with lossless attribute identifiers and validated text.
    pub fn issuer(&self) -> &EncodedDistinguishedName<'_> {
        &self.issuer
    }
    /// SAN extension, distinguished from an absent extension.
    pub fn subject_alternative_names(&self) -> Option<&AlternativeNamesProjection<'_>> {
        self.san.as_ref()
    }
    /// IAN extension (2.5.29.18), independent of SAN.
    pub fn issuer_alternative_names(&self) -> Option<&AlternativeNamesProjection<'_>> {
        self.ian.as_ref()
    }
    /// Complete CRL distribution points, distinguished from an absent extension.
    pub fn crl_distribution_points(&self) -> Option<&CrlDistributionPointsProjection<'_>> {
        self.crl.as_ref()
    }
}

pub(crate) fn decode_attribute(
    encoding: AttributeEncoding,
    content: &[u8],
) -> Result<DecodedNameValue<'_>, ProjectionError> {
    project_name::decode_value(&EncodedValue {
        encoding,
        der: &[],
        content,
    })
}

#[cfg(test)]
mod tests;
