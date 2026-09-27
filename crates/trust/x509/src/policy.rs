// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    error::{X509MissingField, X509PolicyFailure},
    CertificateExtensionKind, CertificatePolicyId, CertificateVersion, DistinguishedName,
    ExtendedKeyUsagePurpose, KeyUsage, NameAttributeKind, NameAttributeValue, PublicKeyAlgorithm,
    PublicKeyProfile, QcStatementId, QcType, RsaPssHashAlgorithm, RsaPssMaskGenerationAlgorithm,
    SignatureAlgorithm, X509Chain, X509Error, X509ResourceLimit, MAX_X509_CHAIN_CERTIFICATES,
};
use asn1_rs::{Any, Class, FromDer, PrintableString, Tag};
use time::OffsetDateTime;

/// Certificate-path and profile requirements enforced by the portable validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Policy {
    /// Require the end-entity certificate to use the X.509 v3 syntax.
    pub require_v3: bool,

    /// Reject unknown critical extensions rather than silently ignoring them.
    pub reject_unknown_critical_extensions: bool,

    /// Whether to reject a leaf certificate that asserts `CA:TRUE`.
    pub require_leaf_not_ca: bool,

    /// Whether every intermediate must assert `CA:TRUE`.
    pub require_intermediate_ca: bool,

    /// Extended-key-usage purposes of which the leaf must contain at least one.
    pub required_leaf_eku_any_of: Vec<ExtendedKeyUsagePurpose>,

    /// Whether the leaf key usage must include `digitalSignature`.
    pub require_leaf_digital_signature: bool,

    /// Required leaf extensions and their normative criticality.
    pub required_leaf_extensions: Vec<RequiredCertificateExtension>,

    /// Exact ETSI key-usage shape required for the leaf.
    pub leaf_key_usage_requirement: LeafKeyUsageRequirement,

    /// Typed subject distinguished-name profile.
    pub leaf_subject_name_requirement: DistinguishedNameRequirement,

    /// Typed issuer distinguished-name profile.
    pub leaf_issuer_name_requirement: DistinguishedNameRequirement,

    /// Reject a self-issued leaf where the profile requires CA issuance.
    pub require_leaf_not_self_issued: bool,

    /// Certificate-policy identifiers of which the leaf must contain at least one.
    pub required_policy_any_of: Vec<CertificatePolicyId>,

    /// Qualified-certificate statement identifiers that must all be present.
    pub required_qc_statement_ids: Vec<QcStatementId>,

    /// Qualified-certificate types of which at least one must be present.
    pub required_qc_type_any_of: Vec<QcType>,

    /// Minimum accepted RSA modulus size, when the leaf uses RSA.
    pub minimum_rsa_bits: Option<u16>,

    /// Minimum accepted elliptic-curve group size, when the leaf uses EC.
    pub minimum_ec_bits: Option<u16>,

    /// Allowed leaf public-key families for this versioned profile.
    pub allowed_public_key_algorithms: Vec<PublicKeyAlgorithm>,

    /// Allowed leaf certificate-signature algorithms for this profile.
    pub allowed_signature_algorithms: Vec<SignatureAlgorithm>,

    /// Versioned ETSI key-parameter and algorithm-lifetime policy.
    pub etsi_algorithm_policy: EtsiAlgorithmPolicy,

    /// Application-specific subject alternative name requirement.
    pub leaf_name_requirement: LeafNameRequirement,

    /// Required leaf key-identifier fields for the selected profile.
    pub leaf_key_identifier_requirement: LeafKeyIdentifierRequirement,

    /// Required leaf Authority Information Access methods.
    pub authority_information_access_requirement: AuthorityInformationAccessRequirement,

    /// Conditional qualified-signature-device statement policy.
    pub qscd_statement_requirement: QscdStatementRequirement,

    /// Required revocation pointer semantics for the leaf profile.
    pub revocation_pointer_requirement: RevocationPointerRequirement,

    /// Apply the TS 119 411-8 policy-family, subject, and QC binding.
    pub wrpac_profile_requirement: WrpacProfileRequirement,

    /// Reject RFC 9608 `noRevAvail` where the selected profile requires revocation.
    pub forbid_no_rev_avail: bool,

    /// Require an RFC 5280 CPS URI certificate-policy qualifier.
    pub require_certificate_policy_cps_uri: bool,

    /// Requirements applied to the terminal configured trust anchor.
    pub trust_anchor_requirement: TrustAnchorRequirement,
}

/// Closed set of extension identities that profile policy may require.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KnownCertificateExtension {
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
}

/// Criticality required for a known certificate extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtensionCriticality {
    /// Either critical or non-critical encoding is accepted.
    Either,
    /// The extension must be critical.
    Critical,
    /// The extension must be non-critical.
    NonCritical,
}

/// Required extension identity and criticality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredCertificateExtension {
    /// Required extension identity.
    pub kind: KnownCertificateExtension,
    /// Required extension criticality.
    pub criticality: ExtensionCriticality,
}

/// Exact leaf key-usage profile from ETSI EN 319 412-2 Table 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeafKeyUsageRequirement {
    /// Accepts any leaf key-usage shape permitted by the remaining policy.
    None,
    /// TS 119 412-6 permits exactly Type A, B, C, or F.
    PidOrWalletTypeAbcf,
    /// TS 119 411-8 content signatures permit exactly Type A, B, or F.
    WrpacTypeAbf,
}

/// Distinguished-name structural requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DistinguishedNameRequirement {
    /// Accepts any distinguished name permitted by the remaining policy.
    None,
    /// Requires the natural-person distinguished-name profile.
    NaturalPerson,
    /// Requires the legal-person distinguished-name profile.
    LegalPerson,
    /// Accepts either the natural-person or legal-person profile.
    NaturalOrLegalPerson,
    /// EN 319 412-2 issuer profile: legal-person CA or natural-person CA.
    IssuingAuthority,
    /// Issuing-authority profile, or an exact self-issued subject name.
    IssuingAuthorityOrSelfIssued,
}

/// TS 119 411-8 WRPAC certificate-policy family enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WrpacProfileRequirement {
    /// Applies no WRPAC-specific certificate constraints.
    None,
    /// Applies the version 1 WRPAC certificate profile.
    Version1,
}

/// Terminal trust-anchor certificate predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustAnchorRequirement {
    /// Applies no profile-specific predicates to the configured trust anchor.
    None,
    /// Certificate-valued RFC 5280 anchor with CA:true and keyCertSign.
    Rfc5280Ca,
    /// RFC 5280 CA anchor with keyCertSign and a declared certificate policy.
    EudiProviderCa,
}

/// Versioned ETSI TS 119 312 algorithm policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EtsiAlgorithmPolicy {
    /// Applies no ETSI algorithm-lifetime restrictions.
    None,
    /// ETSI TS 119 312 V2.1.1 recommended/legacy key parameter policy.
    Ts119312V211,
}

/// Application-specific leaf name requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeafNameRequirement {
    /// Accepts any subject alternative name permitted by the remaining policy.
    None,
    /// Requires a DNS name or IP address.
    DnsOrIp,
    /// Requires a URI.
    Uri,
    /// Requires an email address.
    Email,
    /// TS 119 411-8 contact URI, rfc822Name, or id-at-telephoneNumber otherName.
    UriEmailOrTelephone,
}

/// Leaf SKI/AKI requirements selected by a versioned certificate profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeafKeyIdentifierRequirement {
    /// Does not require a Subject Key Identifier or Authority Key Identifier.
    None,
    /// Requires a Subject Key Identifier.
    Subject,
    /// Requires an Authority Key Identifier.
    Authority,
    /// Requires both Subject Key Identifier and Authority Key Identifier.
    SubjectAndAuthority,
}

/// Required Authority Information Access method set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorityInformationAccessRequirement {
    /// Does not require an Authority Information Access method.
    None,
    /// Requires an OCSP access method.
    Ocsp,
    /// Requires a CA Issuers access method.
    CaIssuers,
    /// Requires both OCSP and CA Issuers access methods.
    OcspAndCaIssuers,
    /// Requires CA Issuers unless the certificate is self-issued.
    CaIssuersUnlessSelfIssued,
}

/// Whether a QSCD certificate-policy OID requires the ETSI QcSSCD statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QscdStatementRequirement {
    /// Does not require QcSSCD for QSCD policy identifiers.
    None,
    /// Requires QcSSCD whenever a QSCD policy identifier is present.
    WhenQscdPolicy,
}

/// Leaf revocation-discovery requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationPointerRequirement {
    /// Does not require a revocation discovery mechanism.
    None,
    /// Requires an OCSP responder or CRL distribution point.
    OcspOrCrl,
    /// Requires the RFC 9608 `noRevAvail` extension.
    ExplicitNoRevAvail,
}

impl Default for X509Policy {
    fn default() -> Self {
        Self {
            require_v3: true,
            reject_unknown_critical_extensions: true,
            require_leaf_not_ca: true,
            require_intermediate_ca: true,
            required_leaf_eku_any_of: Vec::new(),
            require_leaf_digital_signature: false,
            required_leaf_extensions: Vec::new(),
            leaf_key_usage_requirement: LeafKeyUsageRequirement::None,
            leaf_subject_name_requirement: DistinguishedNameRequirement::None,
            leaf_issuer_name_requirement: DistinguishedNameRequirement::None,
            require_leaf_not_self_issued: false,

            required_policy_any_of: Vec::new(),
            required_qc_statement_ids: Vec::new(),
            required_qc_type_any_of: Vec::new(),
            minimum_rsa_bits: None,
            minimum_ec_bits: None,
            allowed_public_key_algorithms: Vec::new(),
            allowed_signature_algorithms: Vec::new(),
            etsi_algorithm_policy: EtsiAlgorithmPolicy::None,
            leaf_name_requirement: LeafNameRequirement::None,
            leaf_key_identifier_requirement: LeafKeyIdentifierRequirement::None,
            authority_information_access_requirement: AuthorityInformationAccessRequirement::None,
            qscd_statement_requirement: QscdStatementRequirement::None,
            revocation_pointer_requirement: RevocationPointerRequirement::None,
            wrpac_profile_requirement: WrpacProfileRequirement::None,
            forbid_no_rev_avail: false,
            require_certificate_policy_cps_uri: false,
            trust_anchor_requirement: TrustAnchorRequirement::None,
        }
    }
}

include!("policy/evaluate.rs");
include!("policy/intermediate_algorithms.rs");
include!("policy/helpers.rs");
