// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    AuthorityInformationAccessRequirement, CertificatePolicyId, DistinguishedNameRequirement,
    EtsiAlgorithmPolicy, ExtendedKeyUsagePurpose, ExtensionCriticality, KnownCertificateExtension,
    LeafKeyIdentifierRequirement, LeafKeyUsageRequirement, LeafNameRequirement, PublicKeyAlgorithm,
    QcStatementId, QcType, QscdStatementRequirement, RequiredCertificateExtension,
    RevocationPointerRequirement, SignatureAlgorithm, TrustAnchorRequirement,
    WrpacProfileRequirement, X509Policy,
};

/// ETSI EN 319 411-2 QCP-n policy identifier.
pub const OID_QCP_N: &str = "0.4.0.194112.1.0";
/// ETSI EN 319 411-2 QCP-l policy identifier.
pub const OID_QCP_L: &str = "0.4.0.194112.1.1";
/// ETSI EN 319 411-2 QCP-n-qscd policy identifier.
pub const OID_QCP_N_QSCD: &str = "0.4.0.194112.1.2";
/// ETSI EN 319 411-2 QCP-l-qscd policy identifier.
pub const OID_QCP_L_QSCD: &str = "0.4.0.194112.1.3";

/// ETSI EN 319 411-2 QEVCP-w policy identifier.
pub const OID_QEVCP_W: &str = "0.4.0.194112.1.4";
/// ETSI EN 319 411-2 QNCP-w policy identifier.
pub const OID_QNCP_W: &str = "0.4.0.194112.1.5";
/// ETSI EN 319 411-2 QNCP-w-gen policy identifier.
pub const OID_QNCP_W_GEN: &str = "0.4.0.194112.1.6";

/// RFC 5280 TLS server-authentication extended-key-usage identifier.
pub const OID_EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
/// RFC 5280 TLS client-authentication extended-key-usage identifier.
pub const OID_EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

/// EU eIDAS qualified-certificate policy presets.
#[non_exhaustive]
pub enum EuPreset {
    /// Qualified Website Authentication Certificate (QWAC).
    Qwac,
    /// Qualified Electronic Seal Certificate (QSealC).
    Qsealc,
    /// Qualified Electronic Signature Certificate (QSigC).
    Qsigc,
}

/// Build the TS 119 312 algorithm floor for trusted-list signer chains.
pub fn tsl_signer_policy() -> X509Policy {
    X509Policy {
        minimum_rsa_bits: Some(2_048),
        minimum_ec_bits: Some(256),
        allowed_public_key_algorithms: approved_public_key_algorithms(),
        allowed_signature_algorithms: approved_signature_algorithms(),
        etsi_algorithm_policy: EtsiAlgorithmPolicy::Ts119312V211,
        trust_anchor_requirement: TrustAnchorRequirement::Rfc5280Ca,
        ..X509Policy::default()
    }
}

/// Builds the certificate policy for the selected ETSI qualified-certificate preset.
pub fn eu_policy(p: EuPreset) -> X509Policy {
    match p {
        EuPreset::Qwac => X509Policy {
            require_v3: true,
            reject_unknown_critical_extensions: true,
            require_leaf_not_ca: true,
            require_intermediate_ca: true,

            // A QWAC authenticates a TLS website and therefore requires the
            // serverAuth extended-key-usage purpose.
            required_leaf_eku_any_of: vec![ExtendedKeyUsagePurpose::ServerAuthentication],

            // TLS authentication requires the leaf key to permit signatures.
            require_leaf_digital_signature: true,

            // ETSI EN 319 411-2 defines three accepted QWAC policy families.
            required_policy_any_of: vec![
                CertificatePolicyId::QevcpWeb,
                CertificatePolicyId::QncpWeb,
                CertificatePolicyId::QncpWebGeneric,
            ],

            // ETSI EN 319 412-5 requires compliance and website-authentication
            // qualified-certificate statements.
            required_qc_statement_ids: vec![QcStatementId::Compliance, QcStatementId::Type],
            required_qc_type_any_of: vec![QcType::WebAuthentication],
            minimum_rsa_bits: Some(2048),
            minimum_ec_bits: Some(256),
            allowed_public_key_algorithms: approved_public_key_algorithms(),
            allowed_signature_algorithms: approved_signature_algorithms(),
            leaf_name_requirement: LeafNameRequirement::DnsOrIp,
            leaf_key_identifier_requirement: LeafKeyIdentifierRequirement::None,
            authority_information_access_requirement: AuthorityInformationAccessRequirement::None,
            qscd_statement_requirement: QscdStatementRequirement::None,
            revocation_pointer_requirement: RevocationPointerRequirement::None,
            ..X509Policy::default()
        },

        EuPreset::Qsealc => X509Policy {
            require_v3: true,
            reject_unknown_critical_extensions: true,
            require_leaf_not_ca: true,
            require_intermediate_ca: true,

            // Electronic seals require the leaf key to permit signatures.
            require_leaf_digital_signature: true,

            // The qualified-seal profile does not require an extended key usage.
            required_leaf_eku_any_of: vec![],

            // Qualified electronic seals use legal-person policy identifiers.
            required_policy_any_of: vec![
                CertificatePolicyId::QcpLegalPerson,
                CertificatePolicyId::QcpLegalPersonQscd,
            ],

            // Compliance and electronic-seal type statements are mandatory;
            // QSCD policy identifiers additionally require QcSSCD.
            required_qc_statement_ids: vec![QcStatementId::Compliance, QcStatementId::Type],
            required_qc_type_any_of: vec![QcType::ElectronicSeal],
            minimum_rsa_bits: Some(2048),
            minimum_ec_bits: Some(256),
            allowed_public_key_algorithms: approved_public_key_algorithms(),
            allowed_signature_algorithms: approved_signature_algorithms(),
            leaf_name_requirement: LeafNameRequirement::None,
            leaf_key_identifier_requirement: LeafKeyIdentifierRequirement::None,
            authority_information_access_requirement: AuthorityInformationAccessRequirement::None,
            qscd_statement_requirement: QscdStatementRequirement::WhenQscdPolicy,
            revocation_pointer_requirement: RevocationPointerRequirement::None,
            ..X509Policy::default()
        },

        EuPreset::Qsigc => X509Policy {
            require_v3: true,
            reject_unknown_critical_extensions: true,
            require_leaf_not_ca: true,
            require_intermediate_ca: true,

            // Electronic signatures require the leaf key to permit signatures.
            require_leaf_digital_signature: true,

            required_leaf_eku_any_of: vec![],

            required_policy_any_of: vec![
                CertificatePolicyId::QcpNaturalPerson,
                CertificatePolicyId::QcpNaturalPersonQscd,
            ],

            required_qc_statement_ids: vec![QcStatementId::Compliance, QcStatementId::Type],
            required_qc_type_any_of: vec![QcType::ElectronicSignature],
            minimum_rsa_bits: Some(2048),
            minimum_ec_bits: Some(256),
            allowed_public_key_algorithms: approved_public_key_algorithms(),
            allowed_signature_algorithms: approved_signature_algorithms(),
            leaf_name_requirement: LeafNameRequirement::None,
            leaf_key_identifier_requirement: LeafKeyIdentifierRequirement::None,
            authority_information_access_requirement: AuthorityInformationAccessRequirement::None,
            qscd_statement_requirement: QscdStatementRequirement::WhenQscdPolicy,
            revocation_pointer_requirement: RevocationPointerRequirement::None,
            ..X509Policy::default()
        },
    }
}

/// Versioned EUDI certificate profiles owned by the reusable SSI X.509 layer.
#[non_exhaustive]
pub enum EudiCertificateProfile {
    /// ETSI TS 119 412-6 V1.2.1 PID-provider sign/seal certificate.
    PidProviderSignerV1,
    /// ETSI TS 119 412-6 V1.2.1 wallet-provider sign/seal certificate.
    WalletProviderSignerV1,
    /// ETSI TS 119 411-8 V1.1.1 wallet relying-party access certificate.
    WrpacLeafV1,
    /// Provider CA anchor used by the EUDI LoTE PKIX lanes.
    ProviderCaV1,
}

/// Constructs a closed, versioned EUDI X.509 policy.
pub fn eudi_policy(profile: EudiCertificateProfile) -> X509Policy {
    match profile {
        EudiCertificateProfile::PidProviderSignerV1 => pid_or_wallet_policy(QcType::PidProvider),
        EudiCertificateProfile::WalletProviderSignerV1 => {
            pid_or_wallet_policy(QcType::WalletProvider)
        }
        EudiCertificateProfile::WrpacLeafV1 => X509Policy {
            required_leaf_extensions: vec![
                required_extension(
                    KnownCertificateExtension::KeyUsage,
                    ExtensionCriticality::Either,
                ),
                required_extension(
                    KnownCertificateExtension::AuthorityKeyIdentifier,
                    ExtensionCriticality::NonCritical,
                ),
                required_extension(
                    KnownCertificateExtension::CertificatePolicies,
                    ExtensionCriticality::Either,
                ),
                required_extension(
                    KnownCertificateExtension::SubjectAlternativeName,
                    ExtensionCriticality::Either,
                ),
                required_extension(
                    KnownCertificateExtension::AuthorityInformationAccess,
                    ExtensionCriticality::NonCritical,
                ),
            ],
            leaf_key_usage_requirement: LeafKeyUsageRequirement::WrpacTypeAbf,
            leaf_issuer_name_requirement: DistinguishedNameRequirement::IssuingAuthority,
            require_leaf_not_self_issued: true,
            allowed_public_key_algorithms: approved_public_key_algorithms(),
            allowed_signature_algorithms: approved_signature_algorithms(),
            etsi_algorithm_policy: EtsiAlgorithmPolicy::Ts119312V211,
            minimum_rsa_bits: Some(2048),
            minimum_ec_bits: Some(256),
            leaf_name_requirement: LeafNameRequirement::UriEmailOrTelephone,
            leaf_key_identifier_requirement: LeafKeyIdentifierRequirement::Authority,
            authority_information_access_requirement:
                AuthorityInformationAccessRequirement::CaIssuers,
            revocation_pointer_requirement: RevocationPointerRequirement::OcspOrCrl,
            wrpac_profile_requirement: WrpacProfileRequirement::Version1,
            forbid_no_rev_avail: true,
            require_certificate_policy_cps_uri: true,
            trust_anchor_requirement: TrustAnchorRequirement::EudiProviderCa,
            ..X509Policy::default()
        },
        EudiCertificateProfile::ProviderCaV1 => X509Policy {
            require_leaf_not_ca: false,
            trust_anchor_requirement: TrustAnchorRequirement::EudiProviderCa,
            allowed_public_key_algorithms: approved_public_key_algorithms(),
            allowed_signature_algorithms: approved_signature_algorithms(),
            etsi_algorithm_policy: EtsiAlgorithmPolicy::Ts119312V211,
            minimum_rsa_bits: Some(2048),
            minimum_ec_bits: Some(256),
            ..X509Policy::default()
        },
    }
}

fn pid_or_wallet_policy(required_qc_type: QcType) -> X509Policy {
    X509Policy {
        required_leaf_extensions: vec![
            required_extension(
                KnownCertificateExtension::KeyUsage,
                ExtensionCriticality::Either,
            ),
            required_extension(
                KnownCertificateExtension::SubjectKeyIdentifier,
                ExtensionCriticality::NonCritical,
            ),
            required_extension(
                KnownCertificateExtension::AuthorityKeyIdentifier,
                ExtensionCriticality::NonCritical,
            ),
            required_extension(
                KnownCertificateExtension::CertificatePolicies,
                ExtensionCriticality::Either,
            ),
            required_extension(
                KnownCertificateExtension::QcStatements,
                ExtensionCriticality::NonCritical,
            ),
        ],
        leaf_key_usage_requirement: LeafKeyUsageRequirement::PidOrWalletTypeAbcf,
        leaf_subject_name_requirement: DistinguishedNameRequirement::NaturalOrLegalPerson,
        leaf_issuer_name_requirement: DistinguishedNameRequirement::IssuingAuthorityOrSelfIssued,
        required_qc_statement_ids: vec![QcStatementId::Type],
        required_qc_type_any_of: vec![required_qc_type],
        minimum_rsa_bits: Some(2048),
        minimum_ec_bits: Some(256),
        allowed_public_key_algorithms: approved_public_key_algorithms(),
        allowed_signature_algorithms: approved_signature_algorithms(),
        etsi_algorithm_policy: EtsiAlgorithmPolicy::Ts119312V211,
        leaf_key_identifier_requirement: LeafKeyIdentifierRequirement::SubjectAndAuthority,
        authority_information_access_requirement:
            AuthorityInformationAccessRequirement::CaIssuersUnlessSelfIssued,
        ..X509Policy::default()
    }
}

const fn required_extension(
    kind: KnownCertificateExtension,
    criticality: ExtensionCriticality,
) -> RequiredCertificateExtension {
    RequiredCertificateExtension { kind, criticality }
}

fn approved_public_key_algorithms() -> Vec<PublicKeyAlgorithm> {
    // The versioned ETSI profiles intentionally admit only algorithm families
    // backed by the configured reallyme-crypto native/wasm feature lanes.
    vec![PublicKeyAlgorithm::Rsa, PublicKeyAlgorithm::Ec]
}

fn approved_signature_algorithms() -> Vec<SignatureAlgorithm> {
    vec![
        SignatureAlgorithm::RsaPkcs1Sha256,
        SignatureAlgorithm::RsaPkcs1Sha384,
        SignatureAlgorithm::RsaPkcs1Sha512,
        SignatureAlgorithm::RsaPss,
        SignatureAlgorithm::EcdsaSha256,
        SignatureAlgorithm::EcdsaSha384,
        SignatureAlgorithm::EcdsaSha512,
    ]
}
