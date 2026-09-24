// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Keep this implementation crate under the shared lint wall without requiring
// release-grade rustdoc on every internal trust-model field.
#![allow(missing_docs)]

//! Portable X.509 parsing and policy checks.
//!
//! Overview: Pure-Rust X.509 parsing and inspection helpers suitable for portable targets.
//!
//! Scope:
//! - Parsing and metadata extraction.
//! - Deterministic, data-driven policy checks that do not require a platform crypto backend.
//! - Bounded certificate-chain signature verification for supported algorithms.
//!
//! Non-goals:
//! - Trusted-list fetching, path discovery, or final application trust decisions.

pub mod der;
pub mod error;
mod identity;
pub mod model;
pub mod parse;
pub mod policy;
pub mod presets;
pub mod qcstatements;
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod signature;
pub mod tsl;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use der::{
    certificate_subject_public_key_info, parse_subject_public_key_info_der,
    validate_certificate_der, validate_x509_name_der, SubjectPublicKeyAlgorithm,
    SubjectPublicKeyInfo,
};
pub use error::{
    X509Error, X509MissingField, X509PolicyFailure, X509ResourceLimit, X509SignatureFailure,
};
pub use identity::{certificate_identity_facts, CertificateIdentityFacts};
pub use model::{
    AuthorityAccessDescription, AuthorityAccessMethod, BasicConstraints, CertificateExtension,
    CertificateExtensionKind, CertificatePolicyId, CertificateProfile, CertificateVersion,
    DistinguishedName, ExtendedKeyUsagePurpose, KeyUsage, NameAttribute, NameAttributeKind,
    NameAttributeValue, ObjectIdentifier, OtherName, PublicKeyAlgorithm, PublicKeyProfile,
    QcStatementId, QcStatements, QcType, RelativeDistinguishedName, RsaPssHashAlgorithm,
    RsaPssMaskGenerationAlgorithm, RsaPssParameters, SignatureAlgorithm, SubjectAlternativeNames,
    X509Certificate, X509Chain, MAX_X509_CERTIFICATE_DER_BYTES, MAX_X509_CERTIFICATE_PEM_BYTES,
    MAX_X509_CHAIN_CERTIFICATES, MAX_X509_CHAIN_PEM_BYTES, MAX_X509_EXTENSIONS, MAX_X509_OID_CHARS,
    MAX_X509_SERIAL_BYTES,
};
pub use parse::{parse_cert_der, parse_cert_pem, parse_chain_pem};
pub use policy::{
    screen_chain_policy_only_no_path_validation, AuthorityInformationAccessRequirement,
    DistinguishedNameRequirement, EtsiAlgorithmPolicy, ExtensionCriticality,
    KnownCertificateExtension, LeafKeyIdentifierRequirement, LeafKeyUsageRequirement,
    LeafNameRequirement, QscdStatementRequirement, RequiredCertificateExtension,
    RevocationPointerRequirement, TrustAnchorRequirement, WrpacProfileRequirement, X509Policy,
};
pub use presets::{
    eu_policy, eudi_policy, EuPreset, EudiCertificateProfile, OID_EKU_CLIENT_AUTH,
    OID_EKU_SERVER_AUTH, OID_QCP_L, OID_QCP_L_QSCD, OID_QCP_N, OID_QCP_N_QSCD, OID_QEVCP_W,
    OID_QNCP_W, OID_QNCP_W_GEN,
};
pub use qcstatements::{
    parse_qc_statements, OID_ETSI_QCS_QC_COMPLIANCE, OID_ETSI_QCS_QC_SSCD, OID_ETSI_QCS_QC_TYPE,
    OID_ETSI_QCT_ESEAL, OID_ETSI_QCT_ESIGN, OID_ETSI_QCT_WEB, OID_QC_STATEMENTS_EXT,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use signature::{verify_chain_signatures_pure_rust, PureRustSignatureVerifier};
pub use tsl::{
    service_status_from_uri, service_type_from_uri, validate_tsl_trust_service_for_leaf,
    TslCertificateBinding, TslServiceStatus, TslServiceType, TslTrustService, TslValidationPolicy,
    TSL_SERVICE_STATUS_GRANTED, TSL_SERVICE_TYPE_CA_QC, TSL_SERVICE_TYPE_OCSP_QC,
};
#[cfg(feature = "wasm")]
pub use wasm::verify_tsl_xml_dsig_wasm_unavailable;
