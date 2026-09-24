// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Typed conformance failures. Variants intentionally contain no credential data.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConformanceError {
    /// The attestation type identifier is absent or invalid.
    #[error("attestation type identifier is invalid")]
    InvalidAttestationType,
    /// The required EAA category signal is absent.
    #[error("attestation category signal is missing")]
    MissingCategorySignal,
    /// A supplied category identifier does not match the attestation category.
    #[error("attestation category signal is invalid")]
    InvalidCategorySignal,
    /// Issuer identity metadata is incomplete.
    #[error("issuer identity metadata is incomplete")]
    InvalidIssuerIdentity,
    /// Subject binding is absent or inconsistent.
    #[error("subject binding is invalid")]
    InvalidSubjectBinding,
    /// The technical validity period is absent or malformed.
    #[error("technical validity period is invalid")]
    InvalidTechnicalValidity,
    /// The administrative validity period is malformed.
    #[error("administrative validity period is invalid")]
    InvalidAdministrativeValidity,
    /// A context URI is malformed, duplicated, or exceeds profile bounds.
    #[error("attestation context metadata is invalid")]
    InvalidContext,
    /// A schema URI is malformed, duplicated, or exceeds profile bounds.
    #[error("attestation schema metadata is invalid")]
    InvalidSchema,
    /// The attestation identifier is absent, malformed, or oversized.
    #[error("attestation identifier is invalid")]
    InvalidAttestationIdentifier,
    /// Issuance-on-behalf identifiers are malformed.
    #[error("issuance-on-behalf metadata is invalid")]
    InvalidIssuedOnBehalf,
    /// Issuance time is inconsistent with the technical validity interval.
    #[error("attestation issuance time is invalid")]
    InvalidIssuanceTime,
    /// Audience or terms-of-use constraints are malformed or duplicated.
    #[error("attestation usage constraints are invalid")]
    InvalidUsageConstraints,
    /// Attribute evidence references are malformed or exceed profile bounds.
    #[error("attribute evidence metadata is invalid")]
    InvalidAttributeEvidence,
    /// Renewal service metadata is malformed or temporally invalid.
    #[error("attestation renewal service is invalid")]
    InvalidRenewalService,
    /// Attested attribute metadata is incomplete.
    #[error("attested attribute metadata is incomplete")]
    InvalidAttributeMetadata,
    /// Selective-disclosure metadata is inconsistent.
    #[error("selective disclosure metadata is invalid")]
    InvalidSelectiveDisclosure,
    /// Holder key binding is required but absent or not hardware protected.
    #[error("holder key binding is invalid")]
    InvalidHolderKeyBinding,
    /// The issuer signature profile is insufficient for the attestation category.
    #[error("issuer signature profile is invalid")]
    InvalidIssuerSignature,
    /// A required issuer-signature certificate reference is absent or malformed.
    #[error("issuer signature certificate reference is invalid")]
    InvalidIssuerSignatureCertificateReference,
    /// Status information is required but absent.
    #[error("status information is missing")]
    MissingStatus,
    /// Status semantics are not privacy preserving, binary, or irreversible as required.
    #[error("status semantics are invalid")]
    InvalidStatus,
    /// The EU ISO mdoc status token or capability profile is incomplete.
    #[error("EU mdoc status profile is invalid")]
    InvalidEuMdocStatusProfile,
    /// An mdoc status reference repeats a URI/key pair allocated to another MSO.
    #[error("mdoc status reference is correlatable")]
    CorrelatableMdocStatusReference,
    /// A short-lived status exemption exceeds the maximum duration.
    #[error("short-lived status exemption is invalid")]
    InvalidShortLivedExemption,
    /// SD-JWT VC profile facts are missing or invalid.
    #[error("SD-JWT VC profile is invalid")]
    InvalidSdJwtProfile,
    /// ISO/IEC mdoc profile facts are missing or invalid.
    #[error("ISO/IEC mdoc profile is invalid")]
    InvalidMdocProfile,
    /// JSON-LD W3C VC profile facts are missing or invalid.
    #[error("JSON-LD W3C VC profile is invalid")]
    InvalidJsonLdProfile,
    /// X.509 Attribute Certificate profile facts are missing or invalid.
    #[error("X.509 attribute certificate profile is invalid")]
    InvalidX509AttributeCertificateProfile,
    /// Mandatory natural-person PID claims are incomplete.
    #[error("mandatory natural-person PID claims are incomplete")]
    MissingMandatoryPidClaim,
    /// A natural-person PID claim violates its required encoding or value constraints.
    #[error("natural-person PID claim encoding is invalid")]
    InvalidPidClaimEncoding,
    /// The portrait does not match the selected PID encoding or opt-out policy.
    #[error("natural-person PID portrait is invalid")]
    InvalidPidPortrait,
    /// PID metadata is incomplete.
    #[error("PID metadata is incomplete")]
    InvalidPidMetadata,
    /// PID claims are not independently selectively disclosable.
    #[error("PID selective disclosure is invalid")]
    InvalidPidSelectiveDisclosure,
    /// PID issuance was not authorized at the required assurance and wallet-binding level.
    #[error("PID issuance authorization is invalid")]
    InvalidPidIssuanceAuthorization,
    /// A Member-State PID allocation is not one-to-one for its subject.
    #[error("PID allocation is not unique")]
    NonUniquePidAllocation,
    /// PID revocation authority, timing, publication, or privacy policy is invalid.
    #[error("PID revocation event is invalid")]
    InvalidPidRevocation,
    /// Portrait disclosure was attempted before the mandatory warning.
    #[error("portrait disclosure warning has not been acknowledged")]
    PortraitWarningRequired,
    /// Portrait disclosure was attempted without transaction-specific confirmation.
    #[error("portrait disclosure confirmation is missing")]
    PortraitConfirmationRequired,
    /// Portrait disclosure confirmation is malformed or does not match the transaction.
    #[error("portrait disclosure confirmation is invalid")]
    InvalidPortraitConfirmation,
    /// Portrait disclosure was rejected, already consumed, or otherwise closed.
    #[error("portrait disclosure is not authorized")]
    PortraitDisclosureDenied,
    /// SD-JWT presentation binding or serialization is invalid.
    #[error("SD-JWT presentation is invalid")]
    InvalidSdJwtPresentation,
    /// ISO/IEC mdoc request or response profile is invalid.
    #[error("ISO/IEC mdoc presentation is invalid")]
    InvalidMdocPresentation,
    /// OpenID4VP/HAIP request, response, or transport profile is invalid.
    #[error("OpenID4VP presentation profile is invalid")]
    InvalidOpenId4VpPresentation,
    /// Mandatory EU mediating-API capabilities are incomplete.
    #[error("EU mediating API presentation profile is invalid")]
    InvalidEuMediatingApiProfile,
    /// A wallet-relying party registration certificate did not validate.
    #[error("wallet-relying party registration is invalid")]
    InvalidRelyingPartyRegistration,
    /// A request exceeds the attestations or attributes registered for the relying party.
    #[error("wallet-relying party request exceeds its registration")]
    RelyingPartyOverasking,
    /// A presentation requires an explicit, warning-specific user decision.
    #[error("explicit presentation approval is required")]
    ExplicitPresentationApprovalRequired,
    /// Credential Issuer Metadata is incomplete or incorrectly protected.
    #[error("credential issuer metadata is invalid")]
    InvalidIssuerMetadata,
    /// Issuance violates a CIR-specific Part 3 adaptation.
    #[error("EU legal issuance profile is invalid")]
    InvalidEuIssuanceProfile,
    /// Credential reuse policy is malformed.
    #[error("credential reuse policy is invalid")]
    InvalidReusePolicy,
    /// Embedded disclosure policy is malformed.
    #[error("embedded disclosure policy is invalid")]
    InvalidEmbeddedDisclosurePolicy,
    /// Mandatory issuance flow behavior is missing.
    #[error("issuance flow is invalid")]
    InvalidIssuanceFlow,
    /// Notification endpoint or identifier is malformed.
    #[error("issuance notification request is invalid")]
    InvalidNotificationRequest,
    /// Wallet attestation or proof-of-possession processing is incomplete.
    #[error("issuance proof is invalid")]
    InvalidCredentialProof,
    /// Required issuance encryption algorithms are not supported.
    #[error("issuance cryptographic suite support is incomplete")]
    MissingIssuanceCryptoSuite,
    /// A wallet operation was attempted before successful user authentication.
    #[error("wallet user authentication is required")]
    WalletUserAuthenticationRequired,
    /// Wallet authentication state transition is invalid.
    #[error("wallet authentication state is invalid")]
    InvalidWalletAuthenticationState,
    /// Required WSCA/WSCD capabilities are incomplete.
    #[error("wallet cryptographic capabilities are incomplete")]
    InvalidWalletCryptographicCapabilities,
    /// A wallet transaction log record or its controls are incomplete.
    #[error("wallet transaction log is invalid")]
    InvalidWalletTransactionLog,
    /// WIA/KA format, transport, content, lifecycle, or revocation profile is invalid.
    #[error("wallet attestation profile is invalid")]
    InvalidWalletAttestationProfile,
    /// Wallet-attestation revocation authority, notification, or publication is invalid.
    #[error("wallet attestation revocation is invalid")]
    InvalidWalletAttestationRevocation,
    /// Wallet support does not cover every ETSI attestation format incorporated by the CIR.
    #[error("wallet credential format support is incomplete")]
    IncompleteWalletCredentialFormatSupport,
    /// A relying-party-specific pseudonym is malformed, reused, or inconsistently allocated.
    #[error("wallet pseudonym allocation is invalid")]
    InvalidWalletPseudonymAllocation,
    /// A caller supplied an empty, oversized, or non-canonical normative identifier.
    #[error("normative requirement identifier is invalid")]
    InvalidNormativeRequirementIdentifier,
    /// The identifier is well-formed but is not in the supported ETSI editions.
    #[error("normative requirement identifier is unknown")]
    UnknownNormativeRequirement,
    /// The embedded one-to-one requirement routing table is malformed or incomplete.
    #[error("normative requirement registry is invalid")]
    InvalidNormativeRequirementRegistry,
}

/// Result returned by conformance validators.
pub type Result<T> = core::result::Result<T, ConformanceError>;
