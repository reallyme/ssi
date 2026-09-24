// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Protocol-neutral ETSI TS 119 472 and EU PID conformance policy over privacy-safe, fail-closed facts.
mod catalogue;
mod country;
mod error;
mod eu_status;
mod issuance;
mod model;
mod pid;
mod pid_claims;
mod pid_lifecycle;
mod portrait;
mod presentation;
mod requirements;
mod standards;
mod validate;
mod wallet_attestation;
mod wallet_core;
pub use catalogue::{
    validate_attestation_catalogue_json, validate_attribute_catalogue_json,
    AttestationCatalogueSummary, AttributeCatalogueSummary, CatalogueError, CatalogueErrorReason,
};
pub use error::{ConformanceError, Result};
pub use eu_status::{
    validate_eu_mdoc_status, validate_eu_mdoc_status_capabilities, EuMdocStatusAlgorithm,
    EuMdocStatusCapabilities, EuMdocStatusTokenFacts, MdocStatusCorrelationKey,
};
pub use issuance::{
    validate_eu_issuance, validate_issuance, CredentialFormatSet, CredentialProofFacts,
    EmbeddedDisclosurePolicy, IssuanceFacts, IssuanceFlow, IssuerMetadataFacts, NotificationEvent,
    NotificationRequest, ReuseMethod, ReuseMethodSet, ReusePolicy, ReusePolicyDecision,
};
pub use model::{
    AttestationCategory, AttestationCategorySignal, AttestationFormat, AttestationIdentifier,
    AttributeEvidence, CommonAttestationFacts, CommonProfileData, FormatFacts, IssuedOnBehalf,
    IssuerSignature, JsonLdFacts, MdocFacts, RenewalService, SdJwtFacts, SelectiveDisclosureFacts,
    StatusFacts, SubjectBinding, ValidityFacts, ValidityInterval, X509AttributeCertificateFacts,
};
pub use pid::{
    validate_legal_person_pid, validate_natural_person_pid, CalendarDate, LegalPersonPidClaims,
    LegalPersonPidFacts, NaturalPersonPidFacts, PidProviderMetadata, OPTIONAL_EMAIL,
    OPTIONAL_FAMILY_NAME_BIRTH, OPTIONAL_GIVEN_NAME_BIRTH, OPTIONAL_MOBILE_PHONE_NUMBER,
    OPTIONAL_PERSONAL_ADMINISTRATIVE_NUMBER, OPTIONAL_RESIDENT_ADDRESS, OPTIONAL_RESIDENT_CITY,
    OPTIONAL_RESIDENT_COUNTRY, OPTIONAL_RESIDENT_POSTAL_CODE, OPTIONAL_RESIDENT_STATE,
    OPTIONAL_RESIDENT_STREET, OPTIONAL_SEX,
};
pub use pid_claims::{
    BirthPlace, NaturalPersonPidClaims, OptionalNaturalPersonPidClaims, Portrait,
    PortraitQualityProfile, Sex,
};
pub use pid_lifecycle::{
    validate_pid_allocation, validate_pid_issuance_authorization, validate_pid_revocation,
    PidAllocationKey, PidIssuanceAuthorization, PidProviderAuthentication, PidRevocationEvent,
    PidRevocationReason,
};
pub use portrait::{
    PortraitDisclosureDecision, PortraitDisclosureEvent, PortraitDisclosureGate,
    PortraitDisclosureRequest,
};
pub use presentation::{
    authorize_eu_presentation, validate_eu_mediating_api, validate_mdoc_presentation,
    validate_openid4vp_presentation, validate_openid4vp_presentation_for_profile,
    validate_sd_jwt_presentation, EtsiPart2Profile, EuMediatingApiFacts, FailedRegistrationPolicy,
    MdocPresentationFacts, OpenId4VpPresentationFacts, OveraskingPolicy, PresentationAuthorization,
    PresentationUserDecision, RegisteredClaim, RelyingPartyRegistrationStatus,
    SdJwtPresentationFacts, SdJwtSerialization,
};
pub use requirements::{
    resolve_eu_profile_requirement, resolve_normative_requirement,
    validate_eu_profile_requirement_registry, validate_normative_requirement_registry,
    ComposedEvidenceBoundary, EuProfileRequirementControl, EuProfileRequirementSummary,
    EuProfileSource, NormativeEuProfileStatus, NormativeRequirementApplicability,
    NormativeRequirementArea, NormativeRequirementControl, NormativeRequirementHandler,
    NormativeRequirementPart, NormativeRequirementProfile, NormativeRequirementSummary,
    RequirementDisposition, RequirementTraceEvidence,
};
pub use standards::{
    CIR_2024_2977_CONSOLIDATED_DATE, CIR_2024_2979_CONSOLIDATED_DATE,
    CIR_2024_2982_CONSOLIDATED_DATE, ETSI_TS_119_472_1_VERSION, ETSI_TS_119_472_2_EU_LEGAL_VERSION,
    ETSI_TS_119_472_2_VERSION, ETSI_TS_119_472_3_VERSION, EU_PID_MDOC_TYPE, EU_PID_SD_JWT_VCT,
    PUBLIC_BODY_EAA_CATEGORY_URN, QEAA_CATEGORY_URN,
};
pub use validate::validate_attestation;
pub use wallet_attestation::{
    validate_wallet_attestation_profile, KeyAttestationIndexPolicy, KeyAttestationProof,
    PerIssuerIndexReuse, StatusPeriodSelection, WalletAttestationAlgorithm,
    WalletAttestationProfile, WiaIndexBinding, WiaStatusIndexPolicy,
};
pub use wallet_core::{
    evaluate_wallet_disclosure_policy, validate_relying_party_pseudonym,
    validate_wallet_attestation_revocation, validate_wallet_cryptographic_capabilities,
    validate_wallet_format_capabilities, validate_wallet_transaction_log,
    RelyingPartyPseudonymBinding, TransactionFailureReason, TransactionOutcome,
    WalletAttestationRevocationEvent, WalletAttestationRevocationReason,
    WalletCryptographicCapabilities, WalletDisclosurePolicy, WalletOperation, WalletOperationGate,
    WalletRelyingPartyLogData, WalletTransactionKind, WalletTransactionLogControls,
    WalletTransactionLogEntry,
};
