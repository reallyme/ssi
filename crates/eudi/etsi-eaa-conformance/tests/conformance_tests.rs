// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use reallyme_etsi_eaa_conformance::{
    authorize_eu_presentation, evaluate_wallet_disclosure_policy, validate_attestation,
    validate_eu_issuance, validate_eu_mdoc_status, validate_eu_mdoc_status_capabilities,
    validate_eu_mediating_api, validate_issuance, validate_legal_person_pid,
    validate_mdoc_presentation, validate_natural_person_pid, validate_openid4vp_presentation,
    validate_openid4vp_presentation_for_profile, validate_pid_allocation,
    validate_pid_issuance_authorization, validate_pid_revocation, validate_relying_party_pseudonym,
    validate_sd_jwt_presentation, validate_wallet_attestation_profile,
    validate_wallet_attestation_revocation, validate_wallet_cryptographic_capabilities,
    validate_wallet_format_capabilities, validate_wallet_transaction_log, AttestationCategory,
    AttestationCategorySignal, AttestationFormat, AttestationIdentifier, AttributeEvidence,
    BirthPlace, CalendarDate, CommonAttestationFacts, CommonProfileData, ConformanceError,
    CredentialFormatSet, CredentialProofFacts, EmbeddedDisclosurePolicy, EtsiPart2Profile,
    EuMdocStatusAlgorithm, EuMdocStatusCapabilities, EuMdocStatusTokenFacts, EuMediatingApiFacts,
    FailedRegistrationPolicy, FormatFacts, IssuanceFacts, IssuanceFlow, IssuedOnBehalf,
    IssuerMetadataFacts, IssuerSignature, JsonLdFacts, KeyAttestationIndexPolicy,
    KeyAttestationProof, LegalPersonPidClaims, LegalPersonPidFacts, MdocFacts,
    MdocPresentationFacts, MdocStatusCorrelationKey, NaturalPersonPidClaims, NaturalPersonPidFacts,
    NotificationEvent, NotificationRequest, OpenId4VpPresentationFacts,
    OptionalNaturalPersonPidClaims, OveraskingPolicy, PerIssuerIndexReuse, PidAllocationKey,
    PidIssuanceAuthorization, PidProviderAuthentication, PidProviderMetadata, PidRevocationEvent,
    PidRevocationReason, Portrait, PortraitDisclosureDecision, PortraitDisclosureEvent,
    PortraitDisclosureGate, PortraitDisclosureRequest, PortraitQualityProfile,
    PresentationUserDecision, RegisteredClaim, RelyingPartyPseudonymBinding,
    RelyingPartyRegistrationStatus, RenewalService, ReuseMethod, ReuseMethodSet, ReusePolicy,
    ReusePolicyDecision, SdJwtFacts, SdJwtPresentationFacts, SdJwtSerialization,
    SelectiveDisclosureFacts, Sex, StatusFacts, StatusPeriodSelection, SubjectBinding,
    TransactionFailureReason, TransactionOutcome, ValidityFacts, ValidityInterval,
    WalletAttestationAlgorithm, WalletAttestationProfile, WalletAttestationRevocationEvent,
    WalletAttestationRevocationReason, WalletCryptographicCapabilities, WalletDisclosurePolicy,
    WalletOperation, WalletOperationGate, WalletRelyingPartyLogData, WalletTransactionKind,
    WalletTransactionLogControls, WalletTransactionLogEntry, WiaStatusIndexPolicy,
    X509AttributeCertificateFacts, EU_PID_MDOC_TYPE, EU_PID_SD_JWT_VCT, OPTIONAL_EMAIL,
    PUBLIC_BODY_EAA_CATEGORY_URN, QEAA_CATEGORY_URN,
};

#[path = "conformance_tests/coverage.rs"]
mod coverage;
#[path = "conformance_tests/format_profiles.rs"]
mod format_profiles;
#[path = "conformance_tests/issuance_wallet.rs"]
mod issuance_wallet;
#[path = "conformance_tests/pid.rs"]
mod pid;
#[path = "conformance_tests/presentation.rs"]
mod presentation;
#[path = "conformance_tests/status_common.rs"]
mod status_common;

fn common_pid(
    format: AttestationFormat,
    type_identifier: &'static str,
) -> CommonAttestationFacts<'static> {
    CommonAttestationFacts {
        format,
        category: AttestationCategory::NaturalPersonPid,
        type_identifier,
        category_signal: AttestationCategorySignal::Absent,
        issuer_identifier: Some("https://issuer.example"),
        issuer_country: Some("DE"),
        issuer_name: Some("Example PID Provider"),
        issuer_signature_certificate_url: None,
        subject_binding: SubjectBinding::Identifier,
        all_attributes_same_subject: true,
        validity: ValidityFacts {
            technical_not_before: 1_800_000_000,
            technical_not_after: 1_800_003_600,
            administrative: Some(ValidityInterval {
                not_before: 1_800_000_000,
                not_after: 1_800_003_600,
            }),
        },
        profile: CommonProfileData {
            components_use_uri_names: true,
            context_uris: &["https://issuer.example/context/eudi-pid"],
            schema_uris: &["https://issuer.example/schema/eudi-pid"],
            attestation_identifier: Some(AttestationIdentifier::Uri(
                "urn:uuid:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            )),
            issued_on_behalf: None,
            issued_at: Some(1_799_999_900),
            audiences: &["eudi-wallet"],
            one_time_use: false,
            terms_of_use_uris: &["https://issuer.example/terms/eudi-pid"],
            attribute_evidence: &[AttributeEvidence {
                evidence_type_uri: "urn:eu:eudi:evidence:authentic-source",
                source_uri: "https://issuer.example/evidence/record",
                sha256: &[0x11; 32],
            }],
            renewal_service: Some(RenewalService {
                endpoint: "https://issuer.example/renew",
                available_until: 1_800_003_600,
            }),
        },
        attribute_identifiers_complete: true,
        attribute_values_complete: true,
        attribute_subjects_complete: true,
        selective_disclosure: Some(SelectiveDisclosureFacts {
            disclosure_count: 8,
            signed_reference_count: 8,
            references_unambiguous: true,
            algorithm_valid: true,
        }),
        holder_public_key_bound: true,
        issuer_signature: IssuerSignature::Advanced,
        status: StatusFacts::Revocation {
            privacy_preserving: true,
            binary_only: true,
            irreversible: true,
        },
    }
}

fn sd_jwt_pid() -> SdJwtFacts<'static> {
    SdJwtFacts {
        vct: EU_PID_SD_JWT_VCT,
        vct_integrity_valid: true,
        validity_claims_match: true,
        disclosure_algorithm_valid: true,
        individual_claim_disclosure: true,
        confirmation_key_present: true,
        confirmation_key_wscd_protected: true,
        protected_x5u_present: true,
        protected_x5t_s256_present: true,
    }
}

fn provider_metadata() -> PidProviderMetadata<'static> {
    PidProviderMetadata {
        issuing_authority: "Example PID Provider",
        issuing_country: "DE",
        expiry_date: Some(CalendarDate {
            year: 2030,
            month: 12,
            day: 31,
        }),
        document_number: Some("document-42"),
        issuing_jurisdiction: Some("DE-BE"),
        issuance_date: Some(CalendarDate {
            year: 2026,
            month: 9,
            day: 21,
        }),
    }
}

fn natural_pid(format: AttestationFormat) -> NaturalPersonPidFacts<'static> {
    let mandatory = NaturalPersonPidFacts::all_mandatory_mask();
    let portrait = match format {
        AttestationFormat::SdJwtVc => Portrait::SdJwtJpegDataUrl {
            value: "data:image/jpeg;base64,/9j/2Q==",
            quality: PortraitQualityProfile::NotAssessedBefore2028,
        },
        AttestationFormat::IsoMdoc => Portrait::MdocJpeg {
            bytes: &[0xff, 0xd8, 0xff, 0xd9],
            quality: PortraitQualityProfile::NotAssessedBefore2028,
        },
        _ => Portrait::OptedOutEmpty,
    };
    NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            family_name: "Mustermann",
            given_name: "Erika",
            birth_date: CalendarDate {
                year: 1990,
                month: 5,
                day: 17,
            },
            birth_place: BirthPlace {
                country: Some("DE"),
                region: Some("Berlin"),
                locality: Some("Berlin"),
            },
            nationalities: &["DE"],
            portrait,
            assessment_date: CalendarDate {
                year: 2026,
                month: 9,
                day: 21,
            },
            optional: OptionalNaturalPersonPidClaims::empty(),
        },
        mandatory_disclosable: mandatory,
        optional_disclosable: 0,
        portrait_opt_out_authorized: false,
        provider_metadata: provider_metadata(),
    }
}
