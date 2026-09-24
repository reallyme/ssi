// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    common_pid, sd_jwt_pid, validate_attestation, validate_eu_mdoc_status,
    validate_eu_mdoc_status_capabilities, validate_sd_jwt_presentation, AttestationCategory,
    AttestationCategorySignal, AttestationFormat, AttestationIdentifier, AttributeEvidence,
    CommonAttestationFacts, CommonProfileData, ConformanceError, EuMdocStatusAlgorithm,
    EuMdocStatusCapabilities, EuMdocStatusTokenFacts, FormatFacts, IssuedOnBehalf, IssuerSignature,
    MdocStatusCorrelationKey, RenewalService, SdJwtFacts, SdJwtPresentationFacts,
    SdJwtSerialization, StatusFacts, ValidityFacts, ValidityInterval, EU_PID_SD_JWT_VCT,
    PUBLIC_BODY_EAA_CATEGORY_URN, QEAA_CATEGORY_URN,
};

#[test]
fn rejects_pid_suspension_status_space() {
    let common = CommonAttestationFacts {
        status: StatusFacts::Revocation {
            privacy_preserving: true,
            binary_only: false,
            irreversible: true,
        },
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidStatus)
    );
}

#[test]
fn validates_eu_mdoc_status_list_token_and_unique_reference() {
    let facts = EuMdocStatusTokenFacts {
        reference: MdocStatusCorrelationKey::StatusList {
            uri: "https://status.example/lists/42",
            index: 17,
        },
        content_type: "application/statuslist+cwt",
        expires_at: 1_900_000_000,
        verified_at: 1_800_000_000,
        time_to_live: Some(3_600),
        algorithm: EuMdocStatusAlgorithm::Es256,
        protected_x5chain_present: true,
        signature_and_certificate_binding_valid: true,
        bits_per_status: Some(1),
        status_list_claim_present: true,
        identifier_list_claim_65530_present: false,
        binary_revocation_only: true,
        irreversible_revocation: true,
    };

    assert_eq!(validate_eu_mdoc_status(&facts, &[]), Ok(()));
}

#[test]
fn rejects_correlatable_eu_mdoc_status_reference() {
    let prior = [MdocStatusCorrelationKey::IdentifierList {
        uri: "https://status.example/identifiers",
        identifier: &[0x01, 0x02],
    }];
    let facts = EuMdocStatusTokenFacts {
        reference: MdocStatusCorrelationKey::IdentifierList {
            uri: "https://status.example/identifiers",
            identifier: &[0x01, 0x02],
        },
        content_type: "application/identifierlist+cwt",
        expires_at: 1_900_000_000,
        verified_at: 1_800_000_000,
        time_to_live: None,
        algorithm: EuMdocStatusAlgorithm::Esb384,
        protected_x5chain_present: true,
        signature_and_certificate_binding_valid: true,
        bits_per_status: None,
        status_list_claim_present: false,
        identifier_list_claim_65530_present: true,
        binary_revocation_only: true,
        irreversible_revocation: true,
    };

    assert_eq!(
        validate_eu_mdoc_status(&facts, &prior),
        Err(ConformanceError::CorrelatableMdocStatusReference)
    );
}

#[test]
fn rejects_identifier_list_that_contains_status_list_claim() {
    let facts = EuMdocStatusTokenFacts {
        reference: MdocStatusCorrelationKey::IdentifierList {
            uri: "https://status.example/identifiers",
            identifier: &[0x03, 0x04],
        },
        content_type: "application/identifierlist+cwt",
        expires_at: 1_900_000_000,
        verified_at: 1_800_000_000,
        time_to_live: None,
        algorithm: EuMdocStatusAlgorithm::Es512,
        protected_x5chain_present: true,
        signature_and_certificate_binding_valid: true,
        bits_per_status: None,
        status_list_claim_present: true,
        identifier_list_claim_65530_present: true,
        binary_revocation_only: true,
        irreversible_revocation: true,
    };

    assert_eq!(
        validate_eu_mdoc_status(&facts, &[]),
        Err(ConformanceError::InvalidEuMdocStatusProfile)
    );
}

#[test]
fn validates_eu_mdoc_status_system_capabilities() {
    assert_eq!(
        validate_eu_mdoc_status_capabilities(EuMdocStatusCapabilities {
            wallet_implements_both_mechanisms: true,
            issuer_verifies_both_for_wallet_attestations: true,
            wallet_attestations_use_profiled_revocation: true,
            relying_party_status_check_supports_both: true,
        }),
        Ok(())
    );
}

#[test]
fn rejects_malformed_renewal_service() {
    let common = CommonAttestationFacts {
        profile: CommonProfileData {
            renewal_service: Some(RenewalService {
                endpoint: "http://issuer.example/renew",
                available_until: 1_800_003_600,
            }),
            ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT).profile
        },
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidRenewalService)
    );
}

#[test]
fn rejects_duplicate_context_uris() {
    let common = CommonAttestationFacts {
        profile: CommonProfileData {
            context_uris: &[
                "https://issuer.example/context/eudi-pid",
                "https://issuer.example/context/eudi-pid",
            ],
            ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT).profile
        },
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidContext)
    );
}

#[test]
fn requires_context_when_component_names_are_urls() {
    let common = CommonAttestationFacts {
        profile: CommonProfileData {
            context_uris: &[],
            ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT).profile
        },
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidContext)
    );
}

#[test]
fn optional_common_identifier_and_issuance_time_may_be_absent() {
    let mut facts = sd_jwt_pid();
    facts.vct = "urn:example:eaa:generic";
    let common = CommonAttestationFacts {
        category: AttestationCategory::Eaa,
        type_identifier: facts.vct,
        issuer_identifier: None,
        profile: CommonProfileData {
            components_use_uri_names: false,
            context_uris: &[],
            attestation_identifier: None,
            issued_at: None,
            ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT).profile
        },
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(facts)),
        Ok(())
    );
}

#[test]
fn validates_optional_issuance_on_behalf_values_when_present() {
    let common = CommonAttestationFacts {
        profile: CommonProfileData {
            issued_on_behalf: Some(IssuedOnBehalf {
                entity_identifier: Some("legal-person:example"),
                entity_name: Some("Example Public Authority"),
                registration_identifier: Some("EU-EXAMPLE-123"),
            }),
            ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT).profile
        },
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Ok(())
    );
}

#[test]
fn rejects_malformed_optional_issuance_on_behalf_value() {
    let common = CommonAttestationFacts {
        profile: CommonProfileData {
            issued_on_behalf: Some(IssuedOnBehalf {
                entity_identifier: Some(" leading-space"),
                entity_name: None,
                registration_identifier: None,
            }),
            ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT).profile
        },
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidIssuedOnBehalf)
    );
}

#[test]
fn rejects_invalid_optional_attestation_identifier_when_present() {
    let common = CommonAttestationFacts {
        profile: CommonProfileData {
            attestation_identifier: Some(AttestationIdentifier::Opaque(&[])),
            ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT).profile
        },
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidAttestationIdentifier)
    );
}

#[test]
fn rejects_inverted_administrative_validity_interval() {
    let common = CommonAttestationFacts {
        validity: ValidityFacts {
            technical_not_before: 1_800_000_000,
            technical_not_after: 1_800_003_600,
            administrative: Some(ValidityInterval {
                not_before: 1_800_003_600,
                not_after: 1_800_000_000,
            }),
        },
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidAdministrativeValidity)
    );
}

#[test]
fn rejects_issuance_after_technical_validity_starts() {
    let common = CommonAttestationFacts {
        profile: CommonProfileData {
            issued_at: Some(1_800_000_001),
            ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT).profile
        },
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidIssuanceTime)
    );
}

#[test]
fn rejects_malformed_attribute_evidence_uri() {
    let common = CommonAttestationFacts {
        profile: CommonProfileData {
            attribute_evidence: &[AttributeEvidence {
                evidence_type_uri: "not a URI",
                source_uri: "https://issuer.example/evidence/record",
                sha256: &[0x22; 32],
            }],
            ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT).profile
        },
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidAttributeEvidence)
    );
}

#[test]
fn rejects_duplicate_attribute_evidence() {
    let evidence = AttributeEvidence {
        evidence_type_uri: "urn:eu:eudi:evidence:authentic-source",
        source_uri: "https://issuer.example/evidence/record",
        sha256: &[0x33; 32],
    };
    let common = CommonAttestationFacts {
        profile: CommonProfileData {
            attribute_evidence: &[evidence, evidence],
            ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT).profile
        },
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidAttributeEvidence)
    );
}

#[test]
fn rejects_malformed_issuer_country_code() {
    let common = CommonAttestationFacts {
        issuer_country: Some("ZZ"),
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidIssuerIdentity)
    );
}

#[test]
fn rejects_malformed_optional_issuer_identifier() {
    let common = CommonAttestationFacts {
        issuer_identifier: Some(" issuer-with-leading-space"),
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidIssuerIdentity)
    );
}

#[test]
fn accepts_short_lived_pid_without_status_at_twenty_four_hours() {
    let common = CommonAttestationFacts {
        validity: ValidityFacts {
            technical_not_before: 1_800_000_000,
            technical_not_after: 1_800_086_400,
            administrative: Some(ValidityInterval {
                not_before: 1_800_000_000,
                not_after: 1_800_003_600,
            }),
        },
        status: StatusFacts::ShortLivedExempt,
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Ok(())
    );
}

#[test]
fn rejects_short_lived_pid_over_twenty_four_hours() {
    let common = CommonAttestationFacts {
        validity: ValidityFacts {
            technical_not_before: 1_800_000_000,
            technical_not_after: 1_800_086_401,
            administrative: Some(ValidityInterval {
                not_before: 1_800_000_000,
                not_after: 1_800_086_401,
            }),
        },
        status: StatusFacts::ShortLivedExempt,
        ..common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT)
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(sd_jwt_pid())),
        Err(ConformanceError::InvalidShortLivedExemption)
    );
}

#[test]
fn rejects_qeaa_without_qualified_signature() {
    let common = CommonAttestationFacts {
        category: AttestationCategory::Qeaa,
        category_signal: AttestationCategorySignal::Uri(QEAA_CATEGORY_URN),
        issuer_signature_certificate_url: Some("https://issuer.example/signing-certificate.der"),
        issuer_signature: IssuerSignature::Advanced,
        ..common_pid(AttestationFormat::SdJwtVc, "urn:example:qeaa:1")
    };
    let facts = SdJwtFacts {
        vct: "urn:example:qeaa:1",
        ..sd_jwt_pid()
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(facts)),
        Err(ConformanceError::InvalidIssuerSignature)
    );
}

#[test]
fn rejects_qeaa_with_wrong_category_uri() {
    let common = CommonAttestationFacts {
        category: AttestationCategory::Qeaa,
        category_signal: AttestationCategorySignal::Uri("urn:example:not-qualified"),
        issuer_signature_certificate_url: Some("https://issuer.example/signing-certificate.der"),
        issuer_signature: IssuerSignature::Qualified,
        ..common_pid(AttestationFormat::SdJwtVc, "urn:example:qeaa:1")
    };
    let facts = SdJwtFacts {
        vct: "urn:example:qeaa:1",
        ..sd_jwt_pid()
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(facts)),
        Err(ConformanceError::InvalidCategorySignal)
    );
}

#[test]
fn rejects_qeaa_without_signature_certificate_reference() {
    let common = CommonAttestationFacts {
        category: AttestationCategory::Qeaa,
        category_signal: AttestationCategorySignal::Uri(QEAA_CATEGORY_URN),
        issuer_signature: IssuerSignature::Qualified,
        ..common_pid(AttestationFormat::SdJwtVc, "urn:example:qeaa:1")
    };
    let facts = SdJwtFacts {
        vct: "urn:example:qeaa:1",
        ..sd_jwt_pid()
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(facts)),
        Err(ConformanceError::InvalidIssuerSignatureCertificateReference)
    );
}

#[test]
fn validates_public_body_category_uri_and_signature_certificate_reference() {
    let common = CommonAttestationFacts {
        category: AttestationCategory::PublicBodyEaa,
        category_signal: AttestationCategorySignal::Uri(PUBLIC_BODY_EAA_CATEGORY_URN),
        issuer_signature_certificate_url: Some("https://issuer.example/signing-certificate.der"),
        issuer_signature: IssuerSignature::QualifiedPublicBody,
        ..common_pid(AttestationFormat::SdJwtVc, "urn:example:public-body-eaa:1")
    };
    let facts = SdJwtFacts {
        vct: "urn:example:public-body-eaa:1",
        ..sd_jwt_pid()
    };

    assert_eq!(
        validate_attestation(&common, &FormatFacts::SdJwt(facts)),
        Ok(())
    );
}

#[test]
fn enforces_sd_jwt_key_binding_when_cnf_is_present() {
    let facts = SdJwtPresentationFacts {
        credential_has_confirmation: true,
        key_binding_jwt_present: false,
        key_binding_signed_by_subject: false,
        serialization: SdJwtSerialization::Compact,
    };

    assert_eq!(
        validate_sd_jwt_presentation(&facts),
        Err(ConformanceError::InvalidSdJwtPresentation)
    );
}
