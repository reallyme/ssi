// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    common_pid, natural_pid, provider_metadata, sd_jwt_pid, validate_legal_person_pid,
    validate_natural_person_pid, validate_pid_allocation, validate_pid_issuance_authorization,
    validate_pid_revocation, AttestationFormat, BirthPlace, CalendarDate, ConformanceError,
    FormatFacts, LegalPersonPidClaims, LegalPersonPidFacts, MdocFacts, NaturalPersonPidClaims,
    NaturalPersonPidFacts, OptionalNaturalPersonPidClaims, PidAllocationKey,
    PidIssuanceAuthorization, PidProviderAuthentication, PidProviderMetadata, PidRevocationEvent,
    PidRevocationReason, Portrait, PortraitDisclosureDecision, PortraitDisclosureEvent,
    PortraitDisclosureGate, PortraitDisclosureRequest, PortraitQualityProfile, Sex,
    EU_PID_MDOC_TYPE, EU_PID_SD_JWT_VCT, OPTIONAL_EMAIL,
};

#[test]
fn accepts_complete_sd_jwt_pid() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());

    assert_eq!(
        validate_natural_person_pid(&common, &format, &natural_pid(AttestationFormat::SdJwtVc)),
        Ok(())
    );
}

#[test]
fn accepts_complete_mdoc_pid() {
    let common = common_pid(AttestationFormat::IsoMdoc, EU_PID_MDOC_TYPE);
    let format = FormatFacts::Mdoc(MdocFacts {
        doc_type: EU_PID_MDOC_TYPE,
        namespace: EU_PID_MDOC_TYPE,
        device_key_present: true,
        device_key_wscd_protected: true,
        protected_x5u_present: true,
        protected_x5t_sha256_present: true,
        deterministic_cbor: true,
        text_constraints_valid: true,
        date_constraints_valid: true,
    });

    assert_eq!(
        validate_natural_person_pid(&common, &format, &natural_pid(AttestationFormat::IsoMdoc)),
        Ok(())
    );
}

#[test]
fn rejects_missing_mandatory_pid_claim() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let pid = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            family_name: "",
            ..natural_pid(AttestationFormat::SdJwtVc).claims
        },
        ..natural_pid(AttestationFormat::SdJwtVc)
    };

    assert_eq!(
        validate_natural_person_pid(&common, &format, &pid),
        Err(ConformanceError::MissingMandatoryPidClaim)
    );
}

#[test]
fn rejects_invalid_optional_pid_claim() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let pid = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            optional: OptionalNaturalPersonPidClaims {
                email: Some("not-an-email"),
                ..OptionalNaturalPersonPidClaims::empty()
            },
            ..natural_pid(AttestationFormat::SdJwtVc).claims
        },
        optional_disclosable: OPTIONAL_EMAIL,
        ..natural_pid(AttestationFormat::SdJwtVc)
    };

    assert_eq!(
        validate_natural_person_pid(&common, &format, &pid),
        Err(ConformanceError::InvalidPidClaimEncoding)
    );
}

#[test]
fn rejects_present_pid_claim_without_independent_disclosure() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let pid = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            optional: OptionalNaturalPersonPidClaims {
                email: Some("erika@example.eu"),
                ..OptionalNaturalPersonPidClaims::empty()
            },
            ..natural_pid(AttestationFormat::SdJwtVc).claims
        },
        optional_disclosable: 0,
        ..natural_pid(AttestationFormat::SdJwtVc)
    };

    assert_eq!(
        validate_natural_person_pid(&common, &format, &pid),
        Err(ConformanceError::InvalidPidSelectiveDisclosure)
    );
}

#[test]
fn rejects_invalid_pid_provider_calendar_date() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let pid = NaturalPersonPidFacts {
        provider_metadata: PidProviderMetadata {
            expiry_date: Some(CalendarDate {
                year: 2027,
                month: 2,
                day: 29,
            }),
            ..provider_metadata()
        },
        ..natural_pid(AttestationFormat::SdJwtVc)
    };

    assert_eq!(
        validate_natural_person_pid(&common, &format, &pid),
        Err(ConformanceError::InvalidPidMetadata)
    );
}

#[test]
fn rejects_unassigned_pid_provider_country_code() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let pid = NaturalPersonPidFacts {
        provider_metadata: PidProviderMetadata {
            issuing_country: "ZZ",
            ..provider_metadata()
        },
        ..natural_pid(AttestationFormat::SdJwtVc)
    };

    assert_eq!(
        validate_natural_person_pid(&common, &format, &pid),
        Err(ConformanceError::InvalidPidMetadata)
    );
}

#[test]
fn accepts_rfc5322_email_mobile_and_closed_sex_value() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let pid = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            optional: OptionalNaturalPersonPidClaims {
                email: Some("\"quoted local\"@example.eu"),
                mobile_phone_number: Some("+491701234567"),
                sex: Some(Sex::NotApplicable),
                ..OptionalNaturalPersonPidClaims::empty()
            },
            ..natural_pid(AttestationFormat::SdJwtVc).claims
        },
        optional_disclosable: OPTIONAL_EMAIL
            | reallyme_etsi_eaa_conformance::OPTIONAL_MOBILE_PHONE_NUMBER
            | reallyme_etsi_eaa_conformance::OPTIONAL_SEX,
        ..natural_pid(AttestationFormat::SdJwtVc)
    };

    assert_eq!(validate_natural_person_pid(&common, &format, &pid), Ok(()));
}

#[test]
fn accepts_unknown_and_stateless_nationality_codes() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let pid = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            nationalities: &["QU", "QS"],
            ..natural_pid(AttestationFormat::SdJwtVc).claims
        },
        ..natural_pid(AttestationFormat::SdJwtVc)
    };

    assert_eq!(validate_natural_person_pid(&common, &format, &pid), Ok(()));
}

#[test]
fn rejects_duplicate_nationality_codes() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let pid = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            nationalities: &["DE", "DE"],
            ..natural_pid(AttestationFormat::SdJwtVc).claims
        },
        ..natural_pid(AttestationFormat::SdJwtVc)
    };

    assert_eq!(
        validate_natural_person_pid(&common, &format, &pid),
        Err(ConformanceError::InvalidPidClaimEncoding)
    );
}

#[test]
fn rejects_empty_birth_place() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let pid = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            birth_place: BirthPlace {
                country: None,
                region: None,
                locality: None,
            },
            ..natural_pid(AttestationFormat::SdJwtVc).claims
        },
        ..natural_pid(AttestationFormat::SdJwtVc)
    };

    assert_eq!(
        validate_natural_person_pid(&common, &format, &pid),
        Err(ConformanceError::InvalidPidClaimEncoding)
    );
}

#[test]
fn rejects_noncanonical_sd_jwt_portrait_base64() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let pid = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            portrait: Portrait::SdJwtJpegDataUrl {
                value: "data:image/jpeg;base64,/9j/2R==",
                quality: PortraitQualityProfile::NotAssessedBefore2028,
            },
            ..natural_pid(AttestationFormat::SdJwtVc).claims
        },
        ..natural_pid(AttestationFormat::SdJwtVc)
    };

    assert_eq!(
        validate_natural_person_pid(&common, &format, &pid),
        Err(ConformanceError::InvalidPidPortrait)
    );
}

#[test]
fn requires_iso_portrait_quality_assessment_from_august_2028() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let unassessed = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            assessment_date: CalendarDate {
                year: 2028,
                month: 8,
                day: 11,
            },
            ..natural_pid(AttestationFormat::SdJwtVc).claims
        },
        ..natural_pid(AttestationFormat::SdJwtVc)
    };
    assert_eq!(
        validate_natural_person_pid(&common, &format, &unassessed),
        Err(ConformanceError::InvalidPidPortrait)
    );

    let assessed = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            portrait: Portrait::SdJwtJpegDataUrl {
                value: "data:image/jpeg;base64,/9j/2Q==",
                quality: PortraitQualityProfile::Iso39794_5,
            },
            assessment_date: CalendarDate {
                year: 2028,
                month: 8,
                day: 11,
            },
            ..natural_pid(AttestationFormat::SdJwtVc).claims
        },
        ..natural_pid(AttestationFormat::SdJwtVc)
    };
    assert_eq!(
        validate_natural_person_pid(&common, &format, &assessed),
        Ok(())
    );
}

#[test]
fn rejects_portrait_encoding_that_does_not_match_credential_format() {
    let common = common_pid(AttestationFormat::IsoMdoc, EU_PID_MDOC_TYPE);
    let format = FormatFacts::Mdoc(MdocFacts {
        doc_type: EU_PID_MDOC_TYPE,
        namespace: EU_PID_MDOC_TYPE,
        device_key_present: true,
        device_key_wscd_protected: true,
        protected_x5u_present: true,
        protected_x5t_sha256_present: true,
        deterministic_cbor: true,
        text_constraints_valid: true,
        date_constraints_valid: true,
    });
    let pid = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            portrait: Portrait::SdJwtJpegDataUrl {
                value: "data:image/jpeg;base64,/9j/2Q==",
                quality: PortraitQualityProfile::NotAssessedBefore2028,
            },
            ..natural_pid(AttestationFormat::IsoMdoc).claims
        },
        ..natural_pid(AttestationFormat::IsoMdoc)
    };

    assert_eq!(
        validate_natural_person_pid(&common, &format, &pid),
        Err(ConformanceError::InvalidPidPortrait)
    );
}

#[test]
fn permits_empty_portrait_only_under_member_state_opt_out() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let denied = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            portrait: Portrait::OptedOutEmpty,
            ..natural_pid(AttestationFormat::SdJwtVc).claims
        },
        ..natural_pid(AttestationFormat::SdJwtVc)
    };
    assert_eq!(
        validate_natural_person_pid(&common, &format, &denied),
        Err(ConformanceError::InvalidPidPortrait)
    );

    let permitted = NaturalPersonPidFacts {
        claims: NaturalPersonPidClaims {
            portrait: Portrait::OptedOutEmpty,
            ..natural_pid(AttestationFormat::SdJwtVc).claims
        },
        portrait_opt_out_authorized: true,
        ..natural_pid(AttestationFormat::SdJwtVc)
    };
    assert_eq!(
        validate_natural_person_pid(&common, &format, &permitted),
        Ok(())
    );
}

#[test]
fn rejects_issuing_jurisdiction_outside_issuing_country() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let pid = NaturalPersonPidFacts {
        provider_metadata: PidProviderMetadata {
            issuing_jurisdiction: Some("FR-IDF"),
            ..provider_metadata()
        },
        ..natural_pid(AttestationFormat::SdJwtVc)
    };

    assert_eq!(
        validate_natural_person_pid(&common, &format, &pid),
        Err(ConformanceError::InvalidPidMetadata)
    );
}

#[test]
fn portrait_disclosure_gate_enforces_warning_and_transaction_confirmation() {
    let request = PortraitDisclosureRequest::new("rp.example", "transaction-42");
    assert!(request.is_ok());
    let Ok(request) = request else {
        return;
    };
    let mut gate = PortraitDisclosureGate::new(request);

    assert_eq!(
        gate.apply(PortraitDisclosureEvent::Disclose),
        Err(ConformanceError::PortraitWarningRequired)
    );
    assert_eq!(
        gate.apply(PortraitDisclosureEvent::WarningDisplayed),
        Ok(false)
    );
    assert_eq!(
        gate.apply(PortraitDisclosureEvent::Decision {
            relying_party_id: "different-rp.example",
            transaction_id: "transaction-42",
            decision: PortraitDisclosureDecision::Confirmed,
        }),
        Err(ConformanceError::InvalidPortraitConfirmation)
    );
    assert_eq!(
        gate.apply(PortraitDisclosureEvent::Decision {
            relying_party_id: "rp.example",
            transaction_id: "transaction-42",
            decision: PortraitDisclosureDecision::Confirmed,
        }),
        Ok(false)
    );
    assert_eq!(gate.apply(PortraitDisclosureEvent::Disclose), Ok(true));
    assert_eq!(
        gate.apply(PortraitDisclosureEvent::Disclose),
        Err(ConformanceError::PortraitDisclosureDenied)
    );
}

#[test]
fn portrait_disclosure_gate_cannot_override_rejection() {
    let request = PortraitDisclosureRequest::new("rp.example", "transaction-43");
    let Ok(request) = request else {
        return;
    };
    let mut gate = PortraitDisclosureGate::new(request);
    assert_eq!(
        gate.apply(PortraitDisclosureEvent::WarningDisplayed),
        Ok(false)
    );
    assert_eq!(
        gate.apply(PortraitDisclosureEvent::Decision {
            relying_party_id: "rp.example",
            transaction_id: "transaction-43",
            decision: PortraitDisclosureDecision::Rejected,
        }),
        Ok(false)
    );
    assert_eq!(
        gate.apply(PortraitDisclosureEvent::Disclose),
        Err(ConformanceError::PortraitDisclosureDenied)
    );
}

#[test]
fn validates_complete_legal_person_pid_without_inventing_a_wire_mapping() {
    let facts = LegalPersonPidFacts {
        claims: LegalPersonPidClaims {
            current_legal_name: "Example Gesellschaft mit beschränkter Haftung",
            cross_border_identifier: "DE-BR-123456789",
            current_address: Some("Example Street 1, 10115 Berlin"),
            vat_registration_number: Some("DE123456789"),
            tax_reference_number: Some("21/815/08150"),
            european_unique_identifier: Some("DE.BR.123456789"),
            legal_entity_identifier: Some("529900T8BM49AURSDO55"),
            eori: Some("DE123456789012345"),
            excise_number: Some("DE1234567890"),
        },
        provider_metadata: provider_metadata(),
    };

    assert_eq!(validate_legal_person_pid(&facts), Ok(()));
}

#[test]
fn rejects_missing_or_malformed_legal_person_pid_values() {
    let valid = LegalPersonPidClaims {
        current_legal_name: "Example GmbH",
        cross_border_identifier: "DE-BR-123456789",
        current_address: None,
        vat_registration_number: None,
        tax_reference_number: None,
        european_unique_identifier: None,
        legal_entity_identifier: None,
        eori: None,
        excise_number: None,
    };
    let missing = LegalPersonPidFacts {
        claims: LegalPersonPidClaims {
            current_legal_name: "",
            ..valid
        },
        provider_metadata: provider_metadata(),
    };
    assert_eq!(
        validate_legal_person_pid(&missing),
        Err(ConformanceError::MissingMandatoryPidClaim)
    );

    let malformed = LegalPersonPidFacts {
        claims: LegalPersonPidClaims {
            vat_registration_number: Some("DE123\n456"),
            ..valid
        },
        provider_metadata: provider_metadata(),
    };
    assert_eq!(
        validate_legal_person_pid(&malformed),
        Err(ConformanceError::InvalidPidClaimEncoding)
    );
}

#[test]
fn validates_high_assurance_pid_issuance_authorization() {
    let facts = PidIssuanceAuthorization {
        provider_identifier: "https://issuer.example",
        credential_issuer_identifier: "https://issuer.example",
        provider_authentication: PidProviderAuthentication::WalletRelyingPartyAccessCertificate,
        electronic_identification_scheme_authorized: true,
        high_assurance_enrollment_complete: true,
        identity_proofing_complete: true,
        wallet_unit_attestation_valid: true,
        wallet_solution_accepted: true,
        authentication_data_complete: true,
        cryptographically_bound_to_authenticated_wallet: true,
    };

    assert_eq!(validate_pid_issuance_authorization(&facts), Ok(()));
}

#[test]
fn rejects_pid_issuance_to_unaccepted_wallet_solution() {
    let facts = PidIssuanceAuthorization {
        provider_identifier: "https://issuer.example",
        credential_issuer_identifier: "https://issuer.example",
        provider_authentication: PidProviderAuthentication::NotifiedHighAssuranceEid,
        electronic_identification_scheme_authorized: true,
        high_assurance_enrollment_complete: true,
        identity_proofing_complete: true,
        wallet_unit_attestation_valid: true,
        wallet_solution_accepted: false,
        authentication_data_complete: true,
        cryptographically_bound_to_authenticated_wallet: true,
    };

    assert_eq!(
        validate_pid_issuance_authorization(&facts),
        Err(ConformanceError::InvalidPidIssuanceAuthorization)
    );
}

#[test]
fn pid_allocation_is_one_to_one_within_member_state() {
    let existing = [PidAllocationKey {
        member_state: "DE",
        subject_reference: b"subject-a",
        pid_identifier: b"pid-a",
    }];
    let candidate = PidAllocationKey {
        member_state: "DE",
        subject_reference: b"subject-a",
        pid_identifier: b"pid-b",
    };

    assert_eq!(
        validate_pid_allocation(&candidate, &existing),
        Err(ConformanceError::NonUniquePidAllocation)
    );
}

#[test]
fn validates_pid_revocation_notification_and_publication() {
    let event = PidRevocationEvent {
        issuer_identifier: "https://issuer.example",
        revoking_actor_identifier: "https://issuer.example",
        public_policy_uri: "https://issuer.example/policy/revocation",
        public_status_uri: "https://status.example/pid",
        reason: PidRevocationReason::WalletUnitAttestationRevoked,
        revoked_at: 1_800_000_000,
        user_notified_at: 1_800_086_400,
        secure_notification_included_reason: true,
        public_status_privacy_preserving: true,
        irreversible: true,
        unlinkability_enabled_when_identity_not_required: true,
    };

    assert_eq!(validate_pid_revocation(&event), Ok(()));
}

#[test]
fn rejects_late_pid_revocation_notification() {
    let event = PidRevocationEvent {
        issuer_identifier: "https://issuer.example",
        revoking_actor_identifier: "https://issuer.example",
        public_policy_uri: "https://issuer.example/policy/revocation",
        public_status_uri: "https://status.example/pid",
        reason: PidRevocationReason::PublishedPolicyCause,
        revoked_at: 1_800_000_000,
        user_notified_at: 1_800_086_401,
        secure_notification_included_reason: true,
        public_status_privacy_preserving: true,
        irreversible: true,
        unlinkability_enabled_when_identity_not_required: true,
    };

    assert_eq!(
        validate_pid_revocation(&event),
        Err(ConformanceError::InvalidPidRevocation)
    );
}
