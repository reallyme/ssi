// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    common_pid, evaluate_wallet_disclosure_policy, natural_pid, sd_jwt_pid, validate_eu_issuance,
    validate_issuance, validate_natural_person_pid, validate_relying_party_pseudonym,
    validate_wallet_attestation_profile, validate_wallet_attestation_revocation,
    validate_wallet_cryptographic_capabilities, validate_wallet_format_capabilities,
    validate_wallet_transaction_log, AttestationFormat, ConformanceError, CredentialFormatSet,
    CredentialProofFacts, EmbeddedDisclosurePolicy, FormatFacts, IssuanceFacts, IssuanceFlow,
    IssuerMetadataFacts, KeyAttestationIndexPolicy, KeyAttestationProof, NaturalPersonPidFacts,
    NotificationEvent, NotificationRequest, PerIssuerIndexReuse, RelyingPartyPseudonymBinding,
    ReuseMethod, ReuseMethodSet, ReusePolicy, ReusePolicyDecision, StatusPeriodSelection,
    TransactionFailureReason, TransactionOutcome, WalletAttestationAlgorithm,
    WalletAttestationProfile, WalletAttestationRevocationEvent, WalletAttestationRevocationReason,
    WalletCryptographicCapabilities, WalletDisclosurePolicy, WalletOperation, WalletOperationGate,
    WalletRelyingPartyLogData, WalletTransactionKind, WalletTransactionLogControls,
    WalletTransactionLogEntry, WiaStatusIndexPolicy, EU_PID_SD_JWT_VCT,
};

fn valid_issuance() -> IssuanceFacts<'static> {
    IssuanceFacts {
        metadata: IssuerMetadataFacts {
            signed_metadata_valid: true,
            access_certificate_signer: true,
            protected_x5c_valid: true,
            formats: CredentialFormatSet::new(
                CredentialFormatSet::SD_JWT_VC | CredentialFormatSet::MSO_MDOC,
            ),
            issuer_info_valid: true,
            issuer_information_entries_valid: true,
            registered_attestation_types_valid: true,
            registration_certificate_present: true,
            batch_metadata_precedence_valid: true,
            reuse_policy: ReusePolicy::OmittedUnrestricted,
            disclosure_policy: Some(EmbeddedDisclosurePolicy::NoPolicy),
        },
        reuse_decision: ReusePolicyDecision {
            supported_methods: ReuseMethodSet::new(
                ReuseMethodSet::ONCE_ONLY
                    | ReuseMethodSet::LIMITED_TIME
                    | ReuseMethodSet::ROTATING_BATCH
                    | ReuseMethodSet::PER_RELYING_PARTY,
            ),
            selected_method: None,
        },
        flow: IssuanceFlow {
            authorization_code_supported: true,
            pre_authorized_code_condition_met: true,
            eu_eaa_offer_scheme_supported: true,
            credential_offer_grant_valid: true,
            wallet_instance_attestation_present: true,
            wallet_instance_proof_valid: true,
            wallet_instance_attestation_valid: true,
            notification: NotificationRequest::NotUsed,
        },
        proof: CredentialProofFacts {
            exactly_one_proof_mechanism: true,
            nonce_valid: true,
            wallet_unit_attestation_valid: true,
            proof_signature_valid: true,
            credential_count_matches_keys: true,
            one_distinct_key_per_credential: true,
        },
        a128gcm_supported: true,
        a256gcm_supported: true,
        openid4vci_security_policy_applied: true,
    }
}

#[test]
fn accepts_complete_issuance_profile() {
    assert_eq!(validate_issuance(&valid_issuance()), Ok(()));
    assert_eq!(validate_eu_issuance(&valid_issuance()), Ok(()));
}

#[test]
fn validates_structured_notification_request() {
    let mut facts = valid_issuance();
    facts.flow.notification = NotificationRequest::Sent {
        endpoint: "https://issuer.example/notification",
        notification_id: "credential-event-42",
        event: NotificationEvent::CredentialAccepted,
    };

    assert_eq!(validate_issuance(&facts), Ok(()));
}

#[test]
fn rejects_notification_with_untrusted_endpoint_shape() {
    let mut facts = valid_issuance();
    facts.flow.notification = NotificationRequest::Sent {
        endpoint: "https://user:secret@issuer.example/notification#fragment",
        notification_id: "credential-event-42",
        event: NotificationEvent::CredentialFailure,
    };

    assert_eq!(
        validate_issuance(&facts),
        Err(ConformanceError::InvalidNotificationRequest)
    );
}

#[test]
fn rejects_invalid_embedded_disclosure_policy() {
    let mut facts = valid_issuance();
    facts.metadata.disclosure_policy = Some(EmbeddedDisclosurePolicy::AuthorizedRelyingParties {
        entries_valid: false,
    });

    assert_eq!(
        validate_issuance(&facts),
        Err(ConformanceError::InvalidEmbeddedDisclosurePolicy)
    );
}

#[test]
fn rejects_missing_required_issuance_crypto_suite() {
    let facts = IssuanceFacts {
        a256gcm_supported: false,
        ..valid_issuance()
    };

    assert_eq!(
        validate_issuance(&facts),
        Err(ConformanceError::MissingIssuanceCryptoSuite)
    );
}

#[test]
fn rejects_unknown_issuer_metadata_format_bits() {
    let mut facts = valid_issuance();
    facts.metadata.formats = CredentialFormatSet::new(1 << 7);

    assert_eq!(
        validate_issuance(&facts),
        Err(ConformanceError::InvalidIssuerMetadata)
    );
}

#[test]
fn rejects_unknown_pid_disclosure_bits() {
    let common = common_pid(AttestationFormat::SdJwtVc, EU_PID_SD_JWT_VCT);
    let format = FormatFacts::SdJwt(sd_jwt_pid());
    let pid = NaturalPersonPidFacts {
        optional_disclosable: 1 << 15,
        ..natural_pid(AttestationFormat::SdJwtVc)
    };

    assert_eq!(
        validate_natural_person_pid(&common, &format, &pid),
        Err(ConformanceError::InvalidPidSelectiveDisclosure)
    );
}

#[test]
fn arf_once_only_reuse_requires_a_real_batch_and_reissue_threshold() {
    let mut facts = valid_issuance();
    facts.metadata.reuse_policy = ReusePolicy::ArfAnnexIi {
        details: &[ReuseMethod::OnceOnly],
        batch_size: Some(1),
        reissue_trigger_unused: Some(0),
        reissue_trigger_lifetime_left_seconds: None,
    };

    assert_eq!(
        validate_issuance(&facts),
        Err(ConformanceError::InvalidReusePolicy)
    );
}

#[test]
fn arf_per_relying_party_reuse_requires_unused_reissue_threshold() {
    let mut facts = valid_issuance();
    facts.metadata.reuse_policy = ReusePolicy::ArfAnnexIi {
        details: &[ReuseMethod::LimitedTime, ReuseMethod::PerRelyingParty],
        batch_size: Some(2),
        reissue_trigger_unused: None,
        reissue_trigger_lifetime_left_seconds: Some(86_400),
    };

    assert_eq!(
        validate_issuance(&facts),
        Err(ConformanceError::InvalidReusePolicy)
    );
}

#[test]
fn accepts_actual_arf_per_relying_party_reuse_values() {
    let mut facts = valid_issuance();
    facts.metadata.reuse_policy = ReusePolicy::ArfAnnexIi {
        details: &[ReuseMethod::LimitedTime, ReuseMethod::PerRelyingParty],
        batch_size: Some(10),
        reissue_trigger_unused: Some(2),
        reissue_trigger_lifetime_left_seconds: Some(86_400),
    };
    facts.reuse_decision.selected_method = Some(ReuseMethod::LimitedTime);

    assert_eq!(validate_issuance(&facts), Ok(()));
}

#[test]
fn omitted_reuse_policy_is_unrestricted_and_selects_no_method() {
    let mut facts = valid_issuance();
    facts.reuse_decision.selected_method = Some(ReuseMethod::OnceOnly);

    assert_eq!(
        validate_issuance(&facts),
        Err(ConformanceError::InvalidReusePolicy)
    );
}

#[test]
fn reuse_policy_selects_the_first_wallet_supported_preference() {
    let mut facts = valid_issuance();
    facts.metadata.reuse_policy = ReusePolicy::ArfAnnexIi {
        details: &[ReuseMethod::LimitedTime, ReuseMethod::PerRelyingParty],
        batch_size: Some(10),
        reissue_trigger_unused: Some(2),
        reissue_trigger_lifetime_left_seconds: Some(86_400),
    };
    facts.reuse_decision.supported_methods = ReuseMethodSet::new(ReuseMethodSet::PER_RELYING_PARTY);
    facts.reuse_decision.selected_method = Some(ReuseMethod::PerRelyingParty);

    assert_eq!(validate_issuance(&facts), Ok(()));

    facts.reuse_decision.selected_method = Some(ReuseMethod::LimitedTime);
    assert_eq!(
        validate_issuance(&facts),
        Err(ConformanceError::InvalidReusePolicy)
    );
}

#[test]
fn reuse_policy_rejects_unknown_wallet_capability_bits() {
    let mut facts = valid_issuance();
    facts.reuse_decision.supported_methods = ReuseMethodSet::new(1 << 7);

    assert_eq!(
        validate_issuance(&facts),
        Err(ConformanceError::InvalidReusePolicy)
    );
}

#[test]
fn eu_issuance_requires_registration_certificate() {
    let mut facts = valid_issuance();
    facts.metadata.registration_certificate_present = false;

    assert_eq!(validate_issuance(&facts), Ok(()));
    assert_eq!(
        validate_eu_issuance(&facts),
        Err(ConformanceError::InvalidEuIssuanceProfile)
    );
}

#[test]
fn eu_issuance_excludes_part_3_annex_a_x509_format() {
    let mut facts = valid_issuance();
    facts.metadata.formats = CredentialFormatSet::new(
        CredentialFormatSet::SD_JWT_VC | CredentialFormatSet::X509_ATTRIBUTE_CERTIFICATE,
    );

    assert_eq!(validate_issuance(&facts), Ok(()));
    assert_eq!(
        validate_eu_issuance(&facts),
        Err(ConformanceError::InvalidEuIssuanceProfile)
    );
}

#[test]
fn wallet_operation_gate_blocks_functionality_until_authentication() {
    let mut gate = WalletOperationGate::new();
    assert_eq!(
        gate.authorize(WalletOperation::PresentCredential),
        Err(ConformanceError::WalletUserAuthenticationRequired)
    );
    assert_eq!(gate.authorize(WalletOperation::AuthenticateUser), Ok(()));
    assert_eq!(gate.record_successful_authentication(), Ok(()));
    assert_eq!(gate.authorize(WalletOperation::PresentCredential), Ok(()));
    gate.lock();
    assert_eq!(
        gate.authorize(WalletOperation::ExportData),
        Err(ConformanceError::WalletUserAuthenticationRequired)
    );
}

#[test]
fn validates_complete_wallet_cryptographic_boundary() {
    assert_eq!(
        validate_wallet_cryptographic_capabilities(WalletCryptographicCapabilities {
            wscd_present: true,
            protected_component_channel: true,
            high_assurance_operation_profile: true,
            exclusive_critical_asset_execution: true,
            secure_key_generation: true,
            secure_erasure: true,
            proof_of_possession: true,
            private_key_lifetime_protection: true,
            enisa_agreed_mechanisms_only: true,
        }),
        Ok(())
    );
}

#[test]
fn validates_complete_wallet_format_support() {
    let all_formats = CredentialFormatSet::new(
        CredentialFormatSet::SD_JWT_VC
            | CredentialFormatSet::MSO_MDOC
            | CredentialFormatSet::X509_ATTRIBUTE_CERTIFICATE
            | CredentialFormatSet::JSON_LD_JOSE
            | CredentialFormatSet::JSON_LD_SD_JWT,
    );
    assert_eq!(validate_wallet_format_capabilities(all_formats), Ok(()));

    assert_eq!(
        validate_wallet_format_capabilities(CredentialFormatSet::new(
            CredentialFormatSet::SD_JWT_VC | CredentialFormatSet::MSO_MDOC,
        )),
        Err(ConformanceError::IncompleteWalletCredentialFormatSupport)
    );
}

fn wallet_attestation_revocation() -> WalletAttestationRevocationEvent<'static> {
    WalletAttestationRevocationEvent {
        wallet_provider_identifier: "https://wallet-provider.example",
        revoking_actor_identifier: "https://wallet-provider.example",
        public_policy_uri: "https://wallet-provider.example/revocation-policy",
        public_status_uri: "https://wallet-provider.example/status/wia",
        reason: WalletAttestationRevocationReason::WalletUnitCompromise,
        revoked_at: 1_800_000_000,
        user_notified_at: 1_800_086_400,
        notification_included_reason_and_consequences: true,
        notification_accessibility_requirements_met: true,
        public_status_privacy_preserving: true,
    }
}

#[test]
fn validates_wallet_attestation_revocation_lifecycle() {
    assert_eq!(
        validate_wallet_attestation_revocation(&wallet_attestation_revocation()),
        Ok(())
    );
}

#[test]
fn rejects_late_wallet_attestation_revocation_notification() {
    let event = WalletAttestationRevocationEvent {
        user_notified_at: 1_800_086_401,
        ..wallet_attestation_revocation()
    };
    assert_eq!(
        validate_wallet_attestation_revocation(&event),
        Err(ConformanceError::InvalidWalletAttestationRevocation)
    );
}

#[test]
fn validates_relying_party_specific_pseudonym_allocation() {
    let existing = [RelyingPartyPseudonymBinding {
        relying_party_identifier: "https://rp-one.example",
        pseudonym: b"pairwise-pseudonym-one",
    }];
    let candidate = RelyingPartyPseudonymBinding {
        relying_party_identifier: "https://rp-two.example",
        pseudonym: b"pairwise-pseudonym-two",
    };
    assert_eq!(
        validate_relying_party_pseudonym(&candidate, &existing),
        Ok(())
    );
}

#[test]
fn rejects_pseudonym_reuse_across_relying_parties() {
    let existing = [RelyingPartyPseudonymBinding {
        relying_party_identifier: "https://rp-one.example",
        pseudonym: b"reused-pseudonym",
    }];
    let candidate = RelyingPartyPseudonymBinding {
        relying_party_identifier: "https://rp-two.example",
        pseudonym: b"reused-pseudonym",
    };
    assert_eq!(
        validate_relying_party_pseudonym(&candidate, &existing),
        Err(ConformanceError::InvalidWalletPseudonymAllocation)
    );
}

fn valid_wallet_attestation_profile() -> WalletAttestationProfile<'static> {
    WalletAttestationProfile {
        wallet_instance_attestation_count: 1,
        key_attestation_count: 1,
        wallet_instance_format_valid: true,
        key_attestation_format_valid: true,
        wallet_integrity_verified_at: 1_800_000_000,
        wallet_instance_expires_at: 1_800_003_600,
        wallet_instance_status_expires_at: 1_803_000_000,
        key_storage_status_expires_at: 1_803_000_000,
        now: 1_800_000_100,
        wallet_instance_sent_in_par_and_token_request: true,
        wallet_instance_proof_valid: true,
        wallet_instance_signature_and_trust_valid: true,
        wallet_instance_index_policy: WiaStatusIndexPolicy::FreshUnlinkable {
            current_index: 42,
            prior_indexes: &[1, 2, 3],
        },
        wallet_instance_status_list_size: 10_000,
        wallet_instance_minimum_size_exception_documented: false,
        credential_is_device_bound: true,
        key_attestation_present: true,
        separate_attestation_per_key_store: true,
        attested_key_count: 2,
        issuer_maximum_batch_size: 2,
        public_keys_unique_across_attestations: true,
        key_attestation_single_use: true,
        attested_keys_in_described_store: true,
        key_attestation_proof: Some(KeyAttestationProof::Jwt {
            signed_by_first_attested_key: true,
            nonce_valid: true,
        }),
        device_bound_metadata_supports_both_proof_types: true,
        non_device_bound_metadata_omits_binding_parameters: false,
        key_attestation_signature_and_trust_valid: true,
        pid_key_originates_from_wscd_attestation: true,
        wallet_instance_content_valid: true,
        key_attestation_content_valid: true,
        wscd_assurance_claims_valid: true,
        token_status_lists_used: true,
        top_level_exp_not_used_for_status_maintenance: true,
        status_maintenance_committed_through_exp: true,
        credential_issuer_metadata_fetched: true,
        wallet_instance_status_period: StatusPeriodSelection {
            preferred_remaining_seconds: Some(2_800_000),
            selected_expires_at: 1_803_000_000,
            available_expires_at: &[1_802_700_000, 1_803_000_000, 1_804_000_000],
        },
        key_storage_status_period: StatusPeriodSelection {
            preferred_remaining_seconds: Some(2_800_000),
            selected_expires_at: 1_803_000_000,
            available_expires_at: &[1_802_700_000, 1_803_000_000, 1_804_000_000],
        },
        key_attestation_index_policy: KeyAttestationIndexPolicy::PerKeyAttestation {
            pairwise_unique: true,
            status_list_size: 10_000,
            minimum_size_exception_documented: false,
            per_issuer_reuse: None,
        },
        signing_algorithm: WalletAttestationAlgorithm::Es256,
        verifier_supports_all_required_algorithms: true,
        pid_not_before: 1_800_000_100,
        pid_expires_at: 1_800_100_000,
        maximum_revocation_check_interval_seconds: Some(86_400),
    }
}

#[test]
fn validates_consolidated_wallet_attestation_profile() {
    assert_eq!(
        validate_wallet_attestation_profile(&valid_wallet_attestation_profile()),
        Ok(())
    );
}

#[test]
fn rejects_wia_valid_beyond_twenty_four_hours_from_integrity_check() {
    let facts = WalletAttestationProfile {
        wallet_instance_expires_at: 1_800_086_400,
        ..valid_wallet_attestation_profile()
    };

    assert_eq!(
        validate_wallet_attestation_profile(&facts),
        Err(ConformanceError::InvalidWalletAttestationProfile)
    );
}

#[test]
fn rejects_reused_unlinkable_wia_status_index() {
    let facts = WalletAttestationProfile {
        wallet_instance_index_policy: WiaStatusIndexPolicy::FreshUnlinkable {
            current_index: 2,
            prior_indexes: &[1, 2, 3],
        },
        ..valid_wallet_attestation_profile()
    };

    assert_eq!(
        validate_wallet_attestation_profile(&facts),
        Err(ConformanceError::InvalidWalletAttestationProfile)
    );
}

#[test]
fn rejects_pid_validity_beyond_wallet_attestation_status_maintenance() {
    let facts = WalletAttestationProfile {
        pid_expires_at: 1_803_000_000,
        ..valid_wallet_attestation_profile()
    };

    assert_eq!(
        validate_wallet_attestation_profile(&facts),
        Err(ConformanceError::InvalidWalletAttestationProfile)
    );
}

#[test]
fn rejects_nonminimal_status_period_selection() {
    let facts = WalletAttestationProfile {
        wallet_instance_status_period: StatusPeriodSelection {
            preferred_remaining_seconds: Some(2_800_000),
            selected_expires_at: 1_803_000_000,
            available_expires_at: &[1_802_900_000, 1_803_000_000],
        },
        ..valid_wallet_attestation_profile()
    };

    assert_eq!(
        validate_wallet_attestation_profile(&facts),
        Err(ConformanceError::InvalidWalletAttestationProfile)
    );
}

#[test]
fn rejects_status_period_candidate_set_with_duplicates() {
    let facts = WalletAttestationProfile {
        key_storage_status_period: StatusPeriodSelection {
            preferred_remaining_seconds: None,
            selected_expires_at: 1_803_000_000,
            available_expires_at: &[1_803_000_000, 1_803_000_000],
        },
        ..valid_wallet_attestation_profile()
    };

    assert_eq!(
        validate_wallet_attestation_profile(&facts),
        Err(ConformanceError::InvalidWalletAttestationProfile)
    );
}

#[test]
fn rejects_undisclosed_key_attestation_per_issuer_index_reuse() {
    let facts = WalletAttestationProfile {
        key_attestation_index_policy: KeyAttestationIndexPolicy::PerKeyAttestation {
            pairwise_unique: true,
            status_list_size: 10_000,
            minimum_size_exception_documented: false,
            per_issuer_reuse: Some(PerIssuerIndexReuse {
                authorization_server: "https://authorization.example",
                current_index: 42,
                prior_bindings: &[],
                privacy_policy_discloses_reuse: false,
            }),
        },
        ..valid_wallet_attestation_profile()
    };

    assert_eq!(
        validate_wallet_attestation_profile(&facts),
        Err(ConformanceError::InvalidWalletAttestationProfile)
    );
}

#[test]
fn validates_complete_wallet_transaction_log_entry() {
    let entry = WalletTransactionLogEntry {
        timestamp: 1_800_000_000,
        kind: WalletTransactionKind::RelyingPartyPresentation(WalletRelyingPartyLogData {
            name: "Example Service",
            contact: "privacy@example.eu",
            identifier: "https://rp.example",
            member_state: "DE",
        }),
        requested_types: &["family_name", "birth_date"],
        presented_types: &["birth_date"],
        outcome: TransactionOutcome::Completed,
        portrait_related: false,
    };
    let controls = WalletTransactionLogControls {
        integrity_protected: true,
        authenticity_protected: true,
        confidentiality_protected: true,
        authority_reports_logged: true,
        provider_access_requires_explicit_prior_consent: true,
        legally_bounded_retention: true,
        user_export_supported: true,
    };

    assert_eq!(validate_wallet_transaction_log(&entry, controls), Ok(()));
}

#[test]
fn rejects_failed_transaction_log_with_disclosed_types() {
    let entry = WalletTransactionLogEntry {
        timestamp: 1_800_000_000,
        kind: WalletTransactionKind::RelyingPartyPresentation(WalletRelyingPartyLogData {
            name: "Example Service",
            contact: "privacy@example.eu",
            identifier: "https://rp.example",
            member_state: "DE",
        }),
        requested_types: &["portrait"],
        presented_types: &["portrait"],
        outcome: TransactionOutcome::NotCompleted(TransactionFailureReason::UserDeclined),
        portrait_related: true,
    };
    let controls = WalletTransactionLogControls {
        integrity_protected: true,
        authenticity_protected: true,
        confidentiality_protected: true,
        authority_reports_logged: true,
        provider_access_requires_explicit_prior_consent: true,
        legally_bounded_retention: true,
        user_export_supported: true,
    };

    assert_eq!(
        validate_wallet_transaction_log(&entry, controls),
        Err(ConformanceError::InvalidWalletTransactionLog)
    );
}

#[test]
fn validates_signature_and_wallet_to_wallet_log_entries() {
    let controls = WalletTransactionLogControls {
        integrity_protected: true,
        authenticity_protected: true,
        confidentiality_protected: true,
        authority_reports_logged: true,
        provider_access_requires_explicit_prior_consent: true,
        legally_bounded_retention: true,
        user_export_supported: true,
    };
    let signature = WalletTransactionLogEntry {
        timestamp: 1_800_000_000,
        kind: WalletTransactionKind::ElectronicSignature {
            relying_party: None,
        },
        requested_types: &[],
        presented_types: &[],
        outcome: TransactionOutcome::Completed,
        portrait_related: false,
    };
    let wallet_interaction = WalletTransactionLogEntry {
        timestamp: 1_800_000_001,
        kind: WalletTransactionKind::OtherWalletUnit {
            counterparty_identifier: "pairwise-wallet-counterparty",
        },
        requested_types: &["eu.europa.ec.eudi.pid.1"],
        presented_types: &[],
        outcome: TransactionOutcome::NotCompleted(TransactionFailureReason::UserDeclined),
        portrait_related: false,
    };

    assert_eq!(
        validate_wallet_transaction_log(&signature, controls),
        Ok(())
    );
    assert_eq!(
        validate_wallet_transaction_log(&wallet_interaction, controls),
        Ok(())
    );
}

#[test]
fn embedded_disclosure_policy_matches_actual_relying_party() {
    let policy = WalletDisclosurePolicy::AuthorizedRelyingParties(&[
        "https://rp.example",
        "https://second.example",
    ]);
    assert_eq!(
        evaluate_wallet_disclosure_policy(&policy, "https://rp.example", None),
        Ok(())
    );
    assert_eq!(
        evaluate_wallet_disclosure_policy(&policy, "https://unlisted.example", None),
        Err(ConformanceError::InvalidEmbeddedDisclosurePolicy)
    );
}

#[test]
fn root_policy_matches_actual_access_certificate_anchor() {
    let accepted = [0x11_u8; 32];
    let unaccepted = [0x22_u8; 32];
    let policy = WalletDisclosurePolicy::SpecificRootsOfTrust(&[accepted]);

    assert_eq!(
        evaluate_wallet_disclosure_policy(&policy, "https://rp.example", Some(&accepted)),
        Ok(())
    );
    assert_eq!(
        evaluate_wallet_disclosure_policy(&policy, "https://rp.example", Some(&unaccepted)),
        Err(ConformanceError::InvalidEmbeddedDisclosurePolicy)
    );
}
