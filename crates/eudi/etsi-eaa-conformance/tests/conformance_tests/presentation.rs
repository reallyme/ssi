// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    authorize_eu_presentation, validate_eu_mediating_api, validate_mdoc_presentation,
    validate_openid4vp_presentation, validate_openid4vp_presentation_for_profile,
    validate_sd_jwt_presentation, ConformanceError, EtsiPart2Profile, EuMediatingApiFacts,
    FailedRegistrationPolicy, MdocPresentationFacts, OpenId4VpPresentationFacts, OveraskingPolicy,
    PresentationUserDecision, RegisteredClaim, RelyingPartyRegistrationStatus,
    SdJwtPresentationFacts, SdJwtSerialization, EU_PID_SD_JWT_VCT,
};

#[test]
fn accepts_complete_sd_jwt_presentation_profile() {
    let facts = SdJwtPresentationFacts {
        credential_has_confirmation: true,
        key_binding_jwt_present: true,
        key_binding_signed_by_subject: true,
        serialization: SdJwtSerialization::Compact,
    };

    assert_eq!(validate_sd_jwt_presentation(&facts), Ok(()));
}

#[test]
fn rejects_sd_jwt_presentation_with_unverified_key_binding() {
    let facts = SdJwtPresentationFacts {
        credential_has_confirmation: true,
        key_binding_jwt_present: true,
        key_binding_signed_by_subject: false,
        serialization: SdJwtSerialization::Compact,
    };

    assert_eq!(
        validate_sd_jwt_presentation(&facts),
        Err(ConformanceError::InvalidSdJwtPresentation)
    );
}

#[test]
fn accepts_complete_mdoc_presentation_profile() {
    let facts = MdocPresentationFacts {
        server_retrieval_disabled: true,
        reader_auth_on_every_request: true,
        reader_auth_signed_by_access_key: true,
        access_certificate_chain_valid: true,
        request_info_present: true,
        registrar_information_valid: true,
        registration_certificate_condition_met: true,
        device_response_valid: true,
        issuer_signed_response_complete: true,
        key_authorizations_restricted_to_transaction_data: true,
        pid_device_key_transaction_signing_disabled: true,
    };

    assert_eq!(validate_mdoc_presentation(&facts), Ok(()));
}

#[test]
fn api_mediated_presentation_requires_privacy_controls() {
    let facts = OpenId4VpPresentationFacts {
        non_api_profile_supported: true,
        x509_hash_client_identifier: true,
        verifier_registrar_information_valid: true,
        registration_certificate_condition_met: true,
        encryption_jwks_valid: true,
        audience_valid: true,
        request_object_signature_valid: true,
        authorization_response_encrypted: true,
        eu_eaap_scheme_supported: true,
        request_by_reference: true,
        protected_request_headers_valid: true,
        api_mediated_supported: true,
        unsigned_exchange_protocol_disabled: true,
        api_discovery_minimized: true,
        api_lifecycle_notifications: true,
        api_global_opt_out: false,
    };

    assert_eq!(
        validate_openid4vp_presentation(&facts),
        Err(ConformanceError::InvalidOpenId4VpPresentation)
    );
}

#[test]
fn api_mediated_presentation_rejects_unsigned_exchange_protocol() {
    let facts = OpenId4VpPresentationFacts {
        api_mediated_supported: true,
        unsigned_exchange_protocol_disabled: false,
        api_discovery_minimized: true,
        api_lifecycle_notifications: true,
        api_global_opt_out: true,
        ..valid_openid4vp_presentation()
    };

    assert_eq!(
        validate_openid4vp_presentation(&facts),
        Err(ConformanceError::InvalidOpenId4VpPresentation)
    );
}

fn valid_openid4vp_presentation() -> OpenId4VpPresentationFacts {
    OpenId4VpPresentationFacts {
        non_api_profile_supported: true,
        x509_hash_client_identifier: true,
        verifier_registrar_information_valid: true,
        registration_certificate_condition_met: true,
        encryption_jwks_valid: true,
        audience_valid: true,
        request_object_signature_valid: true,
        authorization_response_encrypted: true,
        eu_eaap_scheme_supported: true,
        request_by_reference: true,
        protected_request_headers_valid: true,
        api_mediated_supported: false,
        unsigned_exchange_protocol_disabled: true,
        api_discovery_minimized: false,
        api_lifecycle_notifications: false,
        api_global_opt_out: false,
    }
}

#[test]
fn eu_legal_part_2_profile_requires_cross_device_api_mediation() {
    let facts = valid_openid4vp_presentation();

    assert_eq!(validate_openid4vp_presentation(&facts), Ok(()));
    assert_eq!(
        validate_openid4vp_presentation_for_profile(
            EtsiPart2Profile::EuLegallyIncorporatedV1_2_1,
            &facts,
        ),
        Err(ConformanceError::InvalidOpenId4VpPresentation)
    );
}

#[test]
fn eu_legal_part_2_profile_accepts_privacy_controlled_api_mediation() {
    let facts = OpenId4VpPresentationFacts {
        api_mediated_supported: true,
        api_discovery_minimized: true,
        api_lifecycle_notifications: true,
        api_global_opt_out: true,
        ..valid_openid4vp_presentation()
    };

    assert_eq!(
        validate_openid4vp_presentation_for_profile(
            EtsiPart2Profile::EuLegallyIncorporatedV1_2_1,
            &facts,
        ),
        Ok(())
    );
}

#[test]
fn validates_complete_eu_mediating_api_capabilities() {
    let facts = EuMediatingApiFacts {
        both_protocols_supported: true,
        registered_scheme_types_supported: true,
        all_annex_formats_supported: true,
        mdoc_api_profile_supported: true,
        type_discovery_minimized: true,
        lifecycle_notifications_supported: true,
        global_api_disable_supported: true,
        cross_device_proximity_verified: true,
        haip_mdoc_profile_supported: true,
        haip_sd_jwt_profile_supported: true,
    };

    assert_eq!(validate_eu_mediating_api(&facts), Ok(()));
}

#[test]
fn rejects_eu_api_profile_without_cross_device_proximity() {
    let facts = EuMediatingApiFacts {
        both_protocols_supported: true,
        registered_scheme_types_supported: true,
        all_annex_formats_supported: true,
        mdoc_api_profile_supported: true,
        type_discovery_minimized: true,
        lifecycle_notifications_supported: true,
        global_api_disable_supported: true,
        cross_device_proximity_verified: false,
        haip_mdoc_profile_supported: true,
        haip_sd_jwt_profile_supported: true,
    };

    assert_eq!(
        validate_eu_mediating_api(&facts),
        Err(ConformanceError::InvalidEuMediatingApiProfile)
    );
}

#[test]
fn presentation_authorization_rejects_silent_or_preticked_approval() {
    let claims = [RegisteredClaim {
        credential_type: EU_PID_SD_JWT_VCT,
        attribute: "family_name",
    }];

    assert!(matches!(
        authorize_eu_presentation(
            &claims,
            &claims,
            RelyingPartyRegistrationStatus::Valid,
            FailedRegistrationPolicy::Reject,
            OveraskingPolicy::Reject,
            PresentationUserDecision::NotCollected,
        ),
        Err(ConformanceError::ExplicitPresentationApprovalRequired)
    ));
}

#[test]
fn presentation_authorization_enforces_registration_warning() {
    let claims = [RegisteredClaim {
        credential_type: EU_PID_SD_JWT_VCT,
        attribute: "family_name",
    }];

    assert!(matches!(
        authorize_eu_presentation(
            &claims,
            &claims,
            RelyingPartyRegistrationStatus::InvalidSignature,
            FailedRegistrationPolicy::AllowAfterExplicitWarning,
            OveraskingPolicy::AllowAfterExplicitWarning,
            PresentationUserDecision::ApprovedAfterRegistrationWarning,
        ),
        Err(ConformanceError::ExplicitPresentationApprovalRequired)
    ));
    assert!(authorize_eu_presentation(
        &claims,
        &claims,
        RelyingPartyRegistrationStatus::InvalidSignature,
        FailedRegistrationPolicy::AllowAfterExplicitWarning,
        OveraskingPolicy::AllowAfterExplicitWarning,
        PresentationUserDecision::ApprovedAfterBothWarnings,
    )
    .is_ok());
}

#[test]
fn presentation_authorization_ignores_untrusted_registered_claims() {
    let claims = [RegisteredClaim {
        credential_type: EU_PID_SD_JWT_VCT,
        attribute: "family_name",
    }];

    for status in [
        RelyingPartyRegistrationStatus::Malformed,
        RelyingPartyRegistrationStatus::InvalidSignature,
    ] {
        assert!(matches!(
            authorize_eu_presentation(
                &claims,
                &claims,
                status,
                FailedRegistrationPolicy::AllowAfterExplicitWarning,
                OveraskingPolicy::Reject,
                PresentationUserDecision::ApprovedAfterRegistrationWarning,
            ),
            Err(ConformanceError::RelyingPartyOverasking)
        ));
        assert!(matches!(
            authorize_eu_presentation(
                &claims,
                &claims,
                status,
                FailedRegistrationPolicy::AllowAfterExplicitWarning,
                OveraskingPolicy::RegisteredSubsetOnly,
                PresentationUserDecision::ApprovedAfterBothWarnings,
            ),
            Err(ConformanceError::RelyingPartyOverasking)
        ));
    }
}

#[test]
fn presentation_authorization_accepts_empty_registered_set_under_warning() {
    let claims = [RegisteredClaim {
        credential_type: EU_PID_SD_JWT_VCT,
        attribute: "family_name",
    }];

    let authorization = authorize_eu_presentation(
        &claims,
        &[],
        RelyingPartyRegistrationStatus::Malformed,
        FailedRegistrationPolicy::AllowAfterExplicitWarning,
        OveraskingPolicy::AllowAfterExplicitWarning,
        PresentationUserDecision::ApprovedAfterBothWarnings,
    );
    assert!(authorization.is_ok());
    let Ok(authorization) = authorization else {
        return;
    };
    assert!(authorization.allows(claims[0]));

    assert!(matches!(
        authorize_eu_presentation(
            &claims,
            &[],
            RelyingPartyRegistrationStatus::Valid,
            FailedRegistrationPolicy::AllowAfterExplicitWarning,
            OveraskingPolicy::AllowAfterExplicitWarning,
            PresentationUserDecision::ApprovedAfterOveraskingWarning,
        ),
        Err(ConformanceError::RelyingPartyOverasking)
    ));
}

#[test]
fn presentation_authorization_limits_overasking_to_registered_subset() {
    let requested = [
        RegisteredClaim {
            credential_type: EU_PID_SD_JWT_VCT,
            attribute: "family_name",
        },
        RegisteredClaim {
            credential_type: EU_PID_SD_JWT_VCT,
            attribute: "portrait",
        },
    ];
    let registered = [requested[0]];
    let authorization = authorize_eu_presentation(
        &requested,
        &registered,
        RelyingPartyRegistrationStatus::Valid,
        FailedRegistrationPolicy::Reject,
        OveraskingPolicy::RegisteredSubsetOnly,
        PresentationUserDecision::ApprovedAfterOveraskingWarning,
    );
    assert!(authorization.is_ok());
    let Ok(authorization) = authorization else {
        return;
    };
    assert!(authorization.allows(requested[0]));
    assert!(!authorization.allows(requested[1]));
}
