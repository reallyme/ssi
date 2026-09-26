// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ConformanceError, Result};

/// ETSI TS 119 472-2 edition selected for presentation validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EtsiPart2Profile {
    /// Edition incorporated by the 2026 EU implementing-rule amendments.
    EuLegallyIncorporatedV1_2_1,
    /// Current ETSI edition, where `OIDFVP-HAIP-SUPPORT-03` is void.
    LatestV1_3_1,
}

/// Allowed SD-JWT VC presentation serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdJwtSerialization {
    /// RFC 9901 compact serialization.
    Compact,
    /// RFC 9901 flattened JSON serialization.
    FlattenedJson,
}

/// Facts required by ETSI TS 119 472-2 clause 4.1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdJwtPresentationFacts {
    /// Whether the source credential contains `cnf`.
    pub credential_has_confirmation: bool,
    /// Whether the presentation contains a KB-JWT.
    pub key_binding_jwt_present: bool,
    /// Whether the KB-JWT signature was verified under the attestation subject's key.
    pub key_binding_signed_by_subject: bool,
    /// Selected RFC 9901 serialization.
    pub serialization: SdJwtSerialization,
}

/// Facts required by the ISO/IEC mdoc presentation profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MdocPresentationFacts {
    /// Server retrieval is disabled for PID/EAA presentation.
    pub server_retrieval_disabled: bool,
    /// Every document request contains `readerAuth`.
    pub reader_auth_on_every_request: bool,
    /// Each reader authentication was signed by the RP access-certificate key.
    pub reader_auth_signed_by_access_key: bool,
    /// `x5chain` starts with the RP access certificate and omits the trust anchor.
    pub access_certificate_chain_valid: bool,
    /// Every request contains the required non-empty request information.
    pub request_info_present: bool,
    /// Registrar data is present and structurally valid.
    pub registrar_information_valid: bool,
    /// The RP registration certificate is included when the RP has one.
    pub registration_certificate_condition_met: bool,
    /// The response is an ISO/IEC 18013-5 `DeviceResponse`.
    pub device_response_valid: bool,
    /// Each document carries all requested issuer-signed attributes that may be disclosed.
    pub issuer_signed_response_complete: bool,
    /// Key authorizations contain only relying-party transactional data.
    pub key_authorizations_restricted_to_transaction_data: bool,
    /// A PID device key cannot sign relying-party transactional data.
    pub pid_device_key_transaction_signing_disabled: bool,
}

/// Facts required by the OpenID4VC-HAIP presentation profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenId4VpPresentationFacts {
    /// The mandatory non-API-mediated profile is supported.
    pub non_api_profile_supported: bool,
    /// The Authorization Request uses `x509_hash` client identification.
    pub x509_hash_client_identifier: bool,
    /// `verifier_info` contains valid registrar-provided data.
    pub verifier_registrar_information_valid: bool,
    /// An RP registration certificate is included when one exists.
    pub registration_certificate_condition_met: bool,
    /// Client metadata contains an encryption JWK set with unambiguous key IDs.
    pub encryption_jwks_valid: bool,
    /// The Request Object has the correct wallet audience.
    pub audience_valid: bool,
    /// The Request Object signature verifies under the RP access-certificate key.
    pub request_object_signature_valid: bool,
    /// The authorization response is encrypted.
    pub authorization_response_encrypted: bool,
    /// Redirect presentation supports the `eu-eaap` custom URL scheme.
    pub eu_eaap_scheme_supported: bool,
    /// Redirect requests carry `request_uri` and do not inline a Request Object.
    pub request_by_reference: bool,
    /// The Request Object protected header has the required type and access-certificate chain.
    pub protected_request_headers_valid: bool,
    /// Whether the optional API-mediated profile is supported.
    pub api_mediated_supported: bool,
    /// The unsigned `openid4vp-1-unsigned` exchange protocol is disabled.
    pub unsigned_exchange_protocol_disabled: bool,
    /// API mediation exposes credential types but never undisclosed attributes or values.
    pub api_discovery_minimized: bool,
    /// Deletion/uninstallation notifications to the mediating API are implemented.
    pub api_lifecycle_notifications: bool,
    /// A global user setting can disable API-mediated discovery and requests.
    pub api_global_opt_out: bool,
}

/// EU capabilities added by the 2026 Part 2 adaptations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EuMediatingApiFacts {
    /// The mediating API supports both OpenID4VP and ISO/IEC 18013-7 Annex C.
    pub both_protocols_supported: bool,
    /// Every PID/EAA type registered in the scheme catalogue is supported.
    pub registered_scheme_types_supported: bool,
    /// Every credential format required by the 2024/2979 Annex is supported.
    pub all_annex_formats_supported: bool,
    /// ISO/IEC 18013-7 Annex C mandatory and profiled requirements are supported.
    pub mdoc_api_profile_supported: bool,
    /// Type discovery exposes no undisclosed attribute identifiers or values.
    pub type_discovery_minimized: bool,
    /// Deletion and wallet-uninstallation notifications are implemented.
    pub lifecycle_notifications_supported: bool,
    /// A global setting disables API discovery and API presentation/issuance requests.
    pub global_api_disable_supported: bool,
    /// Cross-device API flows verify close physical proximity over a secure local channel.
    pub cross_device_proximity_verified: bool,
    /// HAIP's ISO mdoc format profile is supported.
    pub haip_mdoc_profile_supported: bool,
    /// HAIP's IETF SD-JWT VC format profile is supported.
    pub haip_sd_jwt_profile_supported: bool,
}

/// A credential type and attribute requested or registered for a relying party.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RegisteredClaim<'a> {
    /// PID/EAA type identifier.
    pub credential_type: &'a str,
    /// Attribute or claim identifier.
    pub attribute: &'a str,
}

/// Result of validating a wallet-relying party registration certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelyingPartyRegistrationStatus {
    /// Certificate, path, time, revocation, and signature checks all succeeded.
    Valid,
    /// The certificate is expired or not yet valid.
    InvalidTime,
    /// The certificate is revoked.
    Revoked,
    /// The certificate does not chain to a trusted registration-certificate provider.
    UntrustedProvider,
    /// The certificate encoding or registered claim set is malformed.
    Malformed,
    /// The certificate signature or seal did not verify.
    InvalidSignature,
}

/// Provider policy for a failed registration-certificate validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailedRegistrationPolicy {
    /// Reject the request.
    Reject,
    /// Permit continuation only after a validation-specific warning and approval.
    AllowAfterExplicitWarning,
}

/// Provider policy for a request that exceeds the registration certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OveraskingPolicy {
    /// Reject the request.
    Reject,
    /// Authorize only requested claims covered by the registration certificate.
    RegisteredSubsetOnly,
    /// Permit the entire request only after an overasking-specific warning and approval.
    AllowAfterExplicitWarning,
}

/// Explicit user response collected for a presentation transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresentationUserDecision {
    /// No affirmative user action was collected.
    NotCollected,
    /// The user rejected the request.
    Rejected,
    /// The user approved a valid request that required no warning.
    Approved,
    /// The user approved after the registration-validation warning.
    ApprovedAfterRegistrationWarning,
    /// The user approved after the overasking warning.
    ApprovedAfterOveraskingWarning,
    /// The user approved after both warnings.
    ApprovedAfterBothWarnings,
}

/// Authorized disclosure scope returned by the transaction policy engine.
pub struct PresentationAuthorization<'a> {
    requested: &'a [RegisteredClaim<'a>],
    registered: &'a [RegisteredClaim<'a>],
    registered_subset_only: bool,
}

impl PresentationAuthorization<'_> {
    /// Return whether a requested claim may be disclosed by this authorization.
    #[must_use]
    pub fn allows(&self, claim: RegisteredClaim<'_>) -> bool {
        self.requested.contains(&claim)
            && (!self.registered_subset_only || self.registered.contains(&claim))
    }
}

/// Validate an SD-JWT VC EAA presentation.
pub fn validate_sd_jwt_presentation(facts: &SdJwtPresentationFacts) -> Result<()> {
    let binding_valid = if facts.credential_has_confirmation {
        facts.key_binding_jwt_present && facts.key_binding_signed_by_subject
    } else {
        !facts.key_binding_jwt_present || facts.key_binding_signed_by_subject
    };

    if binding_valid {
        Ok(())
    } else {
        Err(ConformanceError::InvalidSdJwtPresentation)
    }
}

/// Validate an ISO/IEC mdoc EAA/PID request-response exchange.
pub fn validate_mdoc_presentation(facts: &MdocPresentationFacts) -> Result<()> {
    if facts.server_retrieval_disabled
        && facts.reader_auth_on_every_request
        && facts.reader_auth_signed_by_access_key
        && facts.access_certificate_chain_valid
        && facts.request_info_present
        && facts.registrar_information_valid
        && facts.registration_certificate_condition_met
        && facts.device_response_valid
        && facts.issuer_signed_response_complete
        && facts.key_authorizations_restricted_to_transaction_data
        && facts.pid_device_key_transaction_signing_disabled
    {
        Ok(())
    } else {
        Err(ConformanceError::InvalidMdocPresentation)
    }
}

/// Validate the mandatory HAIP presentation profile and optional API-mediated lane.
pub fn validate_openid4vp_presentation(facts: &OpenId4VpPresentationFacts) -> Result<()> {
    validate_openid4vp_presentation_for_profile(EtsiPart2Profile::LatestV1_3_1, facts)
}

/// Validate OpenID4VP against an explicit ETSI edition.
///
/// EU law incorporates V1.2.1 and requires the wallet and relying party to
/// support the API-mediated profile. Its `OIDFVP-HAIP-SUPPORT-03` only says
/// redirects should not be used for cross-device flows, and the accompanying
/// note explicitly says redirect support must not trigger non-conformity.
/// V1.3.1 later made that recommendation void.
pub fn validate_openid4vp_presentation_for_profile(
    profile: EtsiPart2Profile,
    facts: &OpenId4VpPresentationFacts,
) -> Result<()> {
    let common_valid = facts.non_api_profile_supported
        && facts.x509_hash_client_identifier
        && facts.verifier_registrar_information_valid
        && facts.registration_certificate_condition_met
        && facts.encryption_jwks_valid
        && facts.audience_valid
        && facts.request_object_signature_valid
        && facts.authorization_response_encrypted
        && facts.eu_eaap_scheme_supported
        && facts.request_by_reference
        && facts.protected_request_headers_valid;

    let api_valid = !facts.api_mediated_supported
        || (facts.unsigned_exchange_protocol_disabled
            && facts.api_discovery_minimized
            && facts.api_lifecycle_notifications
            && facts.api_global_opt_out);

    let edition_valid = match profile {
        EtsiPart2Profile::EuLegallyIncorporatedV1_2_1 => facts.api_mediated_supported,
        EtsiPart2Profile::LatestV1_3_1 => true,
    };

    if common_valid && api_valid && edition_valid {
        Ok(())
    } else {
        Err(ConformanceError::InvalidOpenId4VpPresentation)
    }
}

/// Validate capabilities mandated by the amended EU legal Part 2 profile.
pub fn validate_eu_mediating_api(facts: &EuMediatingApiFacts) -> Result<()> {
    if facts.both_protocols_supported
        && facts.registered_scheme_types_supported
        && facts.all_annex_formats_supported
        && facts.mdoc_api_profile_supported
        && facts.type_discovery_minimized
        && facts.lifecycle_notifications_supported
        && facts.global_api_disable_supported
        && facts.cross_device_proximity_verified
        && facts.haip_mdoc_profile_supported
        && facts.haip_sd_jwt_profile_supported
    {
        Ok(())
    } else {
        Err(ConformanceError::InvalidEuMediatingApiProfile)
    }
}

/// Authorize one presentation after registration and overasking checks.
///
/// The function compares the actual requested and registered type/attribute
/// pairs, rejects duplicate or malformed identifiers, and requires the user
/// response to match the exact warning combination produced by the checks.
///
/// The registered claim set is only trusted when the registration certificate
/// validated. For any other status the set may be absent, malformed, or
/// attacker-controlled, so it is ignored and treated as empty: every requested
/// claim then counts as overasking.
pub fn authorize_eu_presentation<'a>(
    requested: &'a [RegisteredClaim<'a>],
    registered: &'a [RegisteredClaim<'a>],
    registration_status: RelyingPartyRegistrationStatus,
    failed_registration_policy: FailedRegistrationPolicy,
    overasking_policy: OveraskingPolicy,
    user_decision: PresentationUserDecision,
) -> Result<PresentationAuthorization<'a>> {
    validate_claim_set(requested)?;

    let registration_warning =
        !matches!(registration_status, RelyingPartyRegistrationStatus::Valid);
    if registration_warning
        && matches!(failed_registration_policy, FailedRegistrationPolicy::Reject)
    {
        return Err(ConformanceError::InvalidRelyingPartyRegistration);
    }

    let registered: &'a [RegisteredClaim<'a>] = if registration_warning {
        &[]
    } else {
        validate_claim_set(registered)?;
        registered
    };

    let overasking = requested.iter().any(|claim| !registered.contains(claim));
    if overasking
        && (matches!(overasking_policy, OveraskingPolicy::Reject)
            || (registered.is_empty()
                && matches!(overasking_policy, OveraskingPolicy::RegisteredSubsetOnly)))
    {
        return Err(ConformanceError::RelyingPartyOverasking);
    }

    let required_decision = match (registration_warning, overasking) {
        (false, false) => PresentationUserDecision::Approved,
        (true, false) => PresentationUserDecision::ApprovedAfterRegistrationWarning,
        (false, true) => PresentationUserDecision::ApprovedAfterOveraskingWarning,
        (true, true) => PresentationUserDecision::ApprovedAfterBothWarnings,
    };
    if user_decision != required_decision {
        return Err(ConformanceError::ExplicitPresentationApprovalRequired);
    }

    Ok(PresentationAuthorization {
        requested,
        registered,
        registered_subset_only: overasking
            && matches!(overasking_policy, OveraskingPolicy::RegisteredSubsetOnly),
    })
}

fn validate_claim_set(claims: &[RegisteredClaim<'_>]) -> Result<()> {
    const MAX_CLAIMS: usize = 256;
    const MAX_IDENTIFIER_BYTES: usize = 256;

    if claims.is_empty() || claims.len() > MAX_CLAIMS {
        return Err(ConformanceError::RelyingPartyOverasking);
    }
    for (index, claim) in claims.iter().enumerate() {
        let identifiers_valid = [claim.credential_type, claim.attribute]
            .into_iter()
            .all(|value| {
                !value.is_empty()
                    && value.len() <= MAX_IDENTIFIER_BYTES
                    && value.trim() == value
                    && !value.chars().any(char::is_control)
            });
        if !identifiers_valid || claims[..index].contains(claim) {
            return Err(ConformanceError::RelyingPartyOverasking);
        }
    }
    Ok(())
}
