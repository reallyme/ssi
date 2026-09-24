// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Package-owned recursive cleanup for generated EUDI PID messages.

use crate::generated::proto::identity::eudi::v1 as pb;
use zeroize::Zeroize;

/// Clears a natural-person PID graph, including biometric and contact data.
pub fn zeroize_eudi_natural_person_pid(value: &mut pb::EudiNaturalPersonPidFacts) {
    if let Some(common) = value.common.as_option_mut() {
        zeroize_common_attestation(common);
    }
    value.common = Default::default();
    if let Some(claims) = value.claims.as_option_mut() {
        zeroize_natural_person_claims(claims);
    }
    value.claims = Default::default();
    if let Some(provider) = value.provider_metadata.as_option_mut() {
        zeroize_provider_metadata(provider);
    }
    value.provider_metadata = Default::default();
    if let Some(mut format) = value.format_facts.take() {
        match &mut format {
            pb::__buffa::oneof::eudi_natural_person_pid_facts::FormatFacts::SdJwt(facts) => {
                zeroize_sd_jwt_facts(facts);
            }
            pb::__buffa::oneof::eudi_natural_person_pid_facts::FormatFacts::Mdoc(facts) => {
                zeroize_mdoc_facts(facts);
            }
        }
    }
    value.mandatory_disclosable.zeroize();
    value.optional_disclosable.zeroize();
    value.portrait_opt_out_authorized = false;
    value.__buffa_unknown_fields.clear();
}

/// Clears a legal-person PID graph and its registration identifiers.
pub fn zeroize_eudi_legal_person_pid(value: &mut pb::EudiLegalPersonPidFacts) {
    value.current_legal_name.zeroize();
    value.cross_border_identifier.zeroize();
    value.current_address.zeroize();
    value.vat_registration_number.zeroize();
    value.tax_reference_number.zeroize();
    value.european_unique_identifier.zeroize();
    value.legal_entity_identifier.zeroize();
    value.eori.zeroize();
    value.excise_number.zeroize();
    if let Some(provider) = value.provider_metadata.as_option_mut() {
        zeroize_provider_metadata(provider);
    }
    value.provider_metadata = Default::default();
    value.__buffa_unknown_fields.clear();
}

/// Clears PID issuance-authorization identifiers and decision facts.
pub fn zeroize_eudi_pid_issuance_authorization(value: &mut pb::EudiPidIssuanceAuthorizationFacts) {
    value.provider_identifier.zeroize();
    value.credential_issuer_identifier.zeroize();
    value.provider_authentication = Default::default();
    value.electronic_identification_scheme_authorized = false;
    value.high_assurance_enrollment_complete = false;
    value.identity_proofing_complete = false;
    value.wallet_unit_attestation_valid = false;
    value.wallet_solution_accepted = false;
    value.authentication_data_complete = false;
    value.cryptographically_bound_to_authenticated_wallet = false;
    value.__buffa_unknown_fields.clear();
}

/// Clears PID allocation candidates and existing subject identifiers.
pub fn zeroize_eudi_pid_allocation(value: &mut pb::EudiPidAllocationFacts) {
    if let Some(candidate) = value.candidate.as_option_mut() {
        zeroize_allocation_key(candidate);
    }
    value.candidate = Default::default();
    for key in &mut value.existing {
        zeroize_allocation_key(key);
    }
    value.existing.clear();
    value.__buffa_unknown_fields.clear();
}

/// Clears PID revocation actors, issuer identity, and timestamps.
pub fn zeroize_eudi_pid_revocation(value: &mut pb::EudiPidRevocationFacts) {
    value.issuer_identifier.zeroize();
    value.revoking_actor_identifier.zeroize();
    value.public_policy_uri.zeroize();
    value.public_status_uri.zeroize();
    value.reason = Default::default();
    value.revoked_at.zeroize();
    value.user_notified_at.zeroize();
    value.secure_notification_included_reason = false;
    value.public_status_privacy_preserving = false;
    value.irreversible = false;
    value.unlinkability_enabled_when_identity_not_required = false;
    value.__buffa_unknown_fields.clear();
}

/// Clears a canonical EUDI catalogue JSON document.
pub fn zeroize_eudi_catalogue_document(value: &mut pb::EudiCatalogueDocument) {
    value.kind = Default::default();
    value.json.zeroize();
    value.__buffa_unknown_fields.clear();
}

fn zeroize_provider_metadata(value: &mut pb::EudiPidProviderMetadata) {
    value.issuing_authority.zeroize();
    value.issuing_country.zeroize();
    value.expiry_date = Default::default();
    value.document_number.zeroize();
    value.issuing_jurisdiction.zeroize();
    value.issuance_date = Default::default();
    value.__buffa_unknown_fields.clear();
}

fn zeroize_common_attestation(value: &mut pb::EudiPidCommonAttestationFacts) {
    value.format = Default::default();
    value.type_identifier.zeroize();
    value.issuer_identifier.zeroize();
    value.issuer_country.zeroize();
    value.issuer_name.zeroize();
    value.technical_not_before.zeroize();
    value.technical_not_after.zeroize();
    value.administrative_validity = Default::default();
    if let Some(profile) = value.profile.as_option_mut() {
        zeroize_common_profile(profile);
    }
    value.profile = Default::default();
    value.selective_disclosure = Default::default();
    value.attribute_identifiers_complete = false;
    value.attribute_values_complete = false;
    value.attribute_subjects_complete = false;
    value.holder_public_key_bound = false;
    value.issuer_signature_advanced = false;
    value.status_present = false;
    value.status_privacy_preserving = false;
    value.status_binary_only = false;
    value.status_irreversible = false;
    value.__buffa_unknown_fields.clear();
}

fn zeroize_common_profile(value: &mut pb::EudiPidCommonProfileFacts) {
    value.components_use_uri_names = false;
    value.context_uris.zeroize();
    value.schema_uris.zeroize();
    value.attestation_identifier_uri.zeroize();
    value.issued_at.zeroize();
    value.audiences.zeroize();
    value.one_time_use = false;
    value.terms_of_use_uris.zeroize();
    for evidence in &mut value.attribute_evidence {
        evidence.evidence_type_uri.zeroize();
        evidence.source_uri.zeroize();
        evidence.sha256.zeroize();
        evidence.__buffa_unknown_fields.clear();
    }
    value.attribute_evidence.clear();
    if let Some(renewal) = value.renewal_service.as_option_mut() {
        renewal.endpoint.zeroize();
        renewal.available_until.zeroize();
        renewal.__buffa_unknown_fields.clear();
    }
    value.renewal_service = Default::default();
    value.__buffa_unknown_fields.clear();
}

fn zeroize_sd_jwt_facts(value: &mut pb::EudiPidSdJwtFacts) {
    value.vct.zeroize();
    *value = Default::default();
}

fn zeroize_mdoc_facts(value: &mut pb::EudiPidMdocFacts) {
    value.doc_type.zeroize();
    value.namespace.zeroize();
    *value = Default::default();
}

fn zeroize_natural_person_claims(value: &mut pb::EudiNaturalPersonPidClaims) {
    value.family_name.zeroize();
    value.given_name.zeroize();
    value.birth_date = Default::default();
    if let Some(place) = value.birth_place.as_option_mut() {
        place.country.zeroize();
        place.region.zeroize();
        place.locality.zeroize();
        place.__buffa_unknown_fields.clear();
    }
    value.birth_place = Default::default();
    value.nationalities.zeroize();
    if let Some(portrait) = value.portrait.as_option_mut() {
        portrait.quality = Default::default();
        if let Some(mut portrait_value) = portrait.value.take() {
            match &mut portrait_value {
                pb::__buffa::oneof::eudi_pid_portrait::Value::MdocJpeg(bytes) => bytes.zeroize(),
                pb::__buffa::oneof::eudi_pid_portrait::Value::SdJwtJpegDataUrl(text) => {
                    text.zeroize();
                }
                pb::__buffa::oneof::eudi_pid_portrait::Value::OptedOutEmpty(value) => {
                    *value = false;
                }
            }
        }
        portrait.__buffa_unknown_fields.clear();
    }
    value.portrait = Default::default();
    value.assessment_date = Default::default();
    value.resident_address.zeroize();
    value.resident_country.zeroize();
    value.resident_state.zeroize();
    value.resident_city.zeroize();
    value.resident_postal_code.zeroize();
    value.resident_street.zeroize();
    value.personal_administrative_number.zeroize();
    value.family_name_birth.zeroize();
    value.given_name_birth.zeroize();
    value.sex = None;
    value.email.zeroize();
    value.mobile_phone_number.zeroize();
    value.__buffa_unknown_fields.clear();
}

fn zeroize_allocation_key(value: &mut pb::EudiPidAllocationKey) {
    value.member_state.zeroize();
    value.subject_reference.zeroize();
    value.pid_identifier.zeroize();
    value.__buffa_unknown_fields.clear();
}

#[cfg(test)]
#[path = "zeroize_eudi_pid_tests.rs"]
mod tests;
