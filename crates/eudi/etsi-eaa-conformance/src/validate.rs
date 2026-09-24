// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    AttestationCategory, AttestationCategorySignal, AttestationFormat, AttestationIdentifier,
    CommonAttestationFacts, ConformanceError, FormatFacts, IssuerSignature, Result, StatusFacts,
    SubjectBinding, PUBLIC_BODY_EAA_CATEGORY_URN, QEAA_CATEGORY_URN,
};
use url::Url;

const MAX_SHORT_LIVED_SECONDS: u64 = 24 * 60 * 60;
const MAX_URI_BYTES: usize = 2_048;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_OPAQUE_IDENTIFIER_BYTES: usize = 128;
const MAX_PROFILE_ITEMS: usize = 32;

/// Validate common and format-specific ETSI TS 119 472-1 invariants.
pub fn validate_attestation(
    common: &CommonAttestationFacts<'_>,
    format: &FormatFacts<'_>,
) -> Result<()> {
    validate_common(common)?;
    validate_format_pair(common.format, format)?;

    match format {
        FormatFacts::SdJwt(facts) => validate_sd_jwt(common, facts),
        FormatFacts::Mdoc(facts) => validate_mdoc(common, facts),
        FormatFacts::JsonLd(facts) => validate_json_ld(common, facts),
        FormatFacts::X509AttributeCertificate(facts) => validate_x509_attribute_certificate(facts),
    }
}

fn validate_common(common: &CommonAttestationFacts<'_>) -> Result<()> {
    validate_identifier(
        common.type_identifier,
        ConformanceError::InvalidAttestationType,
    )?;

    if common.validity.technical_not_after <= common.validity.technical_not_before {
        return Err(ConformanceError::InvalidTechnicalValidity);
    }
    if common
        .validity
        .administrative
        .is_some_and(|interval| interval.not_after <= interval.not_before)
    {
        return Err(ConformanceError::InvalidAdministrativeValidity);
    }
    validate_common_profile(common)?;
    if !common.attribute_identifiers_complete
        || !common.attribute_values_complete
        || !common.attribute_subjects_complete
    {
        return Err(ConformanceError::InvalidAttributeMetadata);
    }

    validate_category(common)?;
    validate_disclosures(common)?;
    validate_status(common)
}

fn validate_common_profile(common: &CommonAttestationFacts<'_>) -> Result<()> {
    validate_unique_uri_list(
        common.profile.context_uris,
        false,
        ConformanceError::InvalidContext,
    )?;
    if common.profile.components_use_uri_names && common.profile.context_uris.is_empty() {
        return Err(ConformanceError::InvalidContext);
    }
    validate_unique_uri_list(
        common.profile.schema_uris,
        false,
        ConformanceError::InvalidSchema,
    )?;

    match common.profile.attestation_identifier {
        Some(AttestationIdentifier::Uri(value)) => {
            validate_uri(value, false, ConformanceError::InvalidAttestationIdentifier)?
        }
        Some(AttestationIdentifier::Opaque(value))
            if value.is_empty() || value.len() > MAX_OPAQUE_IDENTIFIER_BYTES =>
        {
            return Err(ConformanceError::InvalidAttestationIdentifier);
        }
        Some(AttestationIdentifier::Opaque(_)) | None => {}
    }

    if let Some(represented) = common.profile.issued_on_behalf {
        for value in [
            represented.entity_identifier,
            represented.entity_name,
            represented.registration_identifier,
        ]
        .into_iter()
        .flatten()
        {
            validate_identifier(value, ConformanceError::InvalidIssuedOnBehalf)?;
        }
    }

    if common
        .profile
        .issued_at
        .is_some_and(|issued_at| issued_at > common.validity.technical_not_before)
    {
        return Err(ConformanceError::InvalidIssuanceTime);
    }

    validate_unique_identifiers(
        common.profile.audiences,
        ConformanceError::InvalidUsageConstraints,
    )?;
    validate_unique_uri_list(
        common.profile.terms_of_use_uris,
        false,
        ConformanceError::InvalidUsageConstraints,
    )?;

    if common.profile.attribute_evidence.len() > MAX_PROFILE_ITEMS {
        return Err(ConformanceError::InvalidAttributeEvidence);
    }
    for (index, evidence) in common.profile.attribute_evidence.iter().enumerate() {
        validate_uri(
            evidence.evidence_type_uri,
            false,
            ConformanceError::InvalidAttributeEvidence,
        )?;
        if common.profile.attribute_evidence[..index].contains(evidence) {
            return Err(ConformanceError::InvalidAttributeEvidence);
        }
        validate_uri(
            evidence.source_uri,
            false,
            ConformanceError::InvalidAttributeEvidence,
        )?;
    }

    if let Some(renewal) = common.profile.renewal_service {
        validate_uri(
            renewal.endpoint,
            true,
            ConformanceError::InvalidRenewalService,
        )?;
        if renewal.available_until < common.validity.technical_not_before {
            return Err(ConformanceError::InvalidRenewalService);
        }
    }

    Ok(())
}

fn validate_unique_uri_list(
    values: &[&str],
    https_only: bool,
    error: ConformanceError,
) -> Result<()> {
    if values.len() > MAX_PROFILE_ITEMS {
        return Err(error);
    }
    for (index, value) in values.iter().enumerate() {
        validate_uri(value, https_only, error)?;
        if values[..index].contains(value) {
            return Err(error);
        }
    }
    Ok(())
}

fn validate_unique_identifiers(values: &[&str], error: ConformanceError) -> Result<()> {
    if values.len() > MAX_PROFILE_ITEMS {
        return Err(error);
    }
    for (index, value) in values.iter().enumerate() {
        validate_identifier(value, error)?;
        if values[..index].contains(value) {
            return Err(error);
        }
    }
    Ok(())
}

fn validate_uri(value: &str, https_only: bool, error: ConformanceError) -> Result<()> {
    if value.is_empty() || value.len() > MAX_URI_BYTES || value.trim() != value {
        return Err(error);
    }
    let parsed = Url::parse(value).map_err(|_| error)?;
    if parsed.scheme().is_empty() || (https_only && parsed.scheme() != "https") {
        return Err(error);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(error);
    }
    if matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_none() {
        return Err(error);
    }
    Ok(())
}

fn validate_identifier(value: &str, error: ConformanceError) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(error)
    } else {
        Ok(())
    }
}

fn validate_country_code(value: &str) -> Result<()> {
    if crate::country::is_iso_3166_alpha_2(value) {
        Ok(())
    } else {
        Err(ConformanceError::InvalidIssuerIdentity)
    }
}

fn validate_category(common: &CommonAttestationFacts<'_>) -> Result<()> {
    if let Some(identifier) = common.issuer_identifier {
        validate_identifier(identifier, ConformanceError::InvalidIssuerIdentity)?;
    }
    if let Some(country) = common.issuer_country {
        validate_country_code(country)?;
    }
    if let Some(name) = common.issuer_name {
        validate_identifier(name, ConformanceError::InvalidIssuerIdentity)?;
    }
    validate_category_signal(common.category, common.category_signal)?;
    if let Some(reference) = common.issuer_signature_certificate_url {
        validate_uri(
            reference,
            false,
            ConformanceError::InvalidIssuerSignatureCertificateReference,
        )?;
    }

    match common.category {
        AttestationCategory::Eaa => {
            if matches!(common.issuer_signature, IssuerSignature::Unverified) {
                return Err(ConformanceError::InvalidIssuerSignature);
            }
        }
        AttestationCategory::Qeaa => {
            if common.issuer_identifier.is_none()
                || common.issuer_country.is_none()
                || common.issuer_name.is_none()
            {
                return Err(ConformanceError::InvalidIssuerIdentity);
            }
            if matches!(common.subject_binding, SubjectBinding::None)
                || !common.all_attributes_same_subject
            {
                return Err(ConformanceError::InvalidSubjectBinding);
            }
            if !matches!(common.issuer_signature, IssuerSignature::Qualified) {
                return Err(ConformanceError::InvalidIssuerSignature);
            }
            if common.issuer_signature_certificate_url.is_none() {
                return Err(ConformanceError::InvalidIssuerSignatureCertificateReference);
            }
        }
        AttestationCategory::PublicBodyEaa => {
            if common.issuer_identifier.is_none()
                || common.issuer_country.is_none()
                || common.issuer_name.is_none()
            {
                return Err(ConformanceError::InvalidIssuerIdentity);
            }
            if !matches!(
                common.issuer_signature,
                IssuerSignature::QualifiedPublicBody
            ) {
                return Err(ConformanceError::InvalidIssuerSignature);
            }
            if common.issuer_signature_certificate_url.is_none() {
                return Err(ConformanceError::InvalidIssuerSignatureCertificateReference);
            }
        }
        AttestationCategory::NaturalPersonPid | AttestationCategory::LegalPersonPid => {
            if common.issuer_identifier.is_none() || common.issuer_country.is_none() {
                return Err(ConformanceError::InvalidIssuerIdentity);
            }
            if !common.holder_public_key_bound {
                return Err(ConformanceError::InvalidHolderKeyBinding);
            }
            if matches!(common.issuer_signature, IssuerSignature::Unverified) {
                return Err(ConformanceError::InvalidIssuerSignature);
            }
        }
    }

    Ok(())
}

fn validate_category_signal(
    category: AttestationCategory,
    signal: AttestationCategorySignal<'_>,
) -> Result<()> {
    match (category, signal) {
        (AttestationCategory::Qeaa, AttestationCategorySignal::Absent)
        | (AttestationCategory::PublicBodyEaa, AttestationCategorySignal::Absent) => {
            Err(ConformanceError::MissingCategorySignal)
        }
        (AttestationCategory::Qeaa, AttestationCategorySignal::Uri(value))
            if value != QEAA_CATEGORY_URN =>
        {
            Err(ConformanceError::InvalidCategorySignal)
        }
        (AttestationCategory::PublicBodyEaa, AttestationCategorySignal::Uri(value))
            if value != PUBLIC_BODY_EAA_CATEGORY_URN =>
        {
            Err(ConformanceError::InvalidCategorySignal)
        }
        (_, AttestationCategorySignal::Uri(value)) => {
            validate_uri(value, false, ConformanceError::InvalidCategorySignal)
        }
        _ => Ok(()),
    }
}

fn validate_disclosures(common: &CommonAttestationFacts<'_>) -> Result<()> {
    let Some(disclosure) = common.selective_disclosure else {
        return Ok(());
    };

    if disclosure.disclosure_count != disclosure.signed_reference_count
        || !disclosure.references_unambiguous
        || !disclosure.algorithm_valid
    {
        return Err(ConformanceError::InvalidSelectiveDisclosure);
    }

    Ok(())
}

fn validate_status(common: &CommonAttestationFacts<'_>) -> Result<()> {
    let status_required = matches!(
        common.category,
        AttestationCategory::Qeaa
            | AttestationCategory::PublicBodyEaa
            | AttestationCategory::NaturalPersonPid
            | AttestationCategory::LegalPersonPid
    );

    match common.status {
        StatusFacts::Absent if status_required => Err(ConformanceError::MissingStatus),
        StatusFacts::Absent => Ok(()),
        StatusFacts::ShortLivedExempt => {
            let duration = common
                .validity
                .technical_not_after
                .checked_sub(common.validity.technical_not_before)
                .ok_or(ConformanceError::InvalidTechnicalValidity)?;
            if duration > MAX_SHORT_LIVED_SECONDS {
                Err(ConformanceError::InvalidShortLivedExemption)
            } else {
                Ok(())
            }
        }
        StatusFacts::Revocation {
            privacy_preserving,
            binary_only,
            irreversible,
        } => {
            let restricted_status = matches!(
                common.category,
                AttestationCategory::Qeaa
                    | AttestationCategory::PublicBodyEaa
                    | AttestationCategory::NaturalPersonPid
                    | AttestationCategory::LegalPersonPid
            );
            if !privacy_preserving || (restricted_status && (!binary_only || !irreversible)) {
                Err(ConformanceError::InvalidStatus)
            } else {
                Ok(())
            }
        }
    }
}

fn validate_format_pair(format: AttestationFormat, facts: &FormatFacts<'_>) -> Result<()> {
    let valid = matches!(
        (format, facts),
        (AttestationFormat::SdJwtVc, FormatFacts::SdJwt(_))
            | (AttestationFormat::IsoMdoc, FormatFacts::Mdoc(_))
            | (
                AttestationFormat::JsonLdJose | AttestationFormat::JsonLdSdJwt,
                FormatFacts::JsonLd(_)
            )
            | (
                AttestationFormat::X509AttributeCertificate,
                FormatFacts::X509AttributeCertificate(_)
            )
    );
    if valid {
        Ok(())
    } else {
        Err(ConformanceError::InvalidAttestationType)
    }
}

fn validate_sd_jwt(
    common: &CommonAttestationFacts<'_>,
    facts: &crate::SdJwtFacts<'_>,
) -> Result<()> {
    if facts.vct.trim().is_empty()
        || facts.vct != common.type_identifier
        || !facts.vct_integrity_valid
        || !facts.validity_claims_match
        || !facts.disclosure_algorithm_valid
    {
        return Err(ConformanceError::InvalidSdJwtProfile);
    }

    if common.selective_disclosure.is_some() && !facts.individual_claim_disclosure {
        return Err(ConformanceError::InvalidSdJwtProfile);
    }

    if common.holder_public_key_bound && !facts.confirmation_key_present {
        return Err(ConformanceError::InvalidSdJwtProfile);
    }

    if matches!(common.category, AttestationCategory::NaturalPersonPid)
        && (!facts.confirmation_key_present
            || !facts.confirmation_key_wscd_protected
            || !facts.protected_x5u_present
            || !facts.protected_x5t_s256_present)
    {
        return Err(ConformanceError::InvalidSdJwtProfile);
    }

    Ok(())
}

fn validate_mdoc(common: &CommonAttestationFacts<'_>, facts: &crate::MdocFacts<'_>) -> Result<()> {
    if facts.doc_type.trim().is_empty()
        || facts.doc_type != common.type_identifier
        || facts.namespace.trim().is_empty()
        || !facts.deterministic_cbor
        || !facts.text_constraints_valid
        || !facts.date_constraints_valid
    {
        return Err(ConformanceError::InvalidMdocProfile);
    }

    if common.holder_public_key_bound && !facts.device_key_present {
        return Err(ConformanceError::InvalidMdocProfile);
    }

    if matches!(common.category, AttestationCategory::NaturalPersonPid)
        && (!facts.device_key_present
            || !facts.device_key_wscd_protected
            || !facts.protected_x5u_present
            || !facts.protected_x5t_sha256_present)
    {
        return Err(ConformanceError::InvalidMdocProfile);
    }

    Ok(())
}

fn validate_json_ld(common: &CommonAttestationFacts<'_>, facts: &crate::JsonLdFacts) -> Result<()> {
    if !common.profile.context_uris.is_empty()
        && facts.vc_data_model_2
        && facts.context_and_type_valid
        && facts.credential_subject_valid
        && facts.enveloping_proof_valid
    {
        Ok(())
    } else {
        Err(ConformanceError::InvalidJsonLdProfile)
    }
}

fn validate_x509_attribute_certificate(facts: &crate::X509AttributeCertificateFacts) -> Result<()> {
    if facts.syntax_valid && facts.mandatory_fields_valid && facts.extensions_valid {
        Ok(())
    } else {
        Err(ConformanceError::InvalidX509AttributeCertificateProfile)
    }
}
