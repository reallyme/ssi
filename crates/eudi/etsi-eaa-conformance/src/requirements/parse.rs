// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parsing for the embedded ETSI normative-requirement registry.

use crate::{ConformanceError, Result};

use super::{
    ComposedEvidenceBoundary, NormativeEuProfileStatus, NormativeRequirementApplicability,
    NormativeRequirementArea, NormativeRequirementHandler, NormativeRequirementPart,
    NormativeRequirementProfile,
};

const REQUIREMENT_TRACE: &str = include_str!("../../requirements/requirement-trace.tsv");
const MAX_REQUIREMENT_IDENTIFIER_BYTES: usize = 128;
const TRACE_COLUMN_COUNT: usize = 13;

pub(super) struct TraceColumns<'a> {
    pub(super) source: &'a str,
    pub(super) identifier: &'a str,
    pub(super) source_edition: &'a str,
    pub(super) disposition: &'a str,
    pub(super) applicability: &'a str,
    pub(super) eu_profile_status: &'a str,
    pub(super) owner_repository: &'a str,
    pub(super) code_path: &'a str,
    pub(super) code_symbol: &'a str,
    pub(super) test_path: &'a str,
    pub(super) test_symbol: &'a str,
    pub(super) external_evidence: &'a str,
    pub(super) justification: &'a str,
}

pub(super) fn normative_trace_lines() -> impl Iterator<Item = &'static str> {
    REQUIREMENT_TRACE
        .lines()
        .filter(|line| !line.starts_with('#'))
}

pub(super) fn validate_lookup_identifier(identifier: &str) -> Result<()> {
    if identifier.is_empty()
        || identifier.len() > MAX_REQUIREMENT_IDENTIFIER_BYTES
        || identifier.trim() != identifier
        || identifier.chars().any(char::is_control)
    {
        Err(ConformanceError::InvalidNormativeRequirementIdentifier)
    } else {
        Ok(())
    }
}

pub(super) fn parse_trace_columns(line: &'static str) -> Result<TraceColumns<'static>> {
    let mut columns = line.split('\t');
    let source = next_column(&mut columns)?;
    let identifier = next_column(&mut columns)?;
    let source_edition = next_column(&mut columns)?;
    let applicability = next_column(&mut columns)?;
    let disposition = next_column(&mut columns)?;
    let eu_profile_status = next_column(&mut columns)?;
    let owner_repository = next_column(&mut columns)?;
    let code_path = next_column(&mut columns)?;
    let code_symbol = next_column(&mut columns)?;
    let test_path = next_column(&mut columns)?;
    let test_symbol = next_column(&mut columns)?;
    let external_evidence = next_column(&mut columns)?;
    let justification = next_column(&mut columns)?;
    if columns.next().is_some() || line.split('\t').count() != TRACE_COLUMN_COUNT {
        return Err(ConformanceError::InvalidNormativeRequirementRegistry);
    }
    Ok(TraceColumns {
        source,
        identifier,
        source_edition,
        disposition,
        applicability,
        eu_profile_status,
        owner_repository,
        code_path,
        code_symbol,
        test_path,
        test_symbol,
        external_evidence,
        justification,
    })
}

fn next_column<'a>(columns: &mut impl Iterator<Item = &'a str>) -> Result<&'a str> {
    columns
        .next()
        .ok_or(ConformanceError::InvalidNormativeRequirementRegistry)
}

pub(super) fn parse_applicability(value: &str) -> Result<NormativeRequirementApplicability> {
    let (profile, area) = value
        .split_once(':')
        .ok_or(ConformanceError::InvalidNormativeRequirementRegistry)?;
    let profile = match profile {
        "eaa_or_pid" => NormativeRequirementProfile::EaaOrPid,
        "qeaa" => NormativeRequirementProfile::Qeaa,
        "public_body_eaa" => NormativeRequirementProfile::PublicBodyEaa,
        "sd_jwt_vc" => NormativeRequirementProfile::SdJwtVc,
        "iso_mdoc" => NormativeRequirementProfile::IsoMdoc,
        "json_ld_vc" => NormativeRequirementProfile::JsonLdVc,
        "x509_attribute_certificate" => NormativeRequirementProfile::X509AttributeCertificate,
        "openid4vp_haip" => NormativeRequirementProfile::OpenId4VpHaip,
        _ => return Err(ConformanceError::InvalidNormativeRequirementRegistry),
    };
    let area = match area {
        "all_formats" => NormativeRequirementArea::AllFormats,
        "authorization_or_token" => NormativeRequirementArea::AuthorizationOrToken,
        "credential_endpoint" => NormativeRequirementArea::CredentialEndpoint,
        "credential_offer" => NormativeRequirementArea::CredentialOffer,
        "iso_mdoc" => NormativeRequirementArea::IsoMdoc,
        "issuance" => NormativeRequirementArea::Issuance,
        "issuance_cryptography" => NormativeRequirementArea::IssuanceCryptography,
        "issuance_security" => NormativeRequirementArea::IssuanceSecurity,
        "issuer_metadata" => NormativeRequirementArea::IssuerMetadata,
        "json_ld_vc" => NormativeRequirementArea::JsonLdVc,
        "notification" => NormativeRequirementArea::Notification,
        "sd_jwt_vc" => NormativeRequirementArea::SdJwtVc,
        "x509_attribute_certificate" => NormativeRequirementArea::X509AttributeCertificate,
        "presentation" => NormativeRequirementArea::Presentation,
        _ => return Err(ConformanceError::InvalidNormativeRequirementRegistry),
    };
    Ok(NormativeRequirementApplicability { profile, area })
}

pub(super) fn parse_eu_profile_status(value: &str) -> Result<NormativeEuProfileStatus> {
    let status = match value {
        "applicable" => NormativeEuProfileStatus::Applicable,
        "applicable_subject_to_eu_adaptations" => {
            NormativeEuProfileStatus::ApplicableSubjectToAdaptations
        }
        "applicable_when_format_selected" => NormativeEuProfileStatus::ApplicableWhenFormatSelected,
        "applicable_when_notification_identifier_issued" => {
            NormativeEuProfileStatus::ApplicableWhenNotificationIdentifierIssued
        }
        "incorporated_subject_to_eu_adaptations" => {
            NormativeEuProfileStatus::IncorporatedSubjectToAdaptations
        }
        "legal_v1_2_1_and_latest_v1_3_1_delta_tracked" => {
            NormativeEuProfileStatus::Part2LegalAndLatestTracked
        }
        "not_applicable_annex_a_void_by_cir_2026_1731" => {
            NormativeEuProfileStatus::AnnexAVoidInCurrentEuProfile
        }
        _ => return Err(ConformanceError::InvalidNormativeRequirementRegistry),
    };
    Ok(status)
}

pub(super) fn source_metadata(
    source: &str,
) -> Option<(NormativeRequirementPart, ComposedEvidenceBoundary)> {
    match source {
        "ETSI-TS-119-472-1" => Some((
            NormativeRequirementPart::Part1,
            ComposedEvidenceBoundary::CredentialVerification,
        )),
        "ETSI-TS-119-472-2" => Some((
            NormativeRequirementPart::Part2,
            ComposedEvidenceBoundary::PresentationProtocol,
        )),
        "ETSI-TS-119-472-3" => Some((
            NormativeRequirementPart::Part3,
            ComposedEvidenceBoundary::IssuanceProtocol,
        )),
        _ => None,
    }
}

pub(super) fn parse_handler(code_symbol: &str) -> Result<NormativeRequirementHandler> {
    let handler = match code_symbol {
        "validate_attestation" => NormativeRequirementHandler::CommonAttestation,
        "validate_sd_jwt" => NormativeRequirementHandler::SdJwtCredential,
        "validate_mdoc" => NormativeRequirementHandler::MdocCredential,
        "validate_json_ld" => NormativeRequirementHandler::JsonLdCredential,
        "validate_x509_attribute_certificate" => {
            NormativeRequirementHandler::X509AttributeCertificate
        }
        "validate_openid4vp_presentation_for_profile;validate_authorization_response_with_options" => {
            NormativeRequirementHandler::OpenId4VpPresentation
        }
        "validate_mdoc_presentation;verify_mdoc_presentation" => {
            NormativeRequirementHandler::MdocPresentation
        }
        "validate_sd_jwt_presentation;verify_sd_jwt_presentation" => {
            NormativeRequirementHandler::SdJwtPresentation
        }
        "validate_issuance;verify_signed_issuer_metadata" => {
            NormativeRequirementHandler::IssuerMetadata
        }
        "validate_issuance;resolve_credential_offer_uri" => {
            NormativeRequirementHandler::CredentialOffer
        }
        "validate_issuance;AuthorizationCodeTokenRequest" => {
            NormativeRequirementHandler::AuthorizationCode
        }
        "validate_issuance;PreAuthorizedTokenRequest" => {
            NormativeRequirementHandler::PreAuthorizedCode
        }
        "validate_issuance;authorization_token" => {
            NormativeRequirementHandler::DpopAuthorization
        }
        "validate_issuance;handle_credential_request" => {
            NormativeRequirementHandler::CredentialRequest
        }
        "validate_issuance;JoseJweCredentialResponseEncryptor" => {
            NormativeRequirementHandler::CredentialResponseEncryption
        }
        "validate_issuance;handle_notification_request" => {
            NormativeRequirementHandler::Notification
        }
        _ => return Err(ConformanceError::InvalidNormativeRequirementRegistry),
    };
    Ok(handler)
}
