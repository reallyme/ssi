// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate v1.6 nested records before they enter the shared registration model.

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use zeroize::Zeroizing;

use super::super::validation::{absolute_uri_text_owned, texts, uri_text_owned, validate_items};
use super::super::{
    parse_iso_calendar_date, parse_registration_date, BoundedText, LocalizedText, PolicyReference,
    SupervisoryAuthority,
};
use super::{
    RawIdentifier, RawLegalPerson, RawLocalizedTextV1_6, RawNaturalPerson, RawPolicyV1_6,
    RawServiceReference, RawSupervisoryAuthority, RawTrustAuthority,
};
use crate::json::StrictValue;
use crate::{RegistrationError, RegistrationErrorReason};

const PRIVACY_STATEMENT_TYPE_URI: &str = "http://data.europa.eu/eudi/policy/privacy-statement";

impl RawLegalPerson {
    pub(super) fn validate(&mut self) -> Result<(), RegistrationError> {
        validate_items(&self.legal_name, true)?;
        for name in &self.legal_name {
            validate_text(name)?;
        }
        if let Some(laws) = self.established_by_law.as_ref() {
            validate_items(laws, false)?;
            for law in laws {
                let _legislative_identifier =
                    absolute_uri_text_owned(law.legislative_identifier.clone())?;
                validate_optional_texts(law.legal_basis.as_deref())?;
            }
        }
        Ok(())
    }
}

impl RawNaturalPerson {
    pub(super) fn validate(&mut self) -> Result<(), RegistrationError> {
        if let Some(date_of_birth) = self.date_of_birth.as_deref() {
            parse_iso_calendar_date(date_of_birth)
                .map_err(|_error| reason(RegistrationErrorReason::InvalidField))?;
        }
        validate_text(&self.family_name)?;
        validate_text(&self.given_name)?;
        validate_optional_text(&self.place_of_birth)
    }
}

impl RawSupervisoryAuthority {
    pub(super) fn validate(&mut self) -> Result<SupervisoryAuthority, RegistrationError> {
        validate_country(&self.country)?;
        validate_text(&self.name)?;
        validate_optional_texts(self.email.as_deref())?;
        validate_optional_items(self.form_uri.as_deref(), false)?;
        validate_optional_texts(self.phone.as_deref())?;
        if self.email.as_ref().is_none_or(Vec::is_empty)
            && self.form_uri.as_ref().is_none_or(Vec::is_empty)
            && self.phone.as_ref().is_none_or(Vec::is_empty)
        {
            return Err(reason(RegistrationErrorReason::MissingField));
        }
        Ok(SupervisoryAuthority {
            country: BoundedText::try_from_owned(core::mem::take(&mut self.country))?,
            name: BoundedText::try_from_owned(core::mem::take(&mut self.name))?,
            email: texts(self.email.take().unwrap_or_default())?,
            form_uri: self
                .form_uri
                .take()
                .unwrap_or_default()
                .into_iter()
                .map(uri_text_owned)
                .collect::<Result<Vec<_>, RegistrationError>>()?,
            phone: texts(self.phone.take().unwrap_or_default())?,
        })
    }
}

impl RawServiceReference {
    pub(super) fn validate(&self) -> Result<(), RegistrationError> {
        validate_items(&self.identifier, true)?;
        for identifier in &self.identifier {
            identifier.validate()?;
        }
        validate_text(&self.service_identifier)?;
        let _registry_uri = uri_text_owned(self.registry_uri.clone())?;
        Ok(())
    }
}

impl RawIdentifier {
    pub(super) fn validate(&self) -> Result<(), RegistrationError> {
        validate_text(&self.identifier)?;
        let _kind = absolute_uri_text_owned(self.kind.clone())?;
        Ok(())
    }
}

impl RawTrustAuthority {
    pub(super) fn validate(&self) -> Result<(), RegistrationError> {
        if self
            .is_lote
            .is_some_and(|is_lote| !is_lote || self.framework_type.as_str() != "etsi_tl")
        {
            return Err(reason(RegistrationErrorReason::SemanticBindingMismatch));
        }
        match self.framework_type.as_str() {
            "aki" => {
                if self.value.is_empty() || self.value.len() > 2_048 {
                    return Err(reason(RegistrationErrorReason::InvalidField));
                }
                let decoded = Zeroizing::new(
                    base64url_to_bytes(&self.value)
                        .map_err(|_error| reason(RegistrationErrorReason::InvalidField))?,
                );
                if bytes_to_base64url(&decoded) != self.value {
                    return Err(reason(RegistrationErrorReason::InvalidField));
                }
            }
            "etsi_tl" | "openid_federation" => {
                let _uri = uri_text_owned(self.value.clone())?;
            }
            _ => return Err(reason(RegistrationErrorReason::InvalidField)),
        }
        Ok(())
    }
}

pub(super) fn validate_policies_v1_6(
    values: Vec<RawPolicyV1_6>,
) -> Result<Vec<PolicyReference>, RegistrationError> {
    validate_items(&values, false)?;
    values
        .into_iter()
        .map(|mut value| {
            Ok(PolicyReference {
                policy_uri: uri_text_owned(core::mem::take(&mut value.policy_uri))?,
                kind: absolute_uri_text_owned(core::mem::take(&mut value.kind))?,
            })
        })
        .collect()
}

pub(super) fn validate_privacy_statements_v1_6(
    values: Vec<RawPolicyV1_6>,
) -> Result<Vec<PolicyReference>, RegistrationError> {
    let policies = validate_policies_v1_6(values)?;
    // TS5's intended-use privacy statement is narrower than the inherited
    // provider/issuer Policy class, which permits other absolute type URIs.
    if policies
        .iter()
        .any(|policy| policy.kind() != PRIVACY_STATEMENT_TYPE_URI)
    {
        return Err(reason(RegistrationErrorReason::SemanticBindingMismatch));
    }
    Ok(policies)
}

pub(super) fn validate_localized_text(
    mut value: RawLocalizedTextV1_6,
) -> Result<LocalizedText, RegistrationError> {
    Ok(LocalizedText {
        lang: BoundedText::try_from_owned(core::mem::take(&mut value.lang))?,
        content: BoundedText::try_from_owned(core::mem::take(&mut value.content))?,
    })
}

pub(super) fn validate_optional_timestamp_interval(
    created: Option<&str>,
    revoked: Option<&str>,
) -> Result<(), RegistrationError> {
    let created = created.map(parse_registration_date).transpose()?;
    let revoked = revoked.map(parse_registration_date).transpose()?;
    if matches!((created, revoked), (Some(created), Some(revoked)) if revoked < created) {
        return Err(reason(RegistrationErrorReason::InvalidValidityInterval));
    }
    Ok(())
}

pub(super) fn validate_optional_identifiers(
    values: Option<&[RawIdentifier]>,
) -> Result<(), RegistrationError> {
    if let Some(values) = values {
        validate_items(values, false)?;
        for value in values {
            value.validate()?;
        }
    }
    Ok(())
}

pub(super) fn validate_optional_uris(values: Option<&[String]>) -> Result<(), RegistrationError> {
    if let Some(values) = values {
        validate_items(values, false)?;
        for value in values {
            let _uri = uri_text_owned(value.clone())?;
        }
    }
    Ok(())
}

pub(super) fn validate_optional_items<T>(
    values: Option<&[T]>,
    required: bool,
) -> Result<(), RegistrationError> {
    if let Some(values) = values {
        validate_items(values, required)?;
    }
    Ok(())
}

pub(super) fn validate_optional_texts(values: Option<&[String]>) -> Result<(), RegistrationError> {
    if let Some(values) = values {
        validate_items(values, false)?;
        for value in values {
            validate_text(value)?;
        }
    }
    Ok(())
}

pub(super) fn validate_optional_text(value: &Option<String>) -> Result<(), RegistrationError> {
    if let Some(value) = value {
        validate_text(value)?;
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), RegistrationError> {
    BoundedText::try_new(value).map(|_value| ())
}

pub(super) fn validate_country(value: &str) -> Result<(), RegistrationError> {
    if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(reason(RegistrationErrorReason::InvalidField));
    }
    Ok(())
}

pub(super) fn validate_claim_segments(values: &[StrictValue]) -> Result<(), RegistrationError> {
    if values.is_empty() || values.len() > 32 {
        return Err(reason(RegistrationErrorReason::InvalidClaimPath));
    }
    if values.iter().any(|segment| match segment {
        StrictValue::Null | StrictValue::String(_) => false,
        StrictValue::Number(number) => number.as_u64().is_none(),
        _ => true,
    }) {
        return Err(reason(RegistrationErrorReason::InvalidClaimPath));
    }
    Ok(())
}

pub(super) fn capacity_error() -> RegistrationError {
    reason(RegistrationErrorReason::CapacityUnavailable)
}

pub(super) const fn reason(value: RegistrationErrorReason) -> RegistrationError {
    RegistrationError::from_reason(value)
}
