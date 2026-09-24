// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::payload::{
    ClaimPath, CredentialMetadata, LocalizedText, ProvidedAttestation, SupervisoryAuthority,
};
use super::validation::{
    texts, uri_text_owned, validate_certificate_history, validate_claim_path,
    validate_entitlements, validate_items, validate_metadata, validate_policies, MAX_SERVICE_DEPTH,
};
use super::{
    BoundedText, CredentialRequest, IntendedUse, WalletRelyingParty, WalletRelyingPartyService,
    WrpEntitlement,
};
use crate::json::StrictValue;
use crate::{RegistrationError, RegistrationErrorReason};

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawWalletRelyingParty {
    #[serde(rename = "isPSB")]
    is_psb: Option<bool>,
    supervisory_authority: Option<RawSupervisoryAuthority>,
    trade_name: String,
    #[serde(rename = "registryURI")]
    registry_uri: String,
    services: Vec<RawService>,
    #[serde(default)]
    policy: Vec<RawPolicy>,
    provider_type: Option<i64>,
    x5c: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawService {
    service_trade_name: String,
    service_identifier: String,
    #[serde(rename = "supportURI")]
    support_uri: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    #[serde(rename = "srvDescription", default)]
    service_descriptions: Vec<Vec<RawLocalizedText>>,
    intended_uses: Vec<RawIntendedUse>,
    #[serde(default)]
    entitlements: Vec<String>,
    #[serde(default)]
    sub_entitlements: Vec<String>,
    #[serde(default)]
    provides_attestations: Vec<RawProvidedAttestation>,
    #[serde(default)]
    uses_intermediaries: Vec<RawService>,
    #[serde(default)]
    is_intermediary: bool,
    #[serde(default)]
    served_wrp_services: Vec<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawIntendedUse {
    purpose: Vec<RawLocalizedText>,
    privacy_policy: Vec<RawPolicy>,
    intended_use_identifier: String,
    created_at: Option<String>,
    revoked_at: Option<String>,
    credentials: Vec<RawCredential>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(super) struct RawLocalizedText {
    lang: String,
    content: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RawProvidedAttestation {
    format: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawSupervisoryAuthority {
    country: String,
    name: String,
    #[serde(default)]
    email: Vec<String>,
    #[serde(rename = "formURI", default)]
    form_uri: Vec<String>,
    #[serde(default)]
    phone: Vec<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RawPolicy {
    #[serde(rename = "policyURI")]
    pub(super) policy_uri: String,
    #[serde(rename = "type")]
    pub(super) kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredential {
    format: String,
    meta: BTreeMap<String, StrictValue>,
    claims: Vec<RawClaim>,
}

impl Zeroize for RawCredential {
    fn zeroize(&mut self) {
        self.format.zeroize();
        let metadata = core::mem::take(&mut self.meta);
        for (mut key, mut value) in metadata {
            key.zeroize();
            value.zeroize();
        }
        self.claims.zeroize();
    }
}

impl Drop for RawCredential {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RawCredential {}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RawClaim {
    path: String,
}

impl RawWalletRelyingParty {
    pub(crate) fn validate(mut self) -> Result<WalletRelyingParty, RegistrationError> {
        validate_items(&self.services, true)?;
        validate_items(&self.policy, false)?;
        let mut services = Vec::new();
        services
            .try_reserve_exact(self.services.len())
            .map_err(|_error| {
                RegistrationError::from_reason(RegistrationErrorReason::CapacityUnavailable)
            })?;
        for service in core::mem::take(&mut self.services) {
            services.push(service.validate(0)?);
        }
        Ok(WalletRelyingParty {
            is_psb: self.is_psb,
            supervisory_authority: self
                .supervisory_authority
                .take()
                .map(RawSupervisoryAuthority::validate)
                .transpose()?,
            trade_name: BoundedText::try_from_owned(core::mem::take(&mut self.trade_name))?,
            registry_uri: uri_text_owned(core::mem::take(&mut self.registry_uri))?,
            services,
            policy: validate_policies(core::mem::take(&mut self.policy))?,
            provider_type: self.provider_type,
            x5c: self
                .x5c
                .take()
                .map(validate_certificate_history)
                .transpose()?,
        })
    }
}

impl RawService {
    fn validate(mut self, depth: usize) -> Result<WalletRelyingPartyService, RegistrationError> {
        if depth >= MAX_SERVICE_DEPTH {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::ResourceLimitExceeded,
            ));
        }
        validate_items(&self.intended_uses, true)?;
        validate_items(&self.service_descriptions, false)?;
        validate_items(&self.entitlements, false)?;
        validate_items(&self.sub_entitlements, false)?;
        validate_items(&self.provides_attestations, false)?;
        validate_items(&self.uses_intermediaries, false)?;
        validate_items(&self.served_wrp_services, false)?;
        if self.support_uri.is_none() && self.email.is_none() && self.phone.is_none() {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::MissingField,
            ));
        }
        if self.is_intermediary == self.served_wrp_services.is_empty() {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::SemanticBindingMismatch,
            ));
        }
        if self.is_intermediary && !self.uses_intermediaries.is_empty() {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::SemanticBindingMismatch,
            ));
        }
        let entitlements = validate_entitlements(core::mem::take(&mut self.entitlements))?;
        let provides_attestations_required = entitlements
            .iter()
            .copied()
            .any(WrpEntitlement::provides_wallet_attestations);
        if provides_attestations_required == self.provides_attestations.is_empty() {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::SemanticBindingMismatch,
            ));
        }
        if !self.sub_entitlements.is_empty()
            && !entitlements.contains(&WrpEntitlement::NonQualifiedEaaProvider)
        {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::SemanticBindingMismatch,
            ));
        }
        let sub_entitlements = core::mem::take(&mut self.sub_entitlements)
            .into_iter()
            .map(uri_text_owned)
            .collect::<Result<Vec<_>, RegistrationError>>()?;
        let next_depth = depth.checked_add(1).ok_or_else(|| {
            RegistrationError::from_reason(RegistrationErrorReason::ResourceLimitExceeded)
        })?;
        let mut intermediaries = Vec::new();
        for intermediary in core::mem::take(&mut self.uses_intermediaries) {
            intermediaries.push(intermediary.validate(next_depth)?);
        }
        let mut intended_uses = Vec::new();
        for intended_use in core::mem::take(&mut self.intended_uses) {
            intended_uses.push(intended_use.validate()?);
        }
        let service_descriptions = core::mem::take(&mut self.service_descriptions)
            .into_iter()
            .map(|descriptions| {
                validate_items(&descriptions, true)?;
                descriptions
                    .into_iter()
                    .map(validate_localized_text)
                    .collect::<Result<Vec<_>, RegistrationError>>()
            })
            .collect::<Result<Vec<_>, RegistrationError>>()?;
        Ok(WalletRelyingPartyService {
            service_trade_name: BoundedText::try_from_owned(core::mem::take(
                &mut self.service_trade_name,
            ))?,
            service_identifier: BoundedText::try_from_owned(core::mem::take(
                &mut self.service_identifier,
            ))?,
            support_uri: self.support_uri.take().map(uri_text_owned).transpose()?,
            email: self
                .email
                .take()
                .map(BoundedText::try_from_owned)
                .transpose()?,
            phone: self
                .phone
                .take()
                .map(BoundedText::try_from_owned)
                .transpose()?,
            service_descriptions,
            intended_uses,
            entitlements,
            sub_entitlements,
            provides_attestations: core::mem::take(&mut self.provides_attestations)
                .into_iter()
                .map(|mut value| {
                    Ok(ProvidedAttestation {
                        format: BoundedText::try_from_owned(core::mem::take(&mut value.format))?,
                        kind: BoundedText::try_from_owned(core::mem::take(&mut value.kind))?,
                    })
                })
                .collect::<Result<Vec<_>, RegistrationError>>()?,
            uses_intermediaries: intermediaries,
            is_intermediary: self.is_intermediary,
            served_wrp_services: texts(core::mem::take(&mut self.served_wrp_services))?,
        })
    }
}

impl RawIntendedUse {
    fn validate(mut self) -> Result<IntendedUse, RegistrationError> {
        validate_items(&self.purpose, true)?;
        validate_items(&self.privacy_policy, true)?;
        validate_items(&self.credentials, true)?;
        let purpose = core::mem::take(&mut self.purpose)
            .into_iter()
            .map(validate_localized_text)
            .collect::<Result<Vec<_>, RegistrationError>>()?;
        let credentials = core::mem::take(&mut self.credentials)
            .into_iter()
            .map(RawCredential::validate)
            .collect::<Result<Vec<_>, RegistrationError>>()?;
        Ok(IntendedUse {
            purpose,
            privacy_policy: validate_policies(core::mem::take(&mut self.privacy_policy))?,
            intended_use_identifier: BoundedText::try_from_owned(core::mem::take(
                &mut self.intended_use_identifier,
            ))?,
            created_at: self
                .created_at
                .take()
                .map(BoundedText::try_from_owned)
                .transpose()?,
            revoked_at: self
                .revoked_at
                .take()
                .map(BoundedText::try_from_owned)
                .transpose()?,
            credentials,
        })
    }
}

impl RawSupervisoryAuthority {
    fn validate(mut self) -> Result<SupervisoryAuthority, RegistrationError> {
        validate_items(&self.email, false)?;
        validate_items(&self.form_uri, false)?;
        validate_items(&self.phone, false)?;
        Ok(SupervisoryAuthority {
            country: BoundedText::try_from_owned(core::mem::take(&mut self.country))?,
            name: BoundedText::try_from_owned(core::mem::take(&mut self.name))?,
            email: texts(core::mem::take(&mut self.email))?,
            form_uri: core::mem::take(&mut self.form_uri)
                .into_iter()
                .map(uri_text_owned)
                .collect::<Result<Vec<_>, RegistrationError>>()?,
            phone: texts(core::mem::take(&mut self.phone))?,
        })
    }
}

fn validate_localized_text(
    mut value: RawLocalizedText,
) -> Result<LocalizedText, RegistrationError> {
    Ok(LocalizedText {
        lang: BoundedText::try_from_owned(core::mem::take(&mut value.lang))?,
        content: BoundedText::try_from_owned(core::mem::take(&mut value.content))?,
    })
}

impl RawCredential {
    fn validate(mut self) -> Result<CredentialRequest, RegistrationError> {
        validate_items(&self.claims, true)?;
        let meta = validate_metadata(core::mem::take(&mut self.meta))?;
        let format = BoundedText::try_from_owned(core::mem::take(&mut self.format))?;
        let metadata_matches_format = matches!(
            (format.expose(), &meta),
            ("dc+sd-jwt", CredentialMetadata::DcSdJwt(_))
                | ("mso_mdoc", CredentialMetadata::MsoMdoc(_))
        );
        if !metadata_matches_format {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::SemanticBindingMismatch,
            ));
        }
        let claims = core::mem::take(&mut self.claims)
            .into_iter()
            .map(|mut claim| {
                validate_claim_path(&claim.path)?;
                Ok(ClaimPath {
                    path: BoundedText::try_from_owned(core::mem::take(&mut claim.path))?,
                })
            })
            .collect::<Result<Vec<_>, RegistrationError>>()?;
        Ok(CredentialRequest {
            format,
            meta,
            claims,
        })
    }
}
