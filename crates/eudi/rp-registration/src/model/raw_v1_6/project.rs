// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Project validated v1.6 records while retaining their canonical profile material.

use zeroize::{Zeroize, Zeroizing};

use super::super::validation::{
    absolute_uri_text_owned, uri_text_owned, validate_entitlements, validate_items,
    validate_v1_6_metadata,
};
use super::super::{
    BoundedText, CredentialRequest, IntendedUse, ProvidedAttestation, WalletRelyingParty,
    WalletRelyingPartyService, WrpEntitlement,
};
use super::validate::{
    capacity_error, reason, validate_claim_segments, validate_country, validate_localized_text,
    validate_optional_identifiers, validate_optional_items, validate_optional_texts,
    validate_optional_timestamp_interval, validate_optional_uris, validate_policies_v1_6,
    validate_privacy_statements_v1_6,
};
use super::{RawCredentialV1_6, RawIntendedUseV1_6, RawServiceV1_6, RawWalletRelyingPartyV1_6};
use crate::json::canonical_json;
use crate::{ProtocolProfile, RegistrationError, RegistrationErrorReason};

impl RawWalletRelyingPartyV1_6 {
    pub(crate) fn validate(mut self) -> Result<WalletRelyingParty, RegistrationError> {
        let mut canonical_source = Zeroizing::new(canonical_json(&self)?);
        validate_items(&self.services, true)?;
        validate_country(&self.country)?;
        validate_items(&self.policy, true)?;
        validate_optional_texts(self.email.as_deref())?;
        validate_optional_identifiers(self.identifier.as_deref())?;
        validate_optional_uris(self.info_uri.as_deref())?;
        validate_optional_texts(self.phone.as_deref())?;
        validate_optional_texts(self.postal_address.as_deref())?;
        if self.provider_type != "WalletRelyingParty" {
            return Err(reason(RegistrationErrorReason::SemanticBindingMismatch));
        }
        validate_optional_texts(self.x5c.as_deref())?;
        validate_optional_timestamp_interval(Some(&self.created_at), self.revoked_at.as_deref())?;
        if self.legal_person.is_some() == self.natural_person.is_some() {
            return Err(reason(RegistrationErrorReason::SemanticBindingMismatch));
        }
        if let Some(legal_person) = self.legal_person.as_mut() {
            legal_person.validate()?;
        }
        if let Some(natural_person) = self.natural_person.as_mut() {
            natural_person.validate()?;
        }

        validate_unique_service_identifiers(&self.services)?;
        let supervisory_authority = self.supervisory_authority.validate()?;
        let mut services = Vec::new();
        services
            .try_reserve_exact(self.services.len())
            .map_err(|_error| capacity_error())?;
        for service in core::mem::take(&mut self.services) {
            services.push(service.validate()?);
        }
        Ok(WalletRelyingParty {
            is_psb: Some(self.is_psb),
            supervisory_authority: Some(supervisory_authority),
            trade_name: self
                .trade_name
                .take()
                .map(BoundedText::try_from_owned)
                .transpose()?,
            registry_uri: uri_text_owned(core::mem::take(&mut self.registry_uri))?,
            services,
            policy: validate_policies_v1_6(core::mem::take(&mut self.policy))?,
            // These v1.6 fields are preserved losslessly in `canonical_source`.
            // The common projection intentionally exposes no misleading v1.5
            // numeric provider type or scalar certificate-history value.
            provider_type: None,
            x5c: None,
            source_profile: ProtocolProfile::Ts5V1_6,
            canonical_source: core::mem::take(&mut *canonical_source),
        })
    }
}

impl RawServiceV1_6 {
    fn validate(mut self) -> Result<WalletRelyingPartyService, RegistrationError> {
        let mut profile_specific_material = Zeroizing::new(canonical_json(&self)?);
        validate_items(&self.service_descriptions, true)?;
        validate_optional_items(self.intended_uses.as_deref(), false)?;
        validate_optional_items(self.entitlements.as_deref(), false)?;
        validate_optional_items(self.sub_entitlements.as_deref(), false)?;
        validate_optional_items(self.provides_attestations.as_deref(), false)?;
        validate_optional_items(self.issuer_policies.as_deref(), false)?;
        validate_optional_items(self.uses_intermediaries.as_deref(), false)?;
        validate_optional_items(self.served_wrp_services.as_deref(), false)?;
        if self.support_uri.is_none() && self.email.is_none() && self.phone.is_none() {
            return Err(reason(RegistrationErrorReason::MissingField));
        }
        // TS5 constrains whether these members may be present, including when
        // their arrays are empty. Preserve presence until role validation ends.
        if (self.is_intermediary && self.uses_intermediaries.is_some())
            || (!self.is_intermediary && self.served_wrp_services.is_some())
        {
            return Err(reason(RegistrationErrorReason::SemanticBindingMismatch));
        }
        let uses_intermediaries = self.uses_intermediaries.take().unwrap_or_default();
        let served_wrp_services = self.served_wrp_services.take().unwrap_or_default();
        if !uses_intermediaries.is_empty() && self.service_identifier.is_none() {
            return Err(reason(RegistrationErrorReason::MissingField));
        }
        for reference in uses_intermediaries.iter().chain(served_wrp_services.iter()) {
            reference.validate()?;
        }
        let entitlements = validate_entitlements(self.entitlements.take().unwrap_or_default())?;
        // Entitlements belong to regular service registrations; an intermediary
        // registration must not acquire a service-provider role through them.
        if self.is_intermediary && !entitlements.is_empty() {
            return Err(reason(RegistrationErrorReason::SemanticBindingMismatch));
        }
        let provides_attestations = self.provides_attestations.take().unwrap_or_default();
        let provides_attestations_required = entitlements
            .iter()
            .copied()
            .any(WrpEntitlement::provides_wallet_attestations);
        if provides_attestations_required == provides_attestations.is_empty() {
            return Err(reason(RegistrationErrorReason::SemanticBindingMismatch));
        }
        let sub_entitlements = self.sub_entitlements.take().unwrap_or_default();
        if !sub_entitlements.is_empty()
            && !entitlements.contains(&WrpEntitlement::NonQualifiedEaaProvider)
        {
            return Err(reason(RegistrationErrorReason::SemanticBindingMismatch));
        }
        let mut validated_attestations = Vec::new();
        validated_attestations
            .try_reserve_exact(provides_attestations.len())
            .map_err(|_error| capacity_error())?;
        for mut value in provides_attestations {
            if let Some(authorities) = value.trusted_authorities.as_ref() {
                validate_items(authorities, false)?;
                for authority in authorities {
                    authority.validate()?;
                }
            }
            validated_attestations.push(ProvidedAttestation {
                format: BoundedText::try_from_owned(core::mem::take(&mut value.format))?,
                kind: BoundedText::try_from_owned(core::mem::take(&mut value.kind))?,
            });
        }
        let descriptions = core::mem::take(&mut self.service_descriptions)
            .into_iter()
            .map(validate_localized_text)
            .collect::<Result<Vec<_>, RegistrationError>>()?;
        let intended_uses = self
            .intended_uses
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(RawIntendedUseV1_6::validate)
            .collect::<Result<Vec<_>, RegistrationError>>()?;
        let _issuer_policies =
            validate_policies_v1_6(self.issuer_policies.take().unwrap_or_default())?;
        Ok(WalletRelyingPartyService {
            service_trade_name: BoundedText::try_from_owned(core::mem::take(
                &mut self.service_trade_name,
            ))?,
            service_identifier: self
                .service_identifier
                .take()
                .map(BoundedText::try_from_owned)
                .transpose()?,
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
            // The common projection retains one language set; the exact flat
            // v1.6 representation remains in `profile_specific_material`.
            service_descriptions: vec![descriptions],
            intended_uses,
            entitlements,
            sub_entitlements: sub_entitlements
                .into_iter()
                .map(absolute_uri_text_owned)
                .collect::<Result<Vec<_>, RegistrationError>>()?,
            provides_attestations: validated_attestations,
            // Cross-registry references are not recursive services. They stay
            // in canonical profile material rather than being misrepresented.
            uses_intermediaries: Vec::new(),
            is_intermediary: self.is_intermediary,
            served_wrp_services: Vec::new(),
            profile_specific_material: core::mem::take(&mut *profile_specific_material),
        })
    }
}

fn validate_unique_service_identifiers(
    services: &[RawServiceV1_6],
) -> Result<(), RegistrationError> {
    for (index, service) in services.iter().enumerate() {
        let Some(identifier) = service.service_identifier.as_deref() else {
            continue;
        };
        if services
            .iter()
            .take(index)
            .any(|candidate| candidate.service_identifier.as_deref() == Some(identifier))
        {
            return Err(reason(RegistrationErrorReason::SemanticBindingMismatch));
        }
    }
    Ok(())
}

impl RawIntendedUseV1_6 {
    fn validate(mut self) -> Result<IntendedUse, RegistrationError> {
        validate_items(&self.purpose, true)?;
        validate_items(&self.privacy_policy, true)?;
        validate_items(&self.credentials, true)?;
        validate_optional_timestamp_interval(Some(&self.created_at), self.revoked_at.as_deref())?;
        Ok(IntendedUse {
            purpose: core::mem::take(&mut self.purpose)
                .into_iter()
                .map(validate_localized_text)
                .collect::<Result<Vec<_>, RegistrationError>>()?,
            privacy_policy: validate_privacy_statements_v1_6(core::mem::take(
                &mut self.privacy_policy,
            ))?,
            intended_use_identifier: BoundedText::try_from_owned(core::mem::take(
                &mut self.intended_use_identifier,
            ))?,
            created_at: Some(BoundedText::try_from_owned(core::mem::take(
                &mut self.created_at,
            ))?),
            revoked_at: self
                .revoked_at
                .take()
                .map(BoundedText::try_from_owned)
                .transpose()?,
            credentials: core::mem::take(&mut self.credentials)
                .into_iter()
                .map(RawCredentialV1_6::validate)
                .collect::<Result<Vec<_>, RegistrationError>>()?,
        })
    }
}

impl RawCredentialV1_6 {
    fn validate(mut self) -> Result<CredentialRequest, RegistrationError> {
        validate_items(&self.claims, true)?;
        let mut paths = Vec::new();
        paths
            .try_reserve_exact(self.claims.len())
            .map_err(|_error| capacity_error())?;
        for mut claim in core::mem::take(&mut self.claims) {
            validate_claim_segments(&claim.path)?;
            let encoded = canonical_json(&claim.path)?;
            let path = String::from_utf8(encoded)
                .map_err(|_error| reason(RegistrationErrorReason::InvalidClaimPath))?;
            claim.path.zeroize();
            paths.push(path);
        }
        let metadata = validate_v1_6_metadata(core::mem::take(&mut self.meta))?;
        CredentialRequest::try_new_with_metadata(core::mem::take(&mut self.format), metadata, paths)
    }
}
