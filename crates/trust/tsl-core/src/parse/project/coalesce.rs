// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop)]
struct ProviderIdentityKey(Vec<u8>);

fn coalesce_duplicate_providers(
    providers: Vec<TrustServiceProvider>,
) -> Result<Vec<TrustServiceProvider>, TslError> {
    let mut output: Vec<TrustServiceProvider> = Vec::new();
    let mut merged: Vec<bool> = Vec::new();
    let mut provider_indices: BTreeMap<ProviderIdentityKey, usize> = BTreeMap::new();
    for mut provider in providers {
        let key = provider_identity_key(&provider);
        if let Some(index) = provider_indices.get(&key).copied() {
            let existing = output.get_mut(index).ok_or(TslError::Provider(
                TslProviderFailure::ContradictoryRegistrationIdentifier,
            ))?;
            merge_unique_bounded(
                &mut existing.names,
                core::mem::take(&mut provider.names),
                MAX_NAMES_PER_FIELD,
                TslResourceLimit::XmlElements,
            )?;
            merge_unique_bounded(
                &mut existing.trade_names,
                core::mem::take(&mut provider.trade_names),
                MAX_NAMES_PER_FIELD,
                TslResourceLimit::XmlElements,
            )?;
            merge_unique_bounded(
                &mut existing.registration_identifiers,
                core::mem::take(&mut provider.registration_identifiers),
                MAX_NAMES_PER_FIELD,
                TslResourceLimit::XmlElements,
            )?;
            merge_unique_bounded(
                &mut existing.address.postal_addresses,
                core::mem::take(&mut provider.address.postal_addresses),
                MAX_NAMES_PER_FIELD,
                TslResourceLimit::XmlElements,
            )?;
            merge_unique_bounded(
                &mut existing.address.electronic_addresses,
                core::mem::take(&mut provider.address.electronic_addresses),
                MAX_NAMES_PER_FIELD,
                TslResourceLimit::XmlElements,
            )?;
            merge_unique_bounded(
                &mut existing.information_uris,
                core::mem::take(&mut provider.information_uris),
                MAX_NAMES_PER_FIELD,
                TslResourceLimit::XmlElements,
            )?;
            existing
                .services
                .append(&mut core::mem::take(&mut provider.services));
            let flag = merged.get_mut(index).ok_or(TslError::Provider(
                TslProviderFailure::ContradictoryRegistrationIdentifier,
            ))?;
            *flag = true;
        } else {
            provider_indices.insert(key, output.len());
            output.push(provider);
            merged.push(false);
        }
    }
    // Group every duplicate provider record first, then coalesce each merged
    // service set once. Re-coalescing after every duplicate is quadratic in
    // the number of services under one provider identity.
    for (provider, was_merged) in output.iter_mut().zip(merged) {
        if was_merged {
            let services = core::mem::take(&mut provider.services);
            provider.services = coalesce_duplicate_current_services(services)?;
        }
    }
    Ok(output)
}

fn provider_identity_key(provider: &TrustServiceProvider) -> ProviderIdentityKey {
    let use_vat = provider.registration_identifiers.iter().any(|identifier| {
        identifier.kind == TspRegistrationIdentifierKind::ValueAddedTax
    });
    let mut identifiers: Vec<_> = provider
        .registration_identifiers
        .iter()
        .filter(|identifier| {
            !use_vat || identifier.kind == TspRegistrationIdentifierKind::ValueAddedTax
        })
        .collect();
    identifiers.sort_unstable_by_key(|identifier| {
        (
            registration_identifier_kind_tag(identifier.kind),
            identifier.country_code.as_str(),
            identifier.value.as_str(),
        )
    });
    let mut key = Vec::new();
    for identifier in identifiers {
        key.push(registration_identifier_kind_tag(identifier.kind));
        key.extend_from_slice(identifier.country_code.as_bytes());
        key.push(0);
        key.extend_from_slice(identifier.value.as_bytes());
        key.push(0);
    }
    ProviderIdentityKey(key)
}

const fn registration_identifier_kind_tag(kind: TspRegistrationIdentifierKind) -> u8 {
    match kind {
        TspRegistrationIdentifierKind::ValueAddedTax => 0,
        TspRegistrationIdentifierKind::NationalTradeRegister => 1,
        TspRegistrationIdentifierKind::Passport => 2,
        TspRegistrationIdentifierKind::IdentityCard => 3,
        TspRegistrationIdentifierKind::PersonalNumber => 4,
        TspRegistrationIdentifierKind::TaxIdentificationNumber => 5,
    }
}

fn coalesce_duplicate_current_services(
    services: Vec<TrustService>,
) -> Result<Vec<TrustService>, TslError> {
    let mut output: Vec<TrustService> = Vec::new();
    let mut service_indices: BTreeMap<_, usize> = BTreeMap::new();
    for service in services {
        let identity_key = match &service.digital_identity {
            ServiceDigitalIdentity::Pki(identity) => {
                let subject_public_key_info = identity
                    .subject_public_key_info_der()
                    .ok_or(TslError::DigitalIdentity(
                        TslDigitalIdentityFailure::MissingCertificate,
                    ))?;
                let capacity = subject_public_key_info
                    .len()
                    .checked_add(1)
                    .ok_or(TslError::ResourceLimit(TslResourceLimit::Services))?;
                let mut key = Vec::new();
                key.try_reserve_exact(capacity)
                    .map_err(|_| TslError::ResourceLimit(TslResourceLimit::Services))?;
                key.push(0);
                key.extend_from_slice(subject_public_key_info);
                key
            }
            ServiceDigitalIdentity::NonPki(identifier) => {
                let capacity = identifier
                    .as_str()
                    .len()
                    .checked_add(1)
                    .ok_or(TslError::ResourceLimit(TslResourceLimit::Services))?;
                let mut key = Vec::new();
                key.try_reserve_exact(capacity)
                    .map_err(|_| TslError::ResourceLimit(TslResourceLimit::Services))?;
                key.push(1);
                key.extend_from_slice(identifier.as_str().as_bytes());
                key
            }
        };
        let purpose_scope_key = additional_service_information_key(
            &service.additional_service_information,
        )?;
        let key = (service.service_type.clone(), identity_key, purpose_scope_key);
        match service_indices.entry(key) {
            std::collections::btree_map::Entry::Occupied(entry) => {
                let existing = output
                    .get_mut(*entry.get())
                    .ok_or(TslError::ResourceLimit(TslResourceLimit::Services))?;
                // An ambiguous row must fail closed for its service key, not
                // make every unrelated provider in the authenticated list
                // unusable. Distinct ASi scopes remain separate keys.
                existing.status = TrustServiceStatus::Indeterminate;
                existing.history.clear();
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(output.len());
                output.push(service);
            }
        }
    }
    Ok(output)
}

fn additional_service_information_key(
    information: &[AdditionalServiceInformation],
) -> Result<Vec<u8>, TslError> {
    let mut entries = information
        .iter()
        .map(|entry| {
            let tag = match entry.kind {
                AdditionalServiceInformationKind::ForElectronicSignatures => 0_u8,
                AdditionalServiceInformationKind::ForElectronicSeals => 1,
                AdditionalServiceInformationKind::ForWebsiteAuthentication => 2,
                AdditionalServiceInformationKind::RootCaQualifiedCertificates => 3,
                AdditionalServiceInformationKind::Other(_) => 4,
            };
            (tag, entry.information_value.as_deref().unwrap_or_default())
        })
        .collect::<Vec<_>>();
    entries.sort_unstable();
    let mut key = Vec::new();
    for (tag, value) in entries {
        let value_len = u32::try_from(value.len())
            .map_err(|_| TslError::ResourceLimit(TslResourceLimit::XmlText))?;
        key.push(tag);
        key.extend_from_slice(&value_len.to_be_bytes());
        key.extend_from_slice(value.as_bytes());
    }
    Ok(key)
}
