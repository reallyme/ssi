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
            merge_unique(&mut existing.names, core::mem::take(&mut provider.names));
            merge_unique(
                &mut existing.trade_names,
                core::mem::take(&mut provider.trade_names),
            );
            merge_unique(
                &mut existing.registration_identifiers,
                core::mem::take(&mut provider.registration_identifiers),
            );
            merge_unique(
                &mut existing.address.postal_addresses,
                core::mem::take(&mut provider.address.postal_addresses),
            );
            merge_unique(
                &mut existing.address.electronic_addresses,
                core::mem::take(&mut provider.address.electronic_addresses),
            );
            merge_unique(
                &mut existing.information_uris,
                core::mem::take(&mut provider.information_uris),
            );
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
    let mut output = Vec::new();
    let mut service_indices = BTreeMap::new();
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
        let key = (service.service_type.clone(), identity_key);
        if let Some(index) = service_indices.get(&key).copied() {
            let current = output.get_mut(index).ok_or(TslError::DigitalIdentity(
                TslDigitalIdentityFailure::DuplicateServiceKey,
            ))?;
            merge_duplicate_current_service(current, service)?;
        } else {
            service_indices.insert(key, output.len());
            output.push(service);
        }
    }
    Ok(output)
}

fn merge_duplicate_current_service(
    current: &mut TrustService,
    mut candidate: TrustService,
) -> Result<(), TslError> {
    let current_time = timestamp_order_key(current.status_starting_time);
    let candidate_time = timestamp_order_key(candidate.status_starting_time);
    if candidate_time > current_time {
        core::mem::swap(current, &mut candidate);
    } else if candidate_time == current_time && candidate.status != current.status {
        return Err(TslError::DigitalIdentity(
            TslDigitalIdentityFailure::DuplicateServiceKey,
        ));
    }

    merge_unique(&mut current.history, core::mem::take(&mut candidate.history));
    if candidate_time == current_time {
        // Two publications of the same effective state: every representation
        // describes the state in force from this starting time.
        merge_unique(
            &mut current.service_names,
            core::mem::take(&mut candidate.service_names),
        );
        merge_unique(
            &mut current.supply_points,
            core::mem::take(&mut candidate.supply_points),
        );
        merge_unique(
            &mut current.qualifications,
            core::mem::take(&mut candidate.qualifications),
        );
        merge_unique(
            &mut current.additional_service_information,
            core::mem::take(&mut candidate.additional_service_information),
        );
        merge_current_certificates(&mut current.digital_identity, &candidate.digital_identity)?;
    } else {
        // An older duplicate describes a superseded state. Its qualifications,
        // additional information, supply points, names, and certificate
        // representations must not widen the current state; they are kept
        // only as the historical row effective from its own starting time.
        let historical_identity = historical_identity_from_current(&candidate.digital_identity)?;
        let entry = TrustServiceHistoryEntry {
            service_type: candidate.service_type.clone(),
            service_names: core::mem::take(&mut candidate.service_names),
            status: candidate.status.clone(),
            status_starting_time: candidate.status_starting_time,
            digital_identity: Some(historical_identity),
            qualifications: core::mem::take(&mut candidate.qualifications),
            additional_service_information: core::mem::take(
                &mut candidate.additional_service_information,
            ),
        };
        if !current.history.contains(&entry) {
            current.history.push(entry);
        }
    }
    normalize_service_history(current.status_starting_time, &mut current.history);
    Ok(())
}
