// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ServiceDigitalIdentity, TrustService, TrustedList};

/// Select service states that are effective at an authenticated evaluation time.
///
/// National trusted lists can pre-publish a future transition as the current
/// `ServiceInformation` value. This projection must run only after XML
/// signature authentication: it promotes the newest applicable historical
/// state when that state identifies the same public key, and omits a service
/// that has not become effective. Future supply points are cleared when a
/// historical state is promoted because clause 5.6.3 does not authenticate
/// historical supply points.
pub fn select_effective_service_states(list: &mut TrustedList, now: time::OffsetDateTime) {
    let now = (now.unix_timestamp(), now.nanosecond());
    for provider in &mut list.providers {
        provider
            .services
            .retain_mut(|service| select_effective_service_state(service, now));
    }
}

fn select_effective_service_state(service: &mut TrustService, now: (i64, u32)) -> bool {
    let current = (
        service.status_starting_time.unix_seconds(),
        service.status_starting_time.nanosecond(),
    );
    if current <= now {
        return true;
    }

    let current_key_identifier = service.digital_identity.subject_key_identifier();
    let selected_index = service.history.iter().position(|entry| {
        let effective = (
            entry.status_starting_time.unix_seconds(),
            entry.status_starting_time.nanosecond(),
        );
        effective <= now && same_service_key(current_key_identifier, &entry.digital_identity)
    });
    let Some(selected_index) = selected_index else {
        return false;
    };
    let mut removed = service.history.drain(..=selected_index);
    let Some(mut selected) = removed.next_back() else {
        return false;
    };
    service.service_type = selected.service_type.clone();
    service.service_names = core::mem::take(&mut selected.service_names);
    service.status = selected.status.clone();
    service.status_starting_time = selected.status_starting_time;
    service.qualifications = core::mem::take(&mut selected.qualifications);
    service.additional_service_information =
        core::mem::take(&mut selected.additional_service_information);
    service.supply_points.clear();
    true
}

fn same_service_key(
    current_key_identifier: Option<&[u8]>,
    historical_identity: &ServiceDigitalIdentity,
) -> bool {
    current_key_identifier.is_some()
        && current_key_identifier == historical_identity.subject_key_identifier()
}
