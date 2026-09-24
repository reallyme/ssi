// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_did_types::DIDDocument;
use reallyme_did_types::Service;
use reallyme_keys::KeySet;
use serde_json::Map;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::DidApiError;
use crate::rotate::rotate_keys;
use crate::update::{update_did, UpdateConfig};
use crate::validate::{validate_did, DomainVerificationEnv};

const MESSAGING_SERVICE_TYPE: &str = "MessagingService";
const MESSAGING_SERVICE_URI_FIELD: &str = "uri";
const MESSAGING_SERVICE_PRE_KEYS_FIELD: &str = "preKeys";

/// Validated sender-side view of one MessagingService pre-key snapshot.
#[derive(PartialEq, Eq)]
pub struct MessagingPreKeySnapshot {
    /// DID whose signed core published this service.
    pub did: String,

    /// did:me sequence number for replay and transcript binding.
    pub sequence: u64,

    /// Current canonical core CID that published the selected pre-keys.
    pub current_core: String,

    /// Service identifier that carried the pre-key set.
    pub service_id: String,

    /// Delivery URI for the messaging service.
    pub uri: String,

    /// Hybrid keyAgreement verification method references selected by sender.
    pub pre_keys: Vec<String>,
}

impl core::fmt::Debug for MessagingPreKeySnapshot {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MessagingPreKeySnapshot(<redacted>)")
    }
}

impl Zeroize for MessagingPreKeySnapshot {
    fn zeroize(&mut self) {
        self.did.zeroize();
        self.sequence.zeroize();
        self.current_core.zeroize();
        self.service_id.zeroize();
        self.uri.zeroize();
        self.pre_keys.zeroize();
    }
}

impl Drop for MessagingPreKeySnapshot {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MessagingPreKeySnapshot {}

/// Discover validated MessagingService pre-key snapshots from a DID document.
///
/// The returned value deliberately carries DID, sequence, and current core CID
/// alongside the pre-key references. Message senders need those fields in the
/// encryption transcript so a relay cannot swap in a stale or cross-DID
/// MessagingService endpoint without changing the bound snapshot.
pub fn discover_messaging_pre_keys(
    doc: &DIDDocument,
) -> Result<Vec<MessagingPreKeySnapshot>, DidApiError> {
    if doc.id.is_empty() || doc.current_core.is_empty() {
        return Err(DidApiError::MessagingPreKeyDiscoveryInvalid);
    }

    if !validate_did(
        doc,
        DomainVerificationEnv {
            resolve_txt: None,
            fetch_url: None,
        },
    )
    .ok
    {
        return Err(DidApiError::MessagingPreKeyDiscoveryInvalid);
    }

    let mut snapshots = Vec::new();

    for service in doc
        .service
        .iter()
        .filter(|service| service.service_type == MESSAGING_SERVICE_TYPE)
    {
        let endpoint = service
            .service_endpoint
            .as_object()
            .ok_or(DidApiError::MessagingPreKeyDiscoveryInvalid)?;
        let uri = endpoint
            .get(MESSAGING_SERVICE_URI_FIELD)
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .ok_or(DidApiError::MessagingPreKeyDiscoveryInvalid)?;
        let pre_key_values = endpoint
            .get(MESSAGING_SERVICE_PRE_KEYS_FIELD)
            .and_then(|value| value.as_array())
            .filter(|values| !values.is_empty())
            .ok_or(DidApiError::MessagingPreKeyDiscoveryInvalid)?;

        let mut pre_keys = Vec::with_capacity(pre_key_values.len());
        for pre_key_value in pre_key_values {
            let pre_key = pre_key_value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or(DidApiError::MessagingPreKeyDiscoveryInvalid)?;
            pre_keys.push(pre_key.to_owned());
        }

        snapshots.push(MessagingPreKeySnapshot {
            did: doc.id.clone(),
            sequence: doc.sequence,
            current_core: doc.current_core.clone(),
            service_id: service.id.clone(),
            uri: uri.to_owned(),
            pre_keys,
        });
    }

    if snapshots.is_empty() {
        return Err(DidApiError::MessagingPreKeyDiscoveryInvalid);
    }

    Ok(snapshots)
}

/// Designate a MessagingService pre-key set in the signed did:me core.
///
/// This is the taxonomy `messaging_keys.designate_pre_keys` operation for
/// did:me. It publishes controller-selected keyAgreement references in a
/// MessagingService endpoint and then revalidates discovery so malformed,
/// non-hybrid, or non-keyAgreement references fail before the caller receives
/// a document to publish.
pub fn designate_messaging_pre_keys(
    old_doc: &DIDDocument,
    ks: &KeySet,
    service_id: String,
    uri: String,
    pre_keys: Vec<String>,
    created: Option<String>,
) -> Result<(DIDDocument, KeySet), DidApiError> {
    let services = services_with_designated_pre_keys(old_doc, service_id, uri, pre_keys)
        .ok_or(DidApiError::MessagingPreKeyDesignationInvalid)?;

    let (doc, new_ks) = update_did(
        old_doc,
        ks,
        UpdateConfig {
            services: Some(services),
            also_known_as: None,
            hardware_bound: None,
            biometric_protected: None,
            user_verification_method: None,
            device_model: None,
            allowed: None,
            threshold: None,
            deactivate: false,
            domain_verification: None,
            rotate_vms: None,
            authentication: None,
            assertion: None,
            invocation: None,
            key_agreement: None,
            created,
        },
    )?;

    discover_messaging_pre_keys(&doc)
        .map_err(|_| DidApiError::MessagingPreKeyDesignationInvalid)?;

    Ok((doc, new_ks))
}

/// Rotate the key material behind one published MessagingService pre-key set.
///
/// did:me MessagingService pre-keys are keyAgreement verification method
/// references. Rotating them keeps the stable references in the service while
/// publishing fresh public material and a new signed core for those methods.
pub fn rotate_messaging_pre_keys(
    old_doc: &DIDDocument,
    ks: &KeySet,
    service_id: &str,
    created: Option<String>,
) -> Result<(DIDDocument, KeySet), DidApiError> {
    let snapshot = discover_messaging_pre_keys(old_doc)?
        .into_iter()
        .find(|snapshot| snapshot.service_id == service_id)
        .ok_or(DidApiError::MessagingPreKeyDiscoveryInvalid)?;

    rotate_keys(old_doc, ks, &snapshot.pre_keys, created)
}

pub(crate) fn services_with_designated_pre_keys(
    doc: &DIDDocument,
    service_id: String,
    uri: String,
    pre_keys: Vec<String>,
) -> Option<Vec<Service>> {
    if service_id.is_empty() || uri.is_empty() || pre_keys.is_empty() {
        return None;
    }

    let mut endpoint = Map::new();
    endpoint.insert(
        MESSAGING_SERVICE_URI_FIELD.to_owned(),
        serde_json::Value::String(uri),
    );
    endpoint.insert(
        MESSAGING_SERVICE_PRE_KEYS_FIELD.to_owned(),
        serde_json::Value::Array(
            pre_keys
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );

    let service = Service {
        id: service_id.clone(),
        service_type: MESSAGING_SERVICE_TYPE.to_owned(),
        service_endpoint: serde_json::Value::Object(endpoint),
    };

    let mut services = doc.service.clone();
    match services
        .iter()
        .position(|candidate| candidate.id == service_id)
    {
        Some(index) => services[index] = service,
        None => services.push(service),
    }

    Some(services)
}
