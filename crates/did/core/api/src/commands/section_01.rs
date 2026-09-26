// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use identity_core_primitives::{alg_str_to_alg, Algorithm};
use reallyme_did_types::{DIDDocument, DomainVerification, Service};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::DidApiError;
use crate::messaging::services_with_designated_pre_keys;
use crate::profile::DidProfile;
use crate::resolve::{DidProvider, DidResolutionResult, DidResolveRequest};
use crate::rotate::RekeyRelationship;
use crate::validate::{
    validate_did, validate_did_consistency, validate_did_transition, DomainVerificationEnv,
};
use reallyme_did_core::update::merge::merge_domain_verification;
use reallyme_did_core::validate::{
    validate_all_domain_bindings, validate_did_me_structure, validate_services,
};

/// Maximum entries accepted in any canonical DID update replacement list.
pub const MAX_DID_UPDATE_COLLECTION_ENTRIES: usize = 256;

/// Maximum bytes accepted in an individual canonical DID update text value.
pub const MAX_DID_UPDATE_TEXT_BYTES: usize = 4 * 1024;

/// Maximum explicit verification methods accepted by selected-key rotation.
pub const MAX_DID_KEY_ROTATION_TARGETS: usize = 256;

/// Maximum bytes accepted in a verification method identifier at rotation boundaries.
pub const MAX_DID_KEY_ROTATION_IDENTIFIER_BYTES: usize = 4 * 1024;

/// Maximum bytes accepted in a host-supplied proof timestamp.
pub const MAX_DID_KEY_ROTATION_TIMESTAMP_BYTES: usize = 128;

/// DID method requested at SDK command boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidMethod {
    /// ReallyMe self-proving DID method.
    DidMe,
}

/// SDK request for `identity.dids.create`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidCreateRequest {
    /// DID method selected by the caller.
    pub method: DidMethod,

    /// Optional typed SDK profile identifier.
    pub profile: Option<DidProfile>,
}

/// Non-cloneable owner for a validated provider-created DID document.
///
/// Creation returns a complete identifying document with public key material.
/// Canonical dispatch keeps it in this owner only until the generated result
/// has been constructed, then recursively clears the domain representation.
pub struct SensitiveDidCreatedDocument {
    inner: DIDDocument,
}

impl SensitiveDidCreatedDocument {
    fn from_document(inner: DIDDocument) -> Self {
        Self { inner }
    }

    /// Borrow the validated document without transferring ownership.
    #[must_use]
    pub fn as_document(&self) -> &DIDDocument {
        &self.inner
    }
}

impl core::fmt::Debug for SensitiveDidCreatedDocument {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SensitiveDidCreatedDocument(<redacted>)")
    }
}

impl Zeroize for SensitiveDidCreatedDocument {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for SensitiveDidCreatedDocument {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SensitiveDidCreatedDocument {}

impl DidCreateRequest {
    /// Construct the default did:me create request used by first-run SDK flows.
    #[must_use]
    pub fn did_me() -> Self {
        Self {
            method: DidMethod::DidMe,
            profile: None,
        }
    }
}

/// SDK request for `identity.dids.validate`.
#[derive(Debug, Clone)]
pub struct DidValidationRequest {
    /// DID document to validate.
    pub document: DIDDocument,
}

/// Explicit update for an optional string-valued DID document property.
#[derive(PartialEq, Eq)]
pub enum DidStringPropertyUpdate {
    /// Replace the property with a non-empty value.
    Set(String),
    /// Remove the optional property.
    Clear,
}

impl Zeroize for DidStringPropertyUpdate {
    fn zeroize(&mut self) {
        if let Self::Set(value) = self {
            value.zeroize();
        }
    }
}

/// Explicit update for an optional boolean-valued DID document property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidBoolPropertyUpdate {
    /// Replace the property with the supplied boolean value.
    Set(bool),
    /// Remove the optional property.
    Clear,
}

/// SDK request for `identity.dids.update`.
pub struct DidUpdateRequest {
    /// DID document to update.
    pub document: DIDDocument,

    /// Replacement service list, or `None` to preserve services.
    pub services: Option<Vec<Service>>,

    /// Replacement `alsoKnownAs` values.
    pub also_known_as: Option<Vec<String>>,

    /// Replacement hardware-bound metadata.
    pub hardware_bound: Option<DidBoolPropertyUpdate>,

    /// Replacement biometric-protection metadata.
    pub biometric_protected: Option<DidBoolPropertyUpdate>,

    /// Replacement user verification method metadata.
    pub user_verification_method: Option<DidStringPropertyUpdate>,

    /// Replacement device model metadata.
    pub device_model: Option<DidStringPropertyUpdate>,

    /// Replacement domain verification claims.
    pub domain_verification: Option<Vec<DomainVerification>>,
}

impl core::fmt::Debug for DidUpdateRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidUpdateRequest(<redacted>)")
    }
}

impl Zeroize for DidUpdateRequest {
    fn zeroize(&mut self) {
        self.document.zeroize();
        if let Some(services) = &mut self.services {
            for service in services.iter_mut() {
                service.zeroize();
            }
            services.clear();
        }
        self.services = None;
        if let Some(identifiers) = &mut self.also_known_as {
            for identifier in identifiers.iter_mut() {
                identifier.zeroize();
            }
            identifiers.clear();
        }
        self.also_known_as = None;
        self.hardware_bound = None;
        self.biometric_protected = None;
        self.user_verification_method.zeroize();
        self.device_model.zeroize();
        if let Some(verifications) = &mut self.domain_verification {
            for verification in verifications.iter_mut() {
                verification.zeroize();
            }
            verifications.clear();
        }
        self.domain_verification = None;
    }
}

impl Drop for DidUpdateRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidUpdateRequest {}

/// Non-cloneable owner for a validated provider-updated DID document.
pub struct SensitiveDidUpdatedDocument {
    inner: DIDDocument,
}

impl SensitiveDidUpdatedDocument {
    fn from_document(inner: DIDDocument) -> Self {
        Self { inner }
    }

    /// Borrow the validated updated document without transferring ownership.
    #[must_use]
    pub fn as_document(&self) -> &DIDDocument {
        &self.inner
    }
}

impl core::fmt::Debug for SensitiveDidUpdatedDocument {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SensitiveDidUpdatedDocument(<redacted>)")
    }
}

impl Zeroize for SensitiveDidUpdatedDocument {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for SensitiveDidUpdatedDocument {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SensitiveDidUpdatedDocument {}

/// SDK request for `identity.dids.deactivate`.
///
/// The complete authoritative document is required so the command boundary can
/// prove that a provider returned the exact next terminal transition. A DID
/// string or version hint alone cannot establish chain continuity.
pub struct DidDeactivateRequest {
    /// Active DID document whose next state must be terminal.
    pub document: DIDDocument,
}

impl core::fmt::Debug for DidDeactivateRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidDeactivateRequest(<redacted>)")
    }
}

impl Zeroize for DidDeactivateRequest {
    fn zeroize(&mut self) {
        self.document.zeroize();
    }
}

impl Drop for DidDeactivateRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidDeactivateRequest {}

/// Non-cloneable owner for a validated provider-deactivated DID document.
pub struct SensitiveDidDeactivatedDocument {
    inner: DIDDocument,
}

impl SensitiveDidDeactivatedDocument {
    fn from_document(inner: DIDDocument) -> Self {
        Self { inner }
    }

    /// Borrow the validated terminal document without transferring ownership.
    #[must_use]
    pub fn as_document(&self) -> &DIDDocument {
        &self.inner
    }
}

impl core::fmt::Debug for SensitiveDidDeactivatedDocument {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SensitiveDidDeactivatedDocument(<redacted>)")
    }
}

impl Zeroize for SensitiveDidDeactivatedDocument {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for SensitiveDidDeactivatedDocument {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SensitiveDidDeactivatedDocument {}

/// Canonical request for `identity.dids.keys.rotate`.
///
/// The authoritative active document is required to validate exactly which
/// public keys changed. Private keys and provider key handles never enter this
/// request.
pub struct DidRotateSelectedKeysRequest {
    /// Active DID document whose selected methods must rotate.
    pub document: DIDDocument,

    /// Explicit verification method identifiers.
    pub verification_method_ids: Vec<String>,

    /// Host-supplied timestamp for proof regeneration when needed.
    pub created: Option<String>,
}

impl core::fmt::Debug for DidRotateSelectedKeysRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidRotateSelectedKeysRequest(<redacted>)")
    }
}

impl Zeroize for DidRotateSelectedKeysRequest {
    fn zeroize(&mut self) {
        self.document.zeroize();
        for identifier in &mut self.verification_method_ids {
            identifier.zeroize();
        }
        self.verification_method_ids.clear();
        self.created.zeroize();
    }
}

impl Drop for DidRotateSelectedKeysRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidRotateSelectedKeysRequest {}

/// Canonical request for provider-backed compromised-key replacement.
///
/// Compromised method identifiers are treated as an authorization exclusion
/// set as well as a replacement set. This prevents suspected private material
/// from authorizing its own recovery transition.
pub struct DidReplaceCompromisedKeysRequest {
    /// Active DID document whose compromised methods must be replaced.
    pub document: DIDDocument,

    /// Explicit verification methods whose private material is considered unsafe.
    pub compromised_verification_method_ids: Vec<String>,

    /// Host-supplied timestamp for proof regeneration when needed.
    pub created: Option<String>,
}

impl core::fmt::Debug for DidReplaceCompromisedKeysRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DidReplaceCompromisedKeysRequest(<redacted>)")
    }
}

impl Zeroize for DidReplaceCompromisedKeysRequest {
    fn zeroize(&mut self) {
        self.document.zeroize();
        for identifier in &mut self.compromised_verification_method_ids {
            identifier.zeroize();
        }
        self.compromised_verification_method_ids.clear();
        self.created.zeroize();
    }
}

impl Drop for DidReplaceCompromisedKeysRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DidReplaceCompromisedKeysRequest {}

/// Non-cloneable owner for a validated provider-rotated DID document.
pub struct SensitiveDidRotatedDocument {
    inner: DIDDocument,
}

impl SensitiveDidRotatedDocument {
    fn from_document(inner: DIDDocument) -> Self {
        Self { inner }
    }

    /// Borrow the validated rotated document without transferring ownership.
    #[must_use]
    pub fn as_document(&self) -> &DIDDocument {
        &self.inner
    }
}

impl core::fmt::Debug for SensitiveDidRotatedDocument {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SensitiveDidRotatedDocument(<redacted>)")
    }
}

impl Zeroize for SensitiveDidRotatedDocument {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for SensitiveDidRotatedDocument {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SensitiveDidRotatedDocument {}
