// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{BoundedText, IntendedUse, LocalizedText, ProvidedAttestation, WrpEntitlement};

/// Strict TS5 `WalletRelyingPartyService` representation.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct WalletRelyingPartyService {
    pub(super) service_trade_name: BoundedText,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) service_identifier: Option<BoundedText>,
    #[serde(rename = "supportURI", skip_serializing_if = "Option::is_none")]
    pub(super) support_uri: Option<BoundedText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) email: Option<BoundedText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) phone: Option<BoundedText>,
    #[serde(
        rename = "srvDescription",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub(super) service_descriptions: Vec<Vec<LocalizedText>>,
    pub(super) intended_uses: Vec<IntendedUse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) entitlements: Vec<WrpEntitlement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) sub_entitlements: Vec<BoundedText>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) provides_attestations: Vec<ProvidedAttestation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) uses_intermediaries: Vec<WalletRelyingPartyService>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(super) is_intermediary: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) served_wrp_services: Vec<BoundedText>,
    /// Canonical v1.6 service bytes retain fields that have no v1.5 analogue.
    /// They are included in application-level definition digests so a change
    /// to a trust authority, issuer policy, or cross-registry reference cannot
    /// disappear during projection into the common workflow model.
    #[serde(skip)]
    pub(super) profile_specific_material: Vec<u8>,
}

impl WalletRelyingPartyService {
    /// Returns the user-facing service trade name.
    #[must_use]
    pub fn service_trade_name(&self) -> &str {
        self.service_trade_name.expose()
    }

    /// Returns the service identifier authenticated by the registrar.
    ///
    /// TS5 v1.6 permits this value to be absent for a non-intermediated service.
    /// The legacy accessor returns an empty string for that case; authorization
    /// code should use [`Self::registered_service_identifier`].
    #[must_use]
    pub fn service_identifier(&self) -> &str {
        self.service_identifier
            .as_ref()
            .map_or("", BoundedText::expose)
    }

    /// Returns the registered service identifier without collapsing absence.
    #[must_use]
    pub fn registered_service_identifier(&self) -> Option<&str> {
        self.service_identifier.as_ref().map(BoundedText::expose)
    }

    /// Returns the support URI.
    #[must_use]
    pub fn support_uri(&self) -> Option<&str> {
        self.support_uri.as_ref().map(BoundedText::expose)
    }

    /// Returns the optional support email address.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_ref().map(BoundedText::expose)
    }

    /// Returns the optional support telephone number.
    #[must_use]
    pub fn phone(&self) -> Option<&str> {
        self.phone.as_ref().map(BoundedText::expose)
    }

    /// Returns the localized service descriptions.
    #[must_use]
    pub fn service_descriptions(&self) -> &[Vec<LocalizedText>] {
        &self.service_descriptions
    }

    /// Returns the non-empty intended-use set.
    #[must_use]
    pub fn intended_uses(&self) -> &[IntendedUse] {
        &self.intended_uses
    }

    /// Returns the registered entitlement identifiers.
    #[must_use]
    pub fn entitlements(&self) -> &[WrpEntitlement] {
        &self.entitlements
    }

    /// Returns the registered sub-entitlement identifiers.
    #[must_use]
    pub fn sub_entitlements(&self) -> &[BoundedText] {
        &self.sub_entitlements
    }

    /// Returns attestation types this service provides.
    #[must_use]
    pub fn provides_attestations(&self) -> &[ProvidedAttestation] {
        &self.provides_attestations
    }

    /// Returns intermediary services used by this regular service.
    #[must_use]
    pub fn uses_intermediaries(&self) -> &[WalletRelyingPartyService] {
        &self.uses_intermediaries
    }

    /// Reports whether this record describes an intermediary service.
    #[must_use]
    pub const fn is_intermediary(&self) -> bool {
        self.is_intermediary
    }

    /// Returns service identifiers served by this intermediary.
    #[must_use]
    pub fn served_wrp_services(&self) -> &[BoundedText] {
        &self.served_wrp_services
    }

    /// Returns canonical profile-specific bytes for security-sensitive
    /// definition binding. Empty bytes identify the v1.5 representation.
    #[must_use]
    pub fn profile_specific_material(&self) -> &[u8] {
        &self.profile_specific_material
    }
}

const fn is_false(value: &bool) -> bool {
    !*value
}
