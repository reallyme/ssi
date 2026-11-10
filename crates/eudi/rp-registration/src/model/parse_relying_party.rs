// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt::{Debug, Formatter};

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    BoundedText, PolicyReference, ProtocolProfile, RawWalletRelyingParty,
    RawWalletRelyingPartyV1_6, SupervisoryAuthority, WalletRelyingPartyService,
};
use crate::json::deserialize_strict;
use crate::RegistrationError;

/// Strict TS5 Wallet Relying Party record.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct WalletRelyingParty {
    #[serde(rename = "isPSB", skip_serializing_if = "Option::is_none")]
    pub(super) is_psb: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) supervisory_authority: Option<SupervisoryAuthority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) trade_name: Option<BoundedText>,
    #[serde(rename = "registryURI")]
    pub(super) registry_uri: BoundedText,
    pub(super) services: Vec<WalletRelyingPartyService>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) policy: Vec<PolicyReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) provider_type: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) x5c: Option<BoundedText>,
    #[serde(skip)]
    pub(super) source_profile: ProtocolProfile,
    /// Canonical v1.6 source bytes preserve the complete validated document
    /// for a lossless write round-trip. The v1.5 representation remains
    /// derived from the typed fields and stores no duplicate source bytes.
    #[serde(skip)]
    pub(super) canonical_source: Vec<u8>,
}

impl WalletRelyingParty {
    /// Parses one strict WRP object, rejecting duplicates and unknown members.
    pub fn from_json(input: &[u8]) -> Result<Self, RegistrationError> {
        let raw: RawWalletRelyingParty = deserialize_strict(input)?;
        raw.validate()
    }

    /// Parses one WRP object using an explicit versioned TS5 data model.
    pub fn from_json_for_profile(
        profile: ProtocolProfile,
        input: &[u8],
    ) -> Result<Self, RegistrationError> {
        match profile {
            ProtocolProfile::Ts5V1_5 | ProtocolProfile::EuReferenceLegacyV0_2_2 => {
                Self::from_json(input)
            }
            ProtocolProfile::Ts5V1_6 => {
                let raw: RawWalletRelyingPartyV1_6 = deserialize_strict(input)?;
                raw.validate()
            }
        }
    }

    /// Returns the exact data-model profile used during strict parsing.
    #[must_use]
    pub const fn source_profile(&self) -> ProtocolProfile {
        self.source_profile
    }

    pub(crate) fn canonical_source(&self) -> &[u8] {
        &self.canonical_source
    }

    /// Returns whether this WRP is a public-sector body, when registered.
    #[must_use]
    pub const fn is_public_sector_body(&self) -> Option<bool> {
        self.is_psb
    }

    /// Returns the optional supervisory authority.
    #[must_use]
    pub const fn supervisory_authority(&self) -> Option<&SupervisoryAuthority> {
        self.supervisory_authority.as_ref()
    }

    /// Returns the registered services.
    #[must_use]
    pub fn services(&self) -> &[WalletRelyingPartyService] {
        &self.services
    }

    /// Returns the registered trade name.
    ///
    /// TS5 v1.6 permits this value to be absent. The legacy accessor returns
    /// an empty string for that case; authorization code should use
    /// [`Self::registered_trade_name`] when absence is significant.
    #[must_use]
    pub fn trade_name(&self) -> &str {
        self.trade_name.as_ref().map_or("", BoundedText::expose)
    }

    /// Returns the registered trade name without collapsing absence.
    #[must_use]
    pub fn registered_trade_name(&self) -> Option<&str> {
        self.trade_name.as_ref().map(BoundedText::expose)
    }

    /// Returns the registry URI.
    #[must_use]
    pub fn registry_uri(&self) -> &str {
        self.registry_uri.expose()
    }

    /// Returns the provider-level policy references.
    #[must_use]
    pub fn policy(&self) -> &[PolicyReference] {
        &self.policy
    }

    /// Returns the optional TS5 provider type discriminator.
    #[must_use]
    pub const fn provider_type(&self) -> Option<i64> {
        self.provider_type
    }

    /// Returns the optional certificate history encoding.
    #[must_use]
    pub fn certificate_history(&self) -> Option<&str> {
        self.x5c.as_ref().map(BoundedText::expose)
    }
}

impl Debug for WalletRelyingParty {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WalletRelyingParty")
            .field("trade_name", &"<redacted>")
            .field("registry_uri", &"<redacted>")
            .field("services", &self.services.len())
            .finish()
    }
}
