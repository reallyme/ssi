// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{BoundedText, CredentialRequest, LocalizedText, PolicyReference};

/// Strict TS5 intended-use record.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct IntendedUse {
    pub(super) purpose: Vec<LocalizedText>,
    pub(super) privacy_policy: Vec<PolicyReference>,
    pub(super) intended_use_identifier: BoundedText,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) created_at: Option<BoundedText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) revoked_at: Option<BoundedText>,
    pub(super) credentials: Vec<CredentialRequest>,
}

impl IntendedUse {
    /// Returns the localized purpose statements.
    #[must_use]
    pub fn purpose(&self) -> &[LocalizedText] {
        &self.purpose
    }

    /// Returns the registered privacy-policy references.
    #[must_use]
    pub fn privacy_policy(&self) -> &[PolicyReference] {
        &self.privacy_policy
    }

    /// Returns the registrar-assigned intended-use identifier.
    #[must_use]
    pub fn intended_use_identifier(&self) -> &str {
        self.intended_use_identifier.expose()
    }

    /// Returns the registrar-provided creation timestamp, when present.
    #[must_use]
    pub fn created_at(&self) -> Option<&str> {
        self.created_at.as_ref().map(BoundedText::expose)
    }

    /// Returns the registrar-provided revocation timestamp, when present.
    #[must_use]
    pub fn revoked_at(&self) -> Option<&str> {
        self.revoked_at.as_ref().map(BoundedText::expose)
    }

    /// Returns the validated credential request set.
    #[must_use]
    pub fn credentials(&self) -> &[CredentialRequest] {
        &self.credentials
    }
}
