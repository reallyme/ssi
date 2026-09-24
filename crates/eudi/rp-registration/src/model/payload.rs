// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{BoundedText, WalletRelyingParty};
use crate::{RegistrationError, RegistrationErrorReason};

/// Semantically validated registry payload.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum RegistryPayload {
    /// One bounded page of WRP records.
    WrpArray {
        /// Authenticated records in the returned page.
        records: Vec<WalletRelyingParty>,
        /// Current-profile pagination metadata, or `None` for an unpaginated
        /// current response and all explicit legacy responses.
        pagination: Option<RegistryPagination>,
    },
    /// One WRP record.
    Wrp(Box<WalletRelyingParty>),
    /// Intended-use registration result.
    IntendedUseCheck {
        /// Whether the requested combination is registered.
        is_registered: bool,
        /// Optional bounded registrar explanation.
        details: Option<BoundedText>,
    },
    /// Legacy raw Boolean response.
    Boolean(bool),
}

/// Validated current-profile pagination state.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RegistryPagination {
    next_cursor: Option<BoundedText>,
    has_next_page: bool,
}

impl RegistryPagination {
    /// Returns the opaque authenticated cursor for the next page.
    #[must_use]
    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_ref().map(BoundedText::expose)
    }

    /// Reports whether the registrar declared another page.
    #[must_use]
    pub const fn has_next_page(&self) -> bool {
        self.has_next_page
    }

    pub(crate) fn try_new(
        next_cursor: Option<&str>,
        has_next_page: bool,
    ) -> Result<Self, RegistrationError> {
        if has_next_page != next_cursor.is_some() {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::SemanticBindingMismatch,
            ));
        }
        Ok(Self {
            next_cursor: next_cursor.map(BoundedText::try_new).transpose()?,
            has_next_page,
        })
    }
}

/// Localized text in a TS5 registration record.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct LocalizedText {
    pub(super) lang: BoundedText,
    pub(super) content: BoundedText,
}

impl LocalizedText {
    /// Returns the BCP 47-style language tag supplied by the registrar.
    #[must_use]
    pub fn language(&self) -> &str {
        self.lang.expose()
    }

    /// Returns the localized content.
    #[must_use]
    pub fn content(&self) -> &str {
        self.content.expose()
    }
}

/// Attestation type provided by a registered WRP service.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct ProvidedAttestation {
    pub(super) format: BoundedText,
    #[serde(rename = "type")]
    pub(super) kind: BoundedText,
}

impl ProvidedAttestation {
    /// Returns the attestation format.
    #[must_use]
    pub fn format(&self) -> &str {
        self.format.expose()
    }

    /// Returns the registered attestation type.
    #[must_use]
    pub fn kind(&self) -> &str {
        self.kind.expose()
    }
}

/// Public-sector supervisory authority contact data.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct SupervisoryAuthority {
    pub(super) country: BoundedText,
    pub(super) name: BoundedText,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) email: Vec<BoundedText>,
    #[serde(rename = "formURI", default, skip_serializing_if = "Vec::is_empty")]
    pub(super) form_uri: Vec<BoundedText>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) phone: Vec<BoundedText>,
}

impl SupervisoryAuthority {
    /// Returns the authority country identifier.
    #[must_use]
    pub fn country(&self) -> &str {
        self.country.expose()
    }

    /// Returns the authority name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.expose()
    }

    /// Returns registered email addresses.
    #[must_use]
    pub fn email(&self) -> &[BoundedText] {
        &self.email
    }

    /// Returns registered contact-form URIs.
    #[must_use]
    pub fn form_uri(&self) -> &[BoundedText] {
        &self.form_uri
    }

    /// Returns registered telephone numbers.
    #[must_use]
    pub fn phone(&self) -> &[BoundedText] {
        &self.phone
    }
}

/// Typed registration policy reference.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct PolicyReference {
    #[serde(rename = "policyURI")]
    pub(super) policy_uri: BoundedText,
    #[serde(rename = "type")]
    pub(super) kind: BoundedText,
}

impl PolicyReference {
    /// Returns the policy URI.
    #[must_use]
    pub fn policy_uri(&self) -> &str {
        self.policy_uri.expose()
    }

    /// Returns the registered policy type.
    #[must_use]
    pub fn kind(&self) -> &str {
        self.kind.expose()
    }
}

/// Validated JSON claim path from a registered credential request.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct ClaimPath {
    pub(super) path: BoundedText,
}

impl ClaimPath {
    /// Returns the exact validated JSON claim-path string.
    #[must_use]
    pub fn path(&self) -> &str {
        self.path.expose()
    }
}

/// Closed format-specific credential metadata.
#[derive(Serialize, ZeroizeOnDrop)]
#[serde(untagged)]
pub enum CredentialMetadata {
    /// SD-JWT VC type identifiers.
    DcSdJwt(DcSdJwtMetadata),
    /// ISO mdoc document type.
    MsoMdoc(MsoMdocMetadata),
}

/// Strict `dc+sd-jwt` credential metadata.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct DcSdJwtMetadata {
    pub(super) vct_values: Vec<BoundedText>,
}

impl DcSdJwtMetadata {
    /// Returns the accepted verifiable credential type identifiers.
    #[must_use]
    pub fn vct_values(&self) -> &[BoundedText] {
        &self.vct_values
    }
}

/// Strict `mso_mdoc` credential metadata.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct MsoMdocMetadata {
    pub(super) doctype_value: BoundedText,
}

impl MsoMdocMetadata {
    /// Returns the accepted document type.
    #[must_use]
    pub fn doctype_value(&self) -> &str {
        self.doctype_value.expose()
    }
}

impl Zeroize for CredentialMetadata {
    fn zeroize(&mut self) {
        match self {
            Self::DcSdJwt(value) => value.zeroize(),
            Self::MsoMdoc(value) => value.zeroize(),
        }
    }
}
