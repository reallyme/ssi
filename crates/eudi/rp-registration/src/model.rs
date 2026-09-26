// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt::{Debug, Formatter};

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::json::deserialize_strict;
use crate::{RegistrationError, RegistrationErrorReason};

mod payload;
mod protocol;
mod raw;
mod validation;

pub use payload::{
    ClaimPath, CredentialMetadata, DcSdJwtMetadata, LocalizedText, MsoMdocMetadata,
    PolicyReference, ProvidedAttestation, RegistryPagination, RegistryPayload,
    SupervisoryAuthority,
};
pub use protocol::{ProtocolProfile, RegistryPayloadShape, WrpEntitlement};
pub(crate) use raw::RawWalletRelyingParty;

const MAX_TEXT_BYTES: usize = 2_048;

/// Bounded UTF-8 protocol text with redacted diagnostics and drop zeroization.
#[derive(Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct BoundedText(String);

impl BoundedText {
    /// Copies a non-empty, NUL-free bounded string.
    pub fn try_new(value: &str) -> Result<Self, RegistrationError> {
        validate_text(value, MAX_TEXT_BYTES)?;
        Ok(Self(value.to_owned()))
    }

    /// Validates an owned string and transfers its allocation without leaving
    /// an unzeroized intermediate copy behind.
    fn try_from_owned(value: String) -> Result<Self, RegistrationError> {
        let mut value = Zeroizing::new(value);
        validate_text(&value, MAX_TEXT_BYTES)?;
        Ok(Self(core::mem::take(&mut *value)))
    }

    /// Borrows the validated text.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Debug for BoundedText {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BoundedText(<redacted>)")
    }
}

/// Strict TS5 credential request.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    format: BoundedText,
    meta: CredentialMetadata,
    claims: Vec<ClaimPath>,
}

impl CredentialRequest {
    pub(crate) fn try_new(
        format: String,
        meta: std::collections::BTreeMap<String, crate::json::StrictValue>,
        claims: Vec<String>,
    ) -> Result<Self, RegistrationError> {
        validation::validate_items(&claims, true)?;
        let meta = validation::validate_metadata(meta)?;
        let format = BoundedText::try_from_owned(format)?;
        let metadata_matches_format = matches!(
            (format.expose(), &meta),
            ("dc+sd-jwt", CredentialMetadata::DcSdJwt(_))
                | ("mso_mdoc", CredentialMetadata::MsoMdoc(_))
        );
        if !metadata_matches_format {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::SemanticBindingMismatch,
            ));
        }
        let claims = claims
            .into_iter()
            .map(|path| {
                validation::validate_claim_path(&path)?;
                Ok(ClaimPath {
                    path: BoundedText::try_from_owned(path)?,
                })
            })
            .collect::<Result<Vec<_>, RegistrationError>>()?;
        let has_duplicate_claim = claims.iter().enumerate().any(|(index, claim)| {
            claims
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| other.path() == claim.path())
        });
        if has_duplicate_claim {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InvalidField,
            ));
        }
        Ok(Self {
            format,
            meta,
            claims,
        })
    }

    /// Returns the registered credential format.
    #[must_use]
    pub fn format(&self) -> &str {
        self.format.expose()
    }

    /// Returns the format-specific registered metadata.
    #[must_use]
    pub const fn metadata(&self) -> &CredentialMetadata {
        &self.meta
    }

    /// Returns the requested claim paths.
    #[must_use]
    pub fn claims(&self) -> &[ClaimPath] {
        &self.claims
    }

    pub(crate) fn authorizes(&self, requested: &Self) -> bool {
        if self.format() != requested.format() {
            return false;
        }
        let metadata_authorized = match (&self.meta, &requested.meta) {
            (CredentialMetadata::DcSdJwt(registered), CredentialMetadata::DcSdJwt(requested)) => {
                requested.vct_values.iter().all(|requested_value| {
                    registered.vct_values.iter().any(|registered_value| {
                        registered_value.expose() == requested_value.expose()
                    })
                })
            }
            (CredentialMetadata::MsoMdoc(registered), CredentialMetadata::MsoMdoc(requested)) => {
                registered.doctype_value.expose() == requested.doctype_value.expose()
            }
            _ => false,
        };
        metadata_authorized
            && requested.claims.iter().all(|requested_claim| {
                self.claims
                    .iter()
                    .any(|registered_claim| registered_claim.path() == requested_claim.path())
            })
    }
}

/// Strict TS5 intended-use record.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct IntendedUse {
    purpose: Vec<LocalizedText>,
    privacy_policy: Vec<PolicyReference>,
    intended_use_identifier: BoundedText,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<BoundedText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<BoundedText>,
    credentials: Vec<CredentialRequest>,
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

/// Strict TS5 `WalletRelyingPartyService` representation.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct WalletRelyingPartyService {
    service_trade_name: BoundedText,
    service_identifier: BoundedText,
    #[serde(rename = "supportURI", skip_serializing_if = "Option::is_none")]
    support_uri: Option<BoundedText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<BoundedText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<BoundedText>,
    #[serde(
        rename = "srvDescription",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    service_descriptions: Vec<Vec<LocalizedText>>,
    intended_uses: Vec<IntendedUse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    entitlements: Vec<WrpEntitlement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sub_entitlements: Vec<BoundedText>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    provides_attestations: Vec<ProvidedAttestation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    uses_intermediaries: Vec<WalletRelyingPartyService>,
    #[serde(default, skip_serializing_if = "is_false")]
    is_intermediary: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    served_wrp_services: Vec<BoundedText>,
}

impl WalletRelyingPartyService {
    /// Returns the user-facing service trade name.
    #[must_use]
    pub fn service_trade_name(&self) -> &str {
        self.service_trade_name.expose()
    }

    /// Returns the service identifier authenticated by the registrar.
    #[must_use]
    pub fn service_identifier(&self) -> &str {
        self.service_identifier.expose()
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
}

/// Strict TS5 Wallet Relying Party record.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct WalletRelyingParty {
    #[serde(rename = "isPSB", skip_serializing_if = "Option::is_none")]
    is_psb: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supervisory_authority: Option<SupervisoryAuthority>,
    trade_name: BoundedText,
    #[serde(rename = "registryURI")]
    registry_uri: BoundedText,
    services: Vec<WalletRelyingPartyService>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    policy: Vec<PolicyReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_type: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x5c: Option<BoundedText>,
}

impl WalletRelyingParty {
    /// Parses one strict WRP object, rejecting duplicates and unknown members.
    pub fn from_json(input: &[u8]) -> Result<Self, RegistrationError> {
        let raw: RawWalletRelyingParty = deserialize_strict(input)?;
        raw.validate()
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
    #[must_use]
    pub fn trade_name(&self) -> &str {
        self.trade_name.expose()
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

fn validate_text(value: &str, limit: usize) -> Result<(), RegistrationError> {
    if value.is_empty() || value.len() > limit || value.bytes().any(|byte| byte == 0) {
        return Err(RegistrationError::from_reason(
            RegistrationErrorReason::InvalidField,
        ));
    }
    Ok(())
}

const fn is_false(value: &bool) -> bool {
    !*value
}
