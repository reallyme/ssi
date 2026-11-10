// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{BoundedText, ClaimPath, CredentialMetadata};
use crate::json::deserialize_strict;
use crate::{RegistrationError, RegistrationErrorReason};

const MAX_CREDENTIAL_REQUEST_JSON_BYTES: usize = 64 * 1_024;

/// Strict TS5 credential request.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    format: BoundedText,
    meta: CredentialMetadata,
    claims: Vec<ClaimPath>,
}

impl CredentialRequest {
    /// Parse one bounded TS5 credential request with the same rules used for
    /// signed WRPRC and registrar records.
    ///
    /// This is for comparing a protocol request with authenticated registration
    /// scope. Parsing alone does not establish that the request is authorized.
    pub fn from_json(input: &[u8]) -> Result<Self, RegistrationError> {
        if input.is_empty() || input.len() > MAX_CREDENTIAL_REQUEST_JSON_BYTES {
            return Err(RegistrationError::from_reason(
                RegistrationErrorReason::InputTooLarge,
            ));
        }
        let raw: super::raw::RawCredential = deserialize_strict(input)?;
        raw.validate()
    }

    /// Check whether this authenticated registration entry covers every
    /// format, metadata value, and claim path of a validated request.
    #[must_use]
    pub fn authorizes_requested(&self, requested: &Self) -> bool {
        self.authorizes(requested)
    }

    pub(crate) fn try_new(
        format: String,
        meta: std::collections::BTreeMap<String, crate::json::StrictValue>,
        claims: Vec<String>,
    ) -> Result<Self, RegistrationError> {
        super::validation::validate_items(&claims, true)?;
        let meta = super::validation::validate_metadata(meta)?;
        Self::try_new_with_metadata(format, meta, claims)
    }

    pub(crate) fn try_new_with_metadata(
        format: String,
        meta: CredentialMetadata,
        claims: Vec<String>,
    ) -> Result<Self, RegistrationError> {
        super::validation::validate_items(&claims, true)?;
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
                super::validation::validate_claim_path(&path)?;
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

#[cfg(test)]
#[path = "credential_request_tests.rs"]
mod credential_request_tests;
