// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict TS5 v1.6 data-model projection.
//!
//! Version 1.6 is not wire-compatible with v1.5: service descriptions were
//! flattened, intermediary relationships became cross-registry references,
//! claim paths became JSON arrays, and inherited provider/legal-entity fields
//! changed shape. Keeping a separate raw type prevents accidental acceptance
//! of a hybrid document assembled from both versions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::json::StrictValue;

mod project;
mod validate;

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawWalletRelyingPartyV1_6 {
    country: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identifier: Option<Vec<RawIdentifier>>,
    #[serde(rename = "infoURI", default, skip_serializing_if = "Option::is_none")]
    info_uri: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legal_person: Option<RawLegalPerson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    natural_person: Option<RawNaturalPerson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phone: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    postal_address: Option<Vec<String>>,
    policy: Vec<RawPolicyV1_6>,
    provider_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    x5c: Option<Vec<String>>,
    #[serde(rename = "isPSB")]
    is_psb: bool,
    supervisory_authority: RawSupervisoryAuthority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trade_name: Option<String>,
    #[serde(rename = "registryURI")]
    registry_uri: String,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked_at: Option<String>,
    services: Vec<RawServiceV1_6>,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawServiceV1_6 {
    service_trade_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service_identifier: Option<String>,
    #[serde(
        rename = "supportURI",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    support_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phone: Option<String>,
    #[serde(rename = "srvDescription")]
    service_descriptions: Vec<RawLocalizedTextV1_6>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intended_uses: Option<Vec<RawIntendedUseV1_6>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entitlements: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sub_entitlements: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provides_attestations: Option<Vec<RawProvidedAttestationV1_6>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer_policies: Option<Vec<RawPolicyV1_6>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uses_intermediaries: Option<Vec<RawServiceReference>>,
    is_intermediary: bool,
    #[serde(
        rename = "servedWRPServices",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    served_wrp_services: Option<Vec<RawServiceReference>>,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawIntendedUseV1_6 {
    purpose: Vec<RawLocalizedTextV1_6>,
    privacy_policy: Vec<RawPolicyV1_6>,
    intended_use_identifier: String,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked_at: Option<String>,
    credentials: Vec<RawCredentialV1_6>,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RawLocalizedTextV1_6 {
    lang: String,
    content: String,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawProvidedAttestationV1_6 {
    format: String,
    #[serde(rename = "type")]
    kind: String,
    // The v1.6 prose and JSON Schema use `trustedAuthorities`; the OpenAPI
    // artifact currently says `trustAuthorities`. The data-model spelling is
    // intentionally selected here rather than accepting both silently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trusted_authorities: Option<Vec<RawTrustAuthority>>,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawTrustAuthority {
    framework_type: String,
    value: String,
    #[serde(rename = "isLOTE", default, skip_serializing_if = "Option::is_none")]
    is_lote: Option<bool>,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawServiceReference {
    identifier: Vec<RawIdentifier>,
    service_identifier: String,
    #[serde(rename = "registryURI")]
    registry_uri: String,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RawIdentifier {
    identifier: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawLegalPerson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    established_by_law: Option<Vec<RawLaw>>,
    legal_name: Vec<String>,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawLaw {
    legislative_identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legal_basis: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawNaturalPerson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    date_of_birth: Option<String>,
    family_name: String,
    given_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    place_of_birth: Option<String>,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawSupervisoryAuthority {
    country: String,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<Vec<String>>,
    #[serde(rename = "formURI", default, skip_serializing_if = "Option::is_none")]
    form_uri: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phone: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RawPolicyV1_6 {
    #[serde(rename = "policyURI")]
    policy_uri: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawCredentialV1_6 {
    format: String,
    meta: BTreeMap<String, StrictValue>,
    claims: Vec<RawClaimV1_6>,
}

impl Zeroize for RawCredentialV1_6 {
    fn zeroize(&mut self) {
        self.format.zeroize();
        let metadata = core::mem::take(&mut self.meta);
        for (mut key, mut value) in metadata {
            key.zeroize();
            value.zeroize();
        }
        self.claims.zeroize();
    }
}

impl Drop for RawCredentialV1_6 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RawCredentialV1_6 {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawClaimV1_6 {
    path: Vec<StrictValue>,
}

impl Zeroize for RawClaimV1_6 {
    fn zeroize(&mut self) {
        self.path.zeroize();
    }
}

impl Drop for RawClaimV1_6 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RawClaimV1_6 {}
