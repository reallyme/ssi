// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential status-list model and verification policy.
//!
//! This crate owns local status-list checks only. It does not fetch status
//! lists, resolve DIDs, or prescribe OpenID/OAuth transport behavior.

mod error;
mod model;
mod payload;
#[cfg(feature = "proto")]
mod proto;
mod token_status_list;
mod verify;

pub use error::{CredentialStatusError, CredentialStatusInvalidReason};
pub use model::{StatusList, StatusListAlgorithm, StatusListSignature, StatusPurpose};
pub use payload::status_list_signing_payload;
#[cfg(feature = "proto")]
pub use proto::{status_list_from_proto, status_list_to_proto};
pub use token_status_list::{
    build_token_status_list_payload, pack_token_status_values, token_status_value, TokenStatusBits,
    TokenStatusListClaims, TokenStatusListError, TokenStatusListFreshnessPolicy,
    TokenStatusListInvalidReason, TokenStatusListPayload, TokenStatusListProfile,
    VerifiedTokenStatusList, DEFAULT_TOKEN_STATUS_LIST_MAX_AGE_SECS,
    STATUS_LIST_CWT_CONTENT_FORMAT, STATUS_LIST_CWT_MEDIA_TYPE, STATUS_LIST_JWT_MEDIA_TYPE,
    STATUS_LIST_JWT_TYPE,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use token_status_list::{
    issue_token_status_list_cwt, issue_token_status_list_cwt_with_signer,
    issue_token_status_list_jwt, issue_token_status_list_jwt_with_signer,
    verify_token_status_list_cwt, verify_token_status_list_jwt,
};
pub use verify::{
    status_bit, validate_status_list, verify_status, StatusListVerifier, MAX_STATUS_LIST_ENTRIES,
};
