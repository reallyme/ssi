// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! IETF OAuth Token Status List draft-21 JWT and CWT claim profile.

mod compress;
#[cfg(any(feature = "native", feature = "wasm"))]
mod cwt;
#[cfg(any(feature = "native", feature = "wasm"))]
mod issue_jwt;
mod model;
#[cfg(any(feature = "native", feature = "wasm"))]
mod verify_jwt;

pub use compress::{build_token_status_list_payload, pack_token_status_values, token_status_value};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use cwt::{
    issue_token_status_list_cwt, issue_token_status_list_cwt_with_signer,
    verify_token_status_list_cwt,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use issue_jwt::{issue_token_status_list_jwt, issue_token_status_list_jwt_with_signer};
pub use model::{
    TokenStatusBits, TokenStatusListClaims, TokenStatusListError, TokenStatusListInvalidReason,
    TokenStatusListPayload, TokenStatusListProfile, VerifiedTokenStatusList,
    STATUS_LIST_CWT_CONTENT_FORMAT, STATUS_LIST_CWT_MEDIA_TYPE, STATUS_LIST_JWT_MEDIA_TYPE,
    STATUS_LIST_JWT_TYPE,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use verify_jwt::verify_token_status_list_jwt;
