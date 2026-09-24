// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Package-owned recursive cleanup for generated status-list messages.

use crate::generated::proto::identity::status::v1 as pb;
use zeroize::Zeroize;

/// Recursively clear identifying status-list fields and signature bytes.
pub fn zeroize_status_list(list: &mut pb::StatusList) {
    list.issuer_did.zeroize();
    list.purpose = Default::default();
    if let Some(issued_at) = list.issued_at.as_option_mut() {
        issued_at.seconds.zeroize();
        issued_at.nanos.zeroize();
        issued_at.__buffa_unknown_fields.clear();
    }
    list.issued_at = Default::default();
    if let Some(next_update) = list.next_update.as_option_mut() {
        next_update.seconds.zeroize();
        next_update.nanos.zeroize();
        next_update.__buffa_unknown_fields.clear();
    }
    list.next_update = Default::default();
    list.encoded_list.zeroize();
    list.length.zeroize();
    list.list_id.zeroize();
    if let Some(signature) = list.signature.as_option_mut() {
        signature.alg = Default::default();
        signature.sig_bytes.zeroize();
        signature.__buffa_unknown_fields.clear();
    }
    list.signature = Default::default();
    list.__buffa_unknown_fields.clear();
}

#[cfg(test)]
#[path = "zeroize_status_tests.rs"]
mod tests;
