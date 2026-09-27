// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Custom cryptosuite identifier.
pub const CRYPTOSUITE: &str = "es256-jws-cid-2025";

pub(super) fn proof_payload(
    current_core: &str,
    created: &str,
) -> Result<Vec<u8>, super::Es256JwsCid2025Error> {
    if current_core.is_empty() || created.is_empty() {
        return Err(super::Es256JwsCid2025Error::InvalidInput);
    }
    serde_json::to_vec(&(current_core, created))
        .map_err(|_| super::Es256JwsCid2025Error::InvalidInput)
}
