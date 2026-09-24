// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::model::GoogleWalletObject;
use crate::WebDeliveryError;

const MAX_ID_LEN: usize = 256;
const MAX_CLASS_ID_LEN: usize = 256;
const MAX_STATE_LEN: usize = 32;

const MAX_TITLE_LEN: usize = 128;
const MAX_SUBTITLE_LEN: usize = 256;

const MAX_TEXT_MODULES: usize = 20;
const MAX_TEXT_ID_LEN: usize = 64;
const MAX_TEXT_HEADER_LEN: usize = 64;
const MAX_TEXT_BODY_LEN: usize = 1024;

fn non_empty_len_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max
}

/// Validate a Google Wallet object before save-link construction.
pub fn validate_google_wallet_payload(obj: &GoogleWalletObject) -> Result<(), WebDeliveryError> {
    // Required identifiers
    if !non_empty_len_ok(&obj.id, MAX_ID_LEN) || !non_empty_len_ok(&obj.class_id, MAX_CLASS_ID_LEN)
    {
        return Err(WebDeliveryError::InvalidPayload);
    }

    // State must match one of the allowed values.
    if obj.state.len() > MAX_STATE_LEN {
        return Err(WebDeliveryError::InvalidPayload);
    }
    if obj.state != "ACTIVE" && obj.state != "INACTIVE" {
        return Err(WebDeliveryError::InvalidPayload);
    }

    // Header must exist
    if !non_empty_len_ok(&obj.header.title, MAX_TITLE_LEN) {
        return Err(WebDeliveryError::InvalidPayload);
    }
    if let Some(sub) = &obj.header.subtitle {
        if sub.len() > MAX_SUBTITLE_LEN {
            return Err(WebDeliveryError::InvalidPayload);
        }
    }

    // Text modules constraints
    if obj.text_modules.len() > MAX_TEXT_MODULES {
        return Err(WebDeliveryError::InvalidPayload);
    }

    let mut seen = std::collections::HashSet::new();
    for m in &obj.text_modules {
        if !non_empty_len_ok(&m.id, MAX_TEXT_ID_LEN) {
            return Err(WebDeliveryError::InvalidPayload);
        }
        if !seen.insert(&m.id) {
            return Err(WebDeliveryError::InvalidPayload);
        }
        if !non_empty_len_ok(&m.header, MAX_TEXT_HEADER_LEN) {
            return Err(WebDeliveryError::InvalidPayload);
        }
        if !non_empty_len_ok(&m.body, MAX_TEXT_BODY_LEN) {
            return Err(WebDeliveryError::InvalidPayload);
        }
    }

    Ok(())
}
