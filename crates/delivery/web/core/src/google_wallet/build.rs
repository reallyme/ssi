// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::model::{GoogleWalletObject, Header};
use crate::WebDeliveryError;

/// Build a minimal active Google Wallet generic object.
pub fn build_generic_object(
    id: impl Into<String>,
    class_id: impl Into<String>,
    title: impl Into<String>,
) -> Result<GoogleWalletObject, WebDeliveryError> {
    let id = id.into().trim().to_string();
    let class_id = class_id.into().trim().to_string();
    let title = title.into().trim().to_string();

    if id.is_empty() || class_id.is_empty() || title.is_empty() {
        return Err(WebDeliveryError::InvalidPayload);
    }

    Ok(GoogleWalletObject {
        id,
        class_id,
        state: "ACTIVE".into(),
        header: Header {
            title,
            subtitle: None,
        },
        text_modules: Vec::new(),
    })
}
