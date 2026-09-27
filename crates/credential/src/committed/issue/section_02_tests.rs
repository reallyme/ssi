// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::jcs_utf8_bytes;

#[test]
fn claim_values_use_rfc8785_number_and_utf16_key_ordering() {
    let value = serde_json::json!({
        "\u{1f600}": 333_333_333.333_333_3,
        "\u{fffd}": true
    });

    let canonical = jcs_utf8_bytes(&value);
    assert!(canonical.is_ok());
    if let Ok(canonical) = canonical {
        assert_eq!(
            canonical,
            "{\"😀\":333333333.3333333,\"�\":true}".as_bytes()
        );
    }
}
