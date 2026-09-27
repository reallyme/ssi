// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::validate_response_nonce;
use identity_revocation_ocsp_core::OcspError;

#[test]
fn nonce_comparison_rejects_absent_or_different_values() {
    assert_eq!(validate_response_nonce(Some(&[1]), Some(&[1])), Ok(()));
    assert_eq!(
        validate_response_nonce(Some(&[1]), Some(&[2])),
        Err(OcspError::InvalidResponse)
    );
    assert_eq!(
        validate_response_nonce(None, Some(&[1])),
        Err(OcspError::InvalidResponse)
    );
}
