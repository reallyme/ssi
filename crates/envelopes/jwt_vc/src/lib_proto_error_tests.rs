// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{IdentityCoreErrorReason, JwtVcEnvelopeError};

#[test]
fn jwt_vc_envelope_errors_map_to_stable_proto_reasons() {
    let cases = [
            (
                JwtVcEnvelopeError::InvalidInput,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_JWT_VC_ENVELOPE_INVALID_INPUT,
            ),
            (
                JwtVcEnvelopeError::InvalidPayload,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_JWT_VC_ENVELOPE_INVALID_PAYLOAD,
            ),
            (
                JwtVcEnvelopeError::InvalidCredentialEncoding,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_JWT_VC_ENVELOPE_INVALID_CREDENTIAL_ENCODING,
            ),
            (
                JwtVcEnvelopeError::Jwt,
                IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_JWT_VC_ENVELOPE_JWT,
            ),
        ];

    for (error, expected) in cases {
        assert_eq!(IdentityCoreErrorReason::from(error), expected);
    }
}
