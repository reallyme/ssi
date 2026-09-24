// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::DidApiError;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn did_api_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(DidApiError::UnsupportedDidMethod),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_METHOD
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DidApiError::ProtoDecodeFailed),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_INVALID_ENCODING
    );
}
