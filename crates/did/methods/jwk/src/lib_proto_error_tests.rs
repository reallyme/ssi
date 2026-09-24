// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::DidJwkErrorReason;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn did_jwk_reason_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(DidJwkErrorReason::PrivateKeyMaterial),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_PRIVATE_KEY_MATERIAL
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DidJwkErrorReason::SerializationFailed),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_JSON_SERIALIZATION_FAILED
    );
}
