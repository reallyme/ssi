// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::DidEbsiErrorReason;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn did_ebsi_reason_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(DidEbsiErrorReason::UnsupportedVersion),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_VERSION
    );
}
