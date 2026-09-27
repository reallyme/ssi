// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::DidMeErrorReason;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn did_me_reason_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(DidMeErrorReason::InvalidPrefix),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_INVALID_PREFIX
    );
    assert_eq!(
        IdentityCoreErrorReason::from(DidMeErrorReason::InvalidUpdatePolicy),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_INVALID_UPDATE_POLICY
    );
}
