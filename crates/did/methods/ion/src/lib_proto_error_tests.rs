// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::DidIonErrorReason;
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn did_ion_reason_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(DidIonErrorReason::UnsupportedNetwork),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_DID_UNSUPPORTED_NETWORK
    );
}
