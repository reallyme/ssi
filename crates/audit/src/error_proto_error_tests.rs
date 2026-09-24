// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{QeaaComplianceError, QeaaField, QeaaInvalidReason};
use reallyme_ssi_proto::generated::proto::reallyme::identity_core::v1::IdentityCoreErrorReason;

#[test]
fn qeaa_invalid_reason_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(QeaaInvalidReason::UnsupportedStatusMethod),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_QEAA_UNSUPPORTED_STATUS_METHOD
    );
    assert_eq!(
        IdentityCoreErrorReason::from(QeaaInvalidReason::FieldTooLarge(QeaaField::PolicyId)),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_QEAA_FIELD_TOO_LARGE
    );
}

#[test]
fn qeaa_error_maps_to_identity_core_proto_reason() {
    assert_eq!(
        IdentityCoreErrorReason::from(QeaaComplianceError::InvalidInput(
            QeaaInvalidReason::InvalidAuditPeriod
        )),
        IdentityCoreErrorReason::IDENTITY_CORE_ERROR_REASON_QEAA_INVALID_AUDIT_PERIOD
    );
}
