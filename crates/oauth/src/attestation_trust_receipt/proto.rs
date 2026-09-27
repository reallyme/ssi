// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_ssi_proto::generated::proto::identity::trust::v1 as trust_pb;
use reallyme_trust_core::CertificateStatus;

use crate::{OauthError, OauthResult, Reason};

pub(super) fn certificate_status_to_proto(
    status: CertificateStatus,
) -> OauthResult<trust_pb::CertificateStatus> {
    Ok(match status {
        CertificateStatus::Good => trust_pb::CertificateStatus::CERTIFICATE_STATUS_GOOD,
        CertificateStatus::Revoked => trust_pb::CertificateStatus::CERTIFICATE_STATUS_REVOKED,
        CertificateStatus::Suspended => trust_pb::CertificateStatus::CERTIFICATE_STATUS_SUSPENDED,
        CertificateStatus::Unknown => trust_pb::CertificateStatus::CERTIFICATE_STATUS_UNKNOWN,
        CertificateStatus::Unavailable => {
            trust_pb::CertificateStatus::CERTIFICATE_STATUS_UNAVAILABLE
        }
        CertificateStatus::Stale => trust_pb::CertificateStatus::CERTIFICATE_STATUS_STALE,
        CertificateStatus::NotYetValid => {
            trust_pb::CertificateStatus::CERTIFICATE_STATUS_NOT_YET_VALID
        }
        CertificateStatus::Malformed => trust_pb::CertificateStatus::CERTIFICATE_STATUS_MALFORMED,
        CertificateStatus::InvalidSignature => {
            trust_pb::CertificateStatus::CERTIFICATE_STATUS_INVALID_SIGNATURE
        }
        CertificateStatus::Unsupported => {
            trust_pb::CertificateStatus::CERTIFICATE_STATUS_UNSUPPORTED
        }
        CertificateStatus::Exempt => trust_pb::CertificateStatus::CERTIFICATE_STATUS_EXEMPT,
        _ => return Err(OauthError::new(Reason::InvalidAttestationReceipt)),
    })
}
