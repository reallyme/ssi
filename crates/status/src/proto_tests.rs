// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{status_list_from_proto, status_list_to_proto};
use crate::{
    CredentialStatusError, CredentialStatusInvalidReason, StatusList, StatusListAlgorithm,
    StatusListSignature, StatusPurpose,
};

fn example_list() -> StatusList {
    StatusList {
        issuer: "did:example:issuer".to_owned(),
        purpose: StatusPurpose::Revocation,
        issued_at: 1_700_000_000,
        next_update: 1_700_003_600,
        encoded_list: vec![0_u8; 2],
        length: 16,
        list_id: Some([7_u8; 32]),
        signature: StatusListSignature {
            alg: StatusListAlgorithm::Ed25519,
            sig_bytes: vec![9_u8; 64],
        },
    }
}

#[test]
fn status_list_round_trips_through_generated_message() -> Result<(), CredentialStatusError> {
    let original = example_list();
    let proto = status_list_to_proto(&original)?;
    let decoded = status_list_from_proto(&proto)?;
    assert_eq!(decoded, original);
    Ok(())
}

#[test]
fn status_list_rejects_non_second_timestamp_precision() -> Result<(), CredentialStatusError> {
    let original = example_list();
    let mut proto = status_list_to_proto(&original)?;
    let Some(issued_at) = proto.issued_at.as_option_mut() else {
        return Err(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidTimeWindow,
        ));
    };
    issued_at.nanos = 1;
    assert!(status_list_from_proto(&proto).is_err());
    Ok(())
}
