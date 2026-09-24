// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{validate_party_reference, PartyReferenceContext};
use crate::{CredentialError, CredentialInvalidReason, PartyReference};

#[test]
fn absent_reference_is_limited_to_the_credential_subject_identifier() {
    assert_eq!(
        validate_party_reference(&PartyReference::Absent, PartyReferenceContext::Issuer),
        Err(CredentialError::InvalidInput(
            CredentialInvalidReason::InvalidIssuerId,
        )),
    );
    assert!(validate_party_reference(
        &PartyReference::Absent,
        PartyReferenceContext::CredentialSubject,
    )
    .is_ok());
}
