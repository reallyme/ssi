// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::Cell;

struct StatefulStatusVerifier {
    verified: Cell<bool>,
}

impl StatusListVerifier for StatefulStatusVerifier {
    fn verify_status_list(
        &self,
        issuer: &str,
        alg: StatusListAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        TestStatusVerifier.verify_status_list(issuer, alg, payload, signature)?;
        self.verified.set(true);
        Ok(())
    }
}

impl reallyme_credential::CredentialStatusListVerifier for StatefulStatusVerifier {
    fn verified_signer(&self) -> PartyReference {
        if self.verified.get() {
            PartyReference::Did("did:web:issuer.example".to_owned())
        } else {
            PartyReference::Did("did:web:stale.example".to_owned())
        }
    }
}

#[test]
fn credential_status_reads_authenticated_signer_after_signature_verification() {
    let envelope = sample_envelope(CredentialKind::Pid);
    let status_list = sample_status_list(vec![0]);
    let verifier = StatefulStatusVerifier {
        verified: Cell::new(false),
    };

    reallyme_credential::verify_credential_status(
        &envelope,
        &status_list,
        1_750_000_000,
        &verifier,
    )
    .unwrap();

    assert!(verifier.verified.get());
}
