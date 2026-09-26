// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::assign_digest_id;
use crate::MdocEnvelopeError;
use reallyme_crypto::core::{CryptoError, RngFailureKind, RngOutputKind};
use reallyme_crypto::csprng::SecureRandom;
use std::collections::BTreeSet;

struct Fixed {
    fail: bool,
}

impl SecureRandom for Fixed {
    fn fill_secure(&mut self, output: &mut [u8], kind: RngOutputKind) -> Result<(), CryptoError> {
        if self.fail {
            return Err(CryptoError::Rng {
                output: kind,
                kind: RngFailureKind::EntropyUnavailable,
            });
        }
        output.fill(0x42);
        Ok(())
    }
}

#[test]
fn uses_random_ids_and_bounds_collisions() {
    let mut used = BTreeSet::new();
    assert_eq!(
        assign_digest_id(&mut used, &mut Fixed { fail: false }),
        Ok(0x4242_4242_4242_4242)
    );
    assert_eq!(
        assign_digest_id(&mut used, &mut Fixed { fail: false }),
        Err(MdocEnvelopeError::RandomnessUnavailable)
    );
    assert_eq!(
        assign_digest_id(&mut used, &mut Fixed { fail: true }),
        Err(MdocEnvelopeError::RandomnessUnavailable)
    );
}
