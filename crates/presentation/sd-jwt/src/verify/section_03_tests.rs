// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{jwk_for_public_key_for_jwt_alg, CredentialAlgorithm, SdJwtVpError};

#[test]
fn kb_jwt_algorithm_must_match_the_authenticated_envelope_key() {
    // The compact token's header declares EdDSA. Signature validity is
    // deliberately irrelevant here: algorithm/key binding is checked before
    // the JOSE verifier is invoked.
    let token = "eyJhbGciOiJFZERTQSJ9.e30.AA";

    let error =
        jwk_for_public_key_for_jwt_alg(token, &[2_u8; 33], CredentialAlgorithm::P256).err();

    assert!(matches!(error, Some(SdJwtVpError::Crypto)));
}
