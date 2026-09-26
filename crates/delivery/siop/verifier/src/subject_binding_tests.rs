// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{jwk_thumbprint, ThumbprintMembers};
use crate::SiopVerifierError;

#[test]
fn okp_thumbprint_matches_rfc8037_vector() {
    // RFC 8037 Appendix A.3.
    let thumbprint = jwk_thumbprint(&ThumbprintMembers {
        kty: "OKP",
        crv: "Ed25519",
        x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        y: None,
    })
    .unwrap();
    assert_eq!(thumbprint, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
}

#[test]
fn thumbprint_rejects_inconsistent_key_shapes() {
    let ec_without_y = ThumbprintMembers {
        kty: "EC",
        crv: "P-256",
        x: "x",
        y: None,
    };
    assert!(matches!(
        jwk_thumbprint(&ec_without_y),
        Err(SiopVerifierError::SubjectMismatch)
    ));

    let okp_with_y = ThumbprintMembers {
        kty: "OKP",
        crv: "Ed25519",
        x: "x",
        y: Some("y"),
    };
    assert!(matches!(
        jwk_thumbprint(&okp_with_y),
        Err(SiopVerifierError::SubjectMismatch)
    ));

    let empty_member = ThumbprintMembers {
        kty: "OKP",
        crv: "",
        x: "x",
        y: None,
    };
    assert!(matches!(
        jwk_thumbprint(&empty_member),
        Err(SiopVerifierError::SubjectMismatch)
    ));
}
