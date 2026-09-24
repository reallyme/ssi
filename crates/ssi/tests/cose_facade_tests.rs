// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
//! Test coverage for this crate.

use reallyme_crypto::dispatch::generate_keypair;
use reallyme_ssi::compression::brotli::{brotli_compress, brotli_decompress};
use reallyme_ssi::cose::{cose_sign1, cose_verify1, Algorithm};
use reallyme_ssi::jose::jws::suites::es256::{sign_es256_jws, verify_es256_jws};

#[test]
fn reallyme_cose_facade_roundtrips_sign1() {
    let (public, private) = generate_keypair(Algorithm::Ed25519).unwrap();
    let kid = b"facade-key";
    let payload = b"facade payload";
    let cose = cose_sign1(Algorithm::Ed25519, payload, &private, Some(kid)).unwrap();

    let verified = cose_verify1(&cose, |algorithm, requested| {
        if algorithm == Algorithm::Ed25519 && requested == kid {
            Some(public.clone())
        } else {
            None
        }
    })
    .unwrap();

    assert_eq!(verified.as_slice(), payload);
}

#[test]
fn reallyme_jose_facade_roundtrips_es256_jws() {
    let (public, private) = generate_keypair(Algorithm::P256).unwrap();
    let payload = "cid:example:facade";

    let jws = sign_es256_jws(&private, payload).unwrap();

    verify_es256_jws(&jws, &public).unwrap();
}

#[test]
fn reallyme_compression_facade_roundtrips_brotli() {
    let payload = b"identity envelope payload identity envelope payload";

    let compressed = brotli_compress(payload).unwrap();
    let decompressed = brotli_decompress(&compressed).unwrap();

    assert_eq!(decompressed, payload);
}
