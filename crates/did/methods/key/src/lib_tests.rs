// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    did_key_url, generate_did_key, parse_did_key, DidKeyErrorReason, DidKeyMultibase,
    DidKeyMulticodec,
};

#[test]
fn published_ed25519_did_key_vector_decodes_and_regenerates(
) -> Result<(), Box<dyn std::error::Error>> {
    let did = "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP";
    let parsed = parse_did_key(did)?;

    assert_eq!(parsed.multibase, DidKeyMultibase::Base58Btc);
    assert_eq!(parsed.multicodec, DidKeyMulticodec::Ed25519);
    assert_eq!(parsed.public_key.len(), 32);
    assert_eq!(
        generate_did_key(parsed.multicodec, &parsed.public_key, parsed.multibase)?,
        did
    );
    assert_eq!(
            did_key_url(did)?,
            "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP#z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"
        );
    Ok(())
}

#[test]
fn published_did_key_vectors_decode_expected_multicodecs() -> Result<(), Box<dyn std::error::Error>>
{
    let cases = [
        (
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            DidKeyMulticodec::Secp256k1,
            33usize,
        ),
        (
            "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
            DidKeyMulticodec::P256,
            33usize,
        ),
        (
            "did:key:z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54",
            DidKeyMulticodec::P384,
            49usize,
        ),
    ];

    for (did, codec, len) in cases {
        let parsed = parse_did_key(did)?;
        assert_eq!(parsed.multicodec, codec);
        assert_eq!(parsed.public_key.len(), len);
        assert_eq!(
            generate_did_key(parsed.multicodec, &parsed.public_key, parsed.multibase)?,
            did
        );
    }
    Ok(())
}

#[test]
fn base64url_did_key_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let public_key = [0x41u8; 32];
    let did = generate_did_key(
        DidKeyMulticodec::X25519,
        &public_key,
        DidKeyMultibase::Base64Url,
    )?;

    assert!(did.starts_with("did:key:u"));
    assert!(!did.contains('='));
    let parsed = parse_did_key(&did)?;
    assert_eq!(parsed.multicodec, DidKeyMulticodec::X25519);
    assert_eq!(parsed.public_key, public_key);
    Ok(())
}

#[test]
fn did_key_rejects_invalid_public_key_length() {
    let err = generate_did_key(
        DidKeyMulticodec::Ed25519,
        &[0x22u8; 31],
        DidKeyMultibase::Base58Btc,
    )
    .err()
    .map(|error| error.reason);
    assert_eq!(err, Some(DidKeyErrorReason::InvalidPublicKeyLength));
}

#[test]
fn did_key_rejects_unsupported_multibase_prefix() {
    let err = parse_did_key("did:key:mabc")
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidKeyErrorReason::UnsupportedMultibase));
}
