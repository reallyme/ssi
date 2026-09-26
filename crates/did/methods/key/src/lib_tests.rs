// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    base58_encode, did_key_url, generate_did_key, parse_did_key, DidKeyErrorReason,
    DidKeyMultibase, DidKeyMulticodec,
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
fn did_key_rejects_base64url_multibase_alias() {
    // Same X25519 key as a `u` (base64url) multibase: not allowed by the did:key ABNF.
    let err = parse_did_key("did:key:u7AFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB")
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidKeyErrorReason::UnsupportedMultibase));
}

#[test]
fn did_key_rejects_non_minimal_multicodec_varint() -> Result<(), Box<dyn std::error::Error>> {
    // 0xed encoded minimally is [0xed, 0x01]; [0xed, 0x81, 0x00] is a non-minimal alias.
    let mut bytes = vec![0xed, 0x81, 0x00];
    bytes.extend_from_slice(&[0x42u8; 32]);
    let did = format!("did:key:z{}", base58_encode(&bytes)?);
    let err = parse_did_key(&did).err().map(|error| error.reason);
    assert_eq!(err, Some(DidKeyErrorReason::InvalidVarint));
    Ok(())
}

#[test]
fn did_key_rejects_oversized_identifier_before_decoding() {
    let did = format!("did:key:z{}", "2".repeat(10_000));
    let err = parse_did_key(&did).err().map(|error| error.reason);
    assert_eq!(err, Some(DidKeyErrorReason::IdentifierTooLong));
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
