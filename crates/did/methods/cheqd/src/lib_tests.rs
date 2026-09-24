// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    effective_namespace, generate_did_cheqd, parse_did_cheqd, CheqdIdentifierKind,
    DidCheqdErrorReason,
};

#[test]
fn published_cheqd_uuid_vectors_parse() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            "did:cheqd:mainnet:de9786cd-ec53-458c-857c-9342cf264f80",
            Some("mainnet"),
            "de9786cd-ec53-458c-857c-9342cf264f80",
        ),
        (
            "did:cheqd:de9786cd-ec53-458c-857c-9342cf264f80",
            None,
            "de9786cd-ec53-458c-857c-9342cf264f80",
        ),
    ];

    for (did, namespace, unique_id) in cases {
        let parsed = parse_did_cheqd(did)?;
        assert_eq!(parsed.namespace, namespace);
        assert_eq!(parsed.unique_id, unique_id);
        assert_eq!(parsed.kind, CheqdIdentifierKind::Uuid);
        assert_eq!(generate_did_cheqd(parsed.namespace, parsed.unique_id)?, did);
    }
    Ok(())
}

#[test]
fn published_cheqd_indy_style_vectors_parse() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        ("did:cheqd:mainnet:TAwT8WVt3dz2DBAifwuSkn", Some("mainnet")),
        ("did:cheqd:testnet:TAwT8WVt3dz2DBAifwuSkn", Some("testnet")),
        ("did:cheqd:TAwT8WVt3dz2DBAifwuSkn", None),
    ];

    for (did, namespace) in cases {
        let parsed = parse_did_cheqd(did)?;
        assert_eq!(parsed.namespace, namespace);
        assert_eq!(parsed.unique_id, "TAwT8WVt3dz2DBAifwuSkn");
        assert_eq!(parsed.kind, CheqdIdentifierKind::IndyStyle);
        assert_eq!(generate_did_cheqd(parsed.namespace, parsed.unique_id)?, did);
    }
    Ok(())
}

#[test]
fn omitted_namespace_defaults_to_mainnet() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        effective_namespace("did:cheqd:de9786cd-ec53-458c-857c-9342cf264f80")?,
        "mainnet"
    );
    Ok(())
}

#[test]
fn did_cheqd_rejects_namespace_with_hyphen() {
    let err = parse_did_cheqd("did:cheqd:test-net:TAwT8WVt3dz2DBAifwuSkn")
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidCheqdErrorReason::InvalidNamespace));
}

#[test]
fn did_cheqd_rejects_malformed_uuid() {
    let err = parse_did_cheqd("did:cheqd:mainnet:de9786cd-ec53-458c-857c-9342cf264f8x")
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidCheqdErrorReason::InvalidUniqueIdentifier));
}
