// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Regression coverage for authenticated EU trusted-list snapshots.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::path::PathBuf;

use identity_trust_tsl_core::parse_tsl_xml;

#[test]
fn projects_every_authenticated_eu_snapshot_document() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/live-v6/corpus");
    let manifest = include_str!("fixtures/live-v6/corpus-manifest.tsv");
    let mut failures = Vec::new();
    let mut document_count = 0_usize;
    for line in manifest.lines().filter(|line| !line.starts_with('#')) {
        let columns = line.split('\t').collect::<Vec<_>>();
        assert_eq!(columns.len(), 3, "invalid corpus manifest row");
        let territory = columns[0];
        let expected_sha256 = columns[1];
        let name = if territory == "EU" {
            "eu-lotl.xml".to_owned()
        } else {
            format!("{territory}.xml")
        };
        let path = corpus.join(&name);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("snapshot {name} must be readable: {error}"));
        let digest = reallyme_crypto::sha2::digest(&bytes);
        let actual_sha256 = digest
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual_sha256, expected_sha256, "snapshot hash: {name}");
        match std::str::from_utf8(&bytes) {
            Ok(xml) => {
                if let Err(error) = parse_tsl_xml(xml) {
                    failures.push((name, error));
                }
            }
            Err(error) => panic!("snapshot {name} must be UTF-8: {error}"),
        }
        document_count = document_count
            .checked_add(1)
            .expect("bounded fixture count");
    }
    assert_eq!(document_count, 30);
    assert!(
        failures.is_empty(),
        "snapshot projection failures: {failures:?}"
    );
}
