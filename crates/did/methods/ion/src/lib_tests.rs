// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    generate_did_ion, generate_long_form_did_ion, parse_did_ion, short_form_did_ion,
    DidIonErrorReason, IonNetwork,
};

const SIDETREE_SUFFIX: &str = "EiCxAP7PtUg7HKSX0H3Refli8XIyD-_PI9y-iuxhh8sx9g";
const ION_TESTNET3_SUFFIX: &str = "EiD0x0JeWXQbVIpBpyeyF5FDdZN1U7enAfHnd13Qk_CYpQ";
const LONG_FORM_SUFFIX_DATA: &str = "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnt9fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUFwazZianZxRUJ4eDBjckdlaHpDUHA4akxDWFpXeXJIczRDWjlPcXktanpnIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBNjQtYngyZU9kMDBJZXE4cHA5TnJYejRBYmdDMk5idjl0Mk51UVdXNmh3dyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQXBrNmJqdnFFQnh4MGNyR2VoekNQcDhqTENYWld5ckhzNENaOU9xeS1qemcifX0";

#[test]
fn published_ion_testnet3_example_parses() -> Result<(), Box<dyn std::error::Error>> {
    let did = "did:ion:testnet3:EiD0x0JeWXQbVIpBpyeyF5FDdZN1U7enAfHnd13Qk_CYpQ";
    let parsed = parse_did_ion(did)?;

    assert_eq!(parsed.network, IonNetwork::Testnet3);
    assert_eq!(parsed.did_suffix, ION_TESTNET3_SUFFIX);
    assert_eq!(parsed.long_form_suffix_data, None);
    assert_eq!(generate_did_ion(parsed.network, parsed.did_suffix)?, did);
    Ok(())
}

#[test]
fn sidetree_short_and_long_form_shapes_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let short = generate_did_ion(IonNetwork::Mainnet, SIDETREE_SUFFIX)?;
    let long =
        generate_long_form_did_ion(IonNetwork::Mainnet, SIDETREE_SUFFIX, LONG_FORM_SUFFIX_DATA)?;

    assert_eq!(
        short,
        "did:ion:EiCxAP7PtUg7HKSX0H3Refli8XIyD-_PI9y-iuxhh8sx9g"
    );
    assert_eq!(short_form_did_ion(&long)?, short);
    let parsed = parse_did_ion(&long)?;
    assert_eq!(parsed.long_form_suffix_data, Some(LONG_FORM_SUFFIX_DATA));
    Ok(())
}

#[test]
fn did_ion_rejects_padded_suffix() {
    let err = parse_did_ion("did:ion:EiD0x0JeWXQbVIpBpyeyF5FDdZN1U7enAfHnd13Qk_CYpQ=")
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidIonErrorReason::InvalidSuffix));
}

#[test]
fn did_ion_rejects_unsupported_network() {
    let err = parse_did_ion("did:ion:devnet:EiD0x0JeWXQbVIpBpyeyF5FDdZN1U7enAfHnd13Qk_CYpQ")
        .err()
        .map(|error| error.reason);
    assert_eq!(err, Some(DidIonErrorReason::UnsupportedNetwork));
}

#[test]
fn rejects_substituted_suffix_and_delta() -> Result<(), Box<dyn std::error::Error>> {
    let wrong = generate_long_form_did_ion(
        IonNetwork::Mainnet,
        ION_TESTNET3_SUFFIX,
        LONG_FORM_SUFFIX_DATA,
    );
    assert_eq!(
        wrong.err().map(|error| error.reason),
        Some(DidIonErrorReason::SuffixMismatch)
    );
    let bytes = reallyme_codec::base64url::base64url_to_bytes(LONG_FORM_SUFFIX_DATA)?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
    value["delta"]["patches"] = serde_json::json!([]);
    let canonical = reallyme_codec::jcs::canonicalize_trusted_json_value(&value)?;
    let tampered = reallyme_codec::base64url::bytes_to_base64url(canonical.as_bytes());
    assert_eq!(
        generate_long_form_did_ion(IonNetwork::Mainnet, SIDETREE_SUFFIX, &tampered)
            .err()
            .map(|error| error.reason),
        Some(DidIonErrorReason::DeltaHashMismatch)
    );
    let did = format!("did:ion:{SIDETREE_SUFFIX}:{tampered}");
    assert_eq!(
        parse_did_ion(&did).err().map(|error| error.reason),
        Some(DidIonErrorReason::DeltaHashMismatch)
    );
    Ok(())
}

#[test]
fn rejects_noncanonical_initial_state_and_invalid_multihashes() {
    let padded_json = reallyme_codec::base64url::bytes_to_base64url(b" {} ");
    assert_eq!(
        generate_long_form_did_ion(IonNetwork::Mainnet, SIDETREE_SUFFIX, &padded_json)
            .err()
            .map(|error| error.reason),
        Some(DidIonErrorReason::InvalidInitialState)
    );
    for did in ["did:ion:AA", "did:ion:abc", "did:ion:"] {
        assert!(parse_did_ion(did).is_err());
    }
}
