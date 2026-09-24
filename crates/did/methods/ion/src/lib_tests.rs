// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    generate_did_ion, generate_long_form_did_ion, parse_did_ion, short_form_did_ion,
    DidIonErrorReason, IonNetwork,
};

const SIDETREE_SUFFIX: &str = "EiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A";
const ION_TESTNET3_SUFFIX: &str = "EiD0x0JeWXQbVIpBpyeyF5FDdZN1U7enAfHnd13Qk_CYpQ";
const LONG_FORM_SUFFIX_DATA: &str = "eyJkZWx0YSI6eyJwYXRjaGVzIjpbXX0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCUCIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQmcifX0";

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
        "did:ion:EiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A"
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
