// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! did:ion method syntax helpers.
//!
//! ION is a Sidetree-based DID method. This crate validates short-form,
//! network-qualified, and long-form DID URI syntax. It does not attempt to
//! verify Sidetree operation commitments or resolve anchored state; those
//! require canonical JSON, hashing, and network-specific operation data.

mod method;

pub use method::{
    generate_did_ion, generate_long_form_did_ion, is_valid_did_ion, parse_did_ion,
    short_form_did_ion, DidIonError, DidIonErrorReason, IonDidIdentifier, IonNetwork,
};
