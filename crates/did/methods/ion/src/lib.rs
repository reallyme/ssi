// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! did:ion identifiers with authenticated Sidetree initial-state commitments.
//!
//! Short forms must carry a canonical SHA-256 multihash. Long forms additionally
//! authenticate canonical initial-state JSON, the suffix-data hash, and the delta
//! hash. These checks establish initial-state integrity, not the latest anchored
//! state: callers must resolve anchored history before authorizing current keys.

mod method;
mod validate_initial_state;

pub use method::{
    generate_did_ion, generate_long_form_did_ion, is_valid_did_ion, parse_did_ion,
    short_form_did_ion, DidIonError, DidIonErrorReason, IonDidIdentifier, IonNetwork,
};
