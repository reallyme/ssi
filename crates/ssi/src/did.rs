// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Ergonomic Rust DID workflows.
pub use reallyme_did_api as api;

/// Core did:me engine and validation logic.
pub use reallyme_did_core as core;

/// Raw Buffa-generated DID protobuf models.
pub use reallyme_ssi_proto as generated_proto;

/// DID method-specific helpers.
pub mod methods {
    /// did:cheqd identifier helpers.
    pub use reallyme_did_method_cheqd as cheqd;

    /// did:ebsi identifier helpers.
    pub use reallyme_did_method_ebsi as ebsi;

    /// did:ion identifier helpers.
    pub use reallyme_did_method_ion as ion;

    /// did:jwk identifier helpers.
    pub use reallyme_did_method_jwk as jwk;

    /// did:key identifier helpers.
    pub use reallyme_did_method_key as key;

    /// did:me identifier helpers.
    pub use reallyme_did_method_me as me;

    /// did:web identifier helpers.
    pub use reallyme_did_method_web as web;
}

/// Buffa protobuf transport for DID documents.
pub use reallyme_ssi_proto_codec::did as proto;

/// DID document domain types.
pub use reallyme_did_types as types;
