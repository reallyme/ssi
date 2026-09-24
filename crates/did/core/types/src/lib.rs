// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JSON-facing DID document model used by ReallyMe DID generation and transport.
//!
//! These types intentionally preserve DID JSON shapes because most credential ecosystems still
//! exchange DID documents as JSON, even when ReallyMe also supports protobuf transport.

mod model;

pub use model::{
    Attestation, Controller, DIDDocument, DNSBinding, DataIntegrityProof, DomainVerification,
    Service, UpdatePolicy, VerificationMethod, WellKnownBinding,
};
