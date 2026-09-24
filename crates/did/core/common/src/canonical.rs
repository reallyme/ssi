// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// A canonical object that can be hashed and signed.
///
/// Implemented by:
/// - DID core object
/// - Verifiable Credential core
/// - Verifiable Presentation core
pub trait CanonicalObject {
    /// Produce canonical CBOR bytes for hashing / signing.
    ///
    /// This MUST be:
    /// - deterministic
    /// - order-stable
    /// - free of envelopes / proofs
    fn canonical_cbor(&self) -> Vec<u8>;
}
