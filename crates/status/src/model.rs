// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Credential status purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum StatusPurpose {
    /// Credential revocation.
    Revocation,

    /// Temporary credential suspension.
    Suspension,
}

/// Supported status-list signature algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum StatusListAlgorithm {
    /// Ed25519 / EdDSA signature.
    Ed25519,

    /// P-256 ECDSA signature.
    P256,

    /// secp256k1 ECDSA signature.
    Secp256k1,
}

/// Status-list signature metadata and bytes.
#[derive(Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct StatusListSignature {
    /// Algorithm used by the issuer to sign the status-list payload.
    pub alg: StatusListAlgorithm,

    /// Signature bytes over [`crate::status_list_signing_payload`].
    pub sig_bytes: Vec<u8>,
}

/// Canonical credential status-list model.
#[derive(Eq, PartialEq)]
pub struct StatusList {
    /// Issuer identifier for the status-list credential or trust source.
    pub issuer: String,

    /// Purpose represented by set bits in the encoded list.
    pub purpose: StatusPurpose,

    /// Unix timestamp when this list was issued.
    pub issued_at: u64,

    /// Unix timestamp after which the list is stale.
    pub next_update: u64,

    /// Little-endian bitstring bytes. Bit `index % 8` of byte `index / 8` is checked.
    pub encoded_list: Vec<u8>,

    /// Number of status entries represented by the list.
    pub length: u64,

    /// Optional stable list identifier.
    pub list_id: Option<[u8; 32]>,

    /// Signature over the deterministic status-list payload.
    pub signature: StatusListSignature,
}

impl core::fmt::Debug for StatusListSignature {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StatusListSignature")
            .field("alg", &self.alg)
            .field("sig_bytes", &redacted_len(self.sig_bytes.len()))
            .finish()
    }
}

impl core::fmt::Debug for StatusList {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StatusList")
            .field("issuer", &redacted_len(self.issuer.len()))
            .field("purpose", &self.purpose)
            .field("issued_at", &self.issued_at)
            .field("next_update", &self.next_update)
            .field("encoded_list", &redacted_len(self.encoded_list.len()))
            .field("length", &self.length)
            .field(
                "list_id",
                &self.list_id.as_ref().map(|value| redacted_len(value.len())),
            )
            .field("signature", &self.signature)
            .finish()
    }
}

impl Zeroize for StatusList {
    fn zeroize(&mut self) {
        self.issuer.zeroize();
        self.purpose.zeroize();
        self.issued_at.zeroize();
        self.next_update.zeroize();
        self.encoded_list.zeroize();
        self.length.zeroize();
        if let Some(list_id) = &mut self.list_id {
            list_id.zeroize();
        }
        self.signature.zeroize();
    }
}

impl Drop for StatusList {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for StatusList {}

fn redacted_len(len: usize) -> RedactedLen {
    RedactedLen { len }
}

struct RedactedLen {
    len: usize,
}

impl core::fmt::Debug for RedactedLen {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("redacted")
            .field("len", &self.len)
            .finish()
    }
}
