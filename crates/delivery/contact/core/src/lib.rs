// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]
//! Contact delivery framing primitives for proximity transports.
//!
//! This crate owns only the transport-neutral CBOR message and frame mechanics
//! used by NFC/BLE style handoff paths. Higher protocol layers remain
//! responsible for signatures, encryption, and presentation semantics.

mod cbor;
mod error;
mod framing;
mod hash;
mod limits;
mod model;

pub use cbor::{
    decode_contact_frame_cbor, decode_contact_message_cbor, encode_contact_frame_cbor,
    encode_contact_message_cbor,
};
pub use error::ContactDeliveryError;
pub use framing::{fragment_message, reassemble_frames};
pub use hash::{sha256_bytes, sha256_concat};
pub use limits::{
    ContactLimits, CONTACT_SESSION_ID_BYTES, MAX_CONTACT_FRAMES, MAX_CONTACT_FRAME_CBOR_BYTES,
    MAX_CONTACT_MESSAGE_CBOR_BYTES,
};
pub use model::{ContactFrame, ContactMessage, ContactPayloadKind};
