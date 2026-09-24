// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed construction and validation API for contact delivery messages.

mod contact;

pub use contact::{
    build_contact_frames_cbor, build_contact_message_cbor, validate_contact_frames,
    validate_contact_message, BuildContactMessageInput, BuiltContactMessage, ContactApiError,
};
