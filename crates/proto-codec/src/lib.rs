// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded codecs and domain conversions for standards-level SSI protobufs.

/// Compression-error mapping owned by the SSI protobuf boundary.
pub mod compression;
/// DID document mappings and bounded protobuf transport.
pub mod did;
/// Presentation mappings and bounded protobuf transport.
pub mod presentation;
