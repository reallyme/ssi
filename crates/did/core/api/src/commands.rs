// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SDK command request types and provider-gated DID mutation wrappers.
//!
//! The managed-document helpers in `create`, `update`, and `rotate` can produce
//! valid did:me document transitions locally. The SDK command taxonomy is a
//! higher boundary: mutation commands may imply publication, resolver policy,
//! storage destruction, or compromise-recovery controls. These wrappers
//! therefore delegate to an explicit provider and fail closed unless that
//! provider opts in to the capability.

include!("commands/section_01.rs");
include!("commands/section_02.rs");
include!("commands/section_03.rs");
include!("commands/section_04.rs");
include!("commands/section_05.rs");
