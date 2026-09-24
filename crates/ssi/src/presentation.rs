// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Protocol-neutral VP validation report API.
pub use reallyme_vp_api as api;

/// Protocol-agnostic VP model and holder-binding primitives.
pub use reallyme_vp_core as core;

/// Protocol-neutral VP policy helpers.
pub use identity_presentation_vp_policy as policy;

/// Raw Buffa-generated VP protobuf models.
pub use reallyme_ssi_proto as generated_proto;

/// Buffa protobuf transport for protocol-neutral VP payloads.
pub use reallyme_ssi_proto_codec::presentation as proto;

/// SD-JWT presentation helpers.
pub use identity_presentation_vp_sd_jwt as sd_jwt;

/// VP validation orchestrator.
pub use identity_presentation_vp_validator as validator;
