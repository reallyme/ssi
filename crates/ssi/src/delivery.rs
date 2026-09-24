// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Protocol-neutral delivery data model.
pub use identity_presentation_delivery_core as core;

/// Contact-card delivery helpers.
pub mod contact {
    /// Contact delivery facade.
    pub use identity_presentation_delivery_contact_api as api;

    /// Contact delivery model.
    pub use identity_presentation_delivery_contact_core as core;

    /// Contact delivery validation.
    pub use identity_presentation_delivery_contact_validator as validator;
}

/// SIOP delivery helpers.
pub mod siop {
    /// SIOP delivery facade.
    pub use identity_presentation_delivery_siop_api as api;

    /// SIOP delivery model.
    pub use identity_presentation_delivery_siop_core as core;

    /// SIOP verifier helpers.
    pub use identity_presentation_delivery_siop_verifier as verifier;
}

/// Web delivery helpers.
pub mod web {
    /// Web delivery model and builders.
    pub use identity_presentation_delivery_web_core as core;

    /// Web delivery validation.
    pub use identity_presentation_delivery_web_validator as validator;
}
