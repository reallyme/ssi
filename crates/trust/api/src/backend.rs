// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Backend convenience helpers for adapters.
//!
//! Overview: Feature-gated constructors and re-exports for signature verification backends.
//!
//! Scope:
//! - Expose concrete `SignatureVerifier` implementations behind feature flags.
//! - Provide a default verifier selection helper for adapter consumers.
//!
//! Non-goals:
//! - Defining trust evaluation logic. The main API remains backend-agnostic and consumes a
//!   `SignatureVerifier` trait object.

use reallyme_trust_core::SignatureVerifier;

#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
pub use identity_trust_openssl::OpenSslSignatureVerifier;

#[cfg(feature = "wasm")]
pub use identity_trust_wasm::WasmSignatureVerifier;

/// Return a boxed signature verifier based on enabled features.
///
/// This is primarily for adapter layers that want a simple "default" without
/// referencing backend crates directly.
pub fn default_signature_verifier() -> Box<dyn SignatureVerifier> {
    default_signature_verifier_impl()
}

#[cfg(all(
    feature = "native",
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
fn default_signature_verifier_impl() -> Box<dyn SignatureVerifier> {
    Box::new(OpenSslSignatureVerifier::new())
}

#[cfg(all(not(feature = "native"), feature = "wasm"))]
fn default_signature_verifier_impl() -> Box<dyn SignatureVerifier> {
    Box::new(WasmSignatureVerifier::new())
}

#[cfg(any(
    not(any(feature = "native", feature = "wasm")),
    all(
        feature = "native",
        any(
            target_os = "android",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos"
        )
    )
))]
fn default_signature_verifier_impl() -> Box<dyn SignatureVerifier> {
    // No backends selected: the caller must pass a verifier explicitly.
    Box::new(NoBackendSignatureVerifier)
}

#[cfg(any(
    not(any(feature = "native", feature = "wasm")),
    all(
        feature = "native",
        any(
            target_os = "android",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos"
        )
    )
))]
#[derive(Debug, Default)]
struct NoBackendSignatureVerifier;

#[cfg(any(
    not(any(feature = "native", feature = "wasm")),
    all(
        feature = "native",
        any(
            target_os = "android",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos"
        )
    )
))]
impl SignatureVerifier for NoBackendSignatureVerifier {
    fn verify_chain(
        &self,
        _chain: &envelopes_x509::X509Chain,
        _now: time::OffsetDateTime,
    ) -> Result<(), reallyme_trust_core::SignatureVerifyError> {
        Err(reallyme_trust_core::SignatureVerifyError::BackendFailure)
    }
}
