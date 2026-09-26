// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use identity_trust_jades::{
    authenticate_compact_jades, AuthenticatedCompactJws, CompactJwsVerificationError,
    CompactJwsVerificationErrorReason, CompactJwsVerifier, JadesAuthenticationInput, JadesPolicy,
    JadesSignatureAlgorithm, JadesVerificationKey,
};
use libfuzzer_sys::fuzz_target;
use reallyme_codec::base64url::bytes_to_base64url;

struct RejectSignature;
impl CompactJwsVerifier for RejectSignature {
    fn verify(
        &self,
        _: &str,
        _: JadesSignatureAlgorithm,
        _: JadesVerificationKey<'_>,
    ) -> Result<AuthenticatedCompactJws, CompactJwsVerificationError> {
        Err(CompactJwsVerificationError::new(
            CompactJwsVerificationErrorReason::InvalidSignature,
        ))
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let root = include_bytes!("../../crates/trust/tsl-xmlsec/tests/fixtures/unrelated_root.der");
    let Ok(certificate) = reallyme_trust_x509::parse_cert_der(root) else {
        return;
    };
    // Wrapping arbitrary bytes as the protected header reaches the JSON parser
    // without spending mutations on compact-serialization delimiters.
    let compact = format!("{}.e30.AA", bytes_to_base64url(data));
    let _ = authenticate_compact_jades(
        JadesAuthenticationInput {
            compact: &compact,
            expected_signing_certificate: &certificate,
            evaluation_time: time::OffsetDateTime::UNIX_EPOCH,
            policy: &JadesPolicy::default(),
        },
        &RejectSignature,
    );
});
