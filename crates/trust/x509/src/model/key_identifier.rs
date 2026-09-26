// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::sha2::{digest, digest_sha2_384, digest_sha2_512};
use sha1::{Digest, Sha1};
use x509_parser::{prelude::FromDer, x509::SubjectPublicKeyInfo};

use super::{X509Certificate, MAX_X509_CERTIFICATE_DER_BYTES};

/// Length of every key identifier computed by the supported methods.
///
/// RFC 5280 Section 4.2.1.2 method 1 uses the full 160-bit SHA-1 value and
/// RFC 7093 Section 2 methods 1-3 truncate the SHA-2 value to its leftmost
/// 160 bits.
const COMPUTED_KEY_IDENTIFIER_BYTES: usize = 20;

impl X509Certificate {
    /// Return whether `key_identifier` names this certificate's public key.
    ///
    /// The comparison uses only identifiers computed from the certificate's
    /// SubjectPublicKeyInfo. The certificate's own SubjectKeyIdentifier
    /// extension is self-asserted by the issuer and is never consulted, so a
    /// certificate cannot claim another key's identifier.
    ///
    /// Supported methods, each hashing the contents of the `subjectPublicKey`
    /// BIT STRING (excluding the tag, length, and unused-bits octets):
    ///
    /// - RFC 5280 Section 4.2.1.2 method 1: SHA-1, 160 bits.
    /// - RFC 7093 Section 2 method 1: leftmost 160 bits of SHA-256.
    /// - RFC 7093 Section 2 method 2: leftmost 160 bits of SHA-384.
    /// - RFC 7093 Section 2 method 3: leftmost 160 bits of SHA-512.
    ///
    /// RFC 5280 method 2 and RFC 7093 method 4 are not supported. A malformed
    /// SubjectPublicKeyInfo, a public key with unused bits, or an identifier
    /// of any length other than 160 bits never matches.
    #[must_use]
    pub fn matches_key_identifier(&self, key_identifier: &[u8]) -> bool {
        if key_identifier.len() != COMPUTED_KEY_IDENTIFIER_BYTES {
            return false;
        }
        let Some(computed) = computed_key_identifiers_for_spki(&self.spki_der) else {
            return false;
        };
        computed
            .iter()
            .any(|identifier| identifier.as_slice() == key_identifier)
    }
}

fn computed_key_identifiers_for_spki(
    spki_der: &[u8],
) -> Option<[[u8; COMPUTED_KEY_IDENTIFIER_BYTES]; 4]> {
    if spki_der.is_empty() || spki_der.len() > MAX_X509_CERTIFICATE_DER_BYTES {
        return None;
    }
    let (remaining, spki) = SubjectPublicKeyInfo::from_der(spki_der).ok()?;
    if !remaining.is_empty() || spki.subject_public_key.unused_bits != 0 {
        return None;
    }
    let public_key_bits: &[u8] = spki.subject_public_key.data.as_ref();
    if public_key_bits.is_empty() {
        return None;
    }
    Some(computed_key_identifiers(public_key_bits))
}

fn computed_key_identifiers(public_key_bits: &[u8]) -> [[u8; COMPUTED_KEY_IDENTIFIER_BYTES]; 4] {
    let sha1: [u8; COMPUTED_KEY_IDENTIFIER_BYTES] = Sha1::digest(public_key_bits).into();
    [
        sha1,
        leftmost_160_bits(digest(public_key_bits).as_bytes()),
        leftmost_160_bits(digest_sha2_384(public_key_bits).as_bytes()),
        leftmost_160_bits(digest_sha2_512(public_key_bits).as_bytes()),
    ]
}

fn leftmost_160_bits(value: &[u8]) -> [u8; COMPUTED_KEY_IDENTIFIER_BYTES] {
    let mut identifier = [0_u8; COMPUTED_KEY_IDENTIFIER_BYTES];
    for (target, source) in identifier.iter_mut().zip(value) {
        *target = *source;
    }
    identifier
}
