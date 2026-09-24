// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;
use std::fmt::Formatter;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{JadesError, JadesErrorReason, JadesSignatureAlgorithm};

const MAX_PROTECTED_PARAMETERS: usize = 32;
const MAX_PROTECTED_PARAMETER_NAME_BYTES: usize = 64;

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct DigestReferenceJson {
    #[serde(rename = "digAlg")]
    pub(crate) algorithm: String,
    #[serde(rename = "digVal")]
    pub(crate) value: String,
}

#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ProtectedHeader {
    pub(crate) algorithm: Option<String>,
    pub(crate) x5c: Option<Vec<String>>,
    pub(crate) x5t_s256: Option<String>,
    pub(crate) x5t_o: Option<DigestReferenceJson>,
    pub(crate) sig_x5ts: Option<Vec<DigestReferenceJson>>,
    pub(crate) issued_at: Option<i64>,
    pub(crate) signature_time: Option<String>,
}

impl ProtectedHeader {
    pub(crate) fn signature_algorithm(&self) -> Result<JadesSignatureAlgorithm, JadesError> {
        match self.algorithm.as_deref() {
            Some("ES256") => Ok(JadesSignatureAlgorithm::Es256),
            Some("EdDSA") => Ok(JadesSignatureAlgorithm::EdDsa),
            Some(_) => Err(JadesError::new(
                JadesErrorReason::UnsupportedSignatureAlgorithm,
            )),
            None => Err(JadesError::new(JadesErrorReason::InvalidProtectedHeader)),
        }
    }

    pub(crate) const fn has_certificate_reference(&self) -> bool {
        self.x5c.is_some()
            || self.x5t_s256.is_some()
            || self.x5t_o.is_some()
            || self.sig_x5ts.is_some()
    }
}

impl<'de> Deserialize<'de> for ProtectedHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ProtectedHeaderVisitor)
    }
}

struct ProtectedHeaderVisitor;

impl<'de> Visitor<'de> for ProtectedHeaderVisitor {
    type Value = ProtectedHeader;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded JAdES protected-header object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut header = ProtectedHeader::default();
        let mut seen = BTreeSet::new();

        while let Some(key) = map.next_key::<String>()? {
            if key.len() > MAX_PROTECTED_PARAMETER_NAME_BYTES
                || seen.len() >= MAX_PROTECTED_PARAMETERS
                || !seen.insert(key.clone())
            {
                return Err(serde::de::Error::custom("invalid protected header"));
            }

            match key.as_str() {
                "alg" => header.algorithm = Some(map.next_value()?),
                "x5c" => header.x5c = Some(map.next_value()?),
                "x5t#S256" => header.x5t_s256 = Some(map.next_value()?),
                "x5t#o" => header.x5t_o = Some(map.next_value()?),
                "sigX5ts" => header.sig_x5ts = Some(map.next_value()?),
                "iat" => header.issued_at = Some(map.next_value()?),
                "sigT" => header.signature_time = Some(map.next_value()?),
                // RFC 7797 `b64` requires a different signing-input operation;
                // RFC 7515 `crit` cannot be ignored. Remote key material and
                // compression are also outside this certificate-bound profile.
                // ETSI TS 119 182-1 v1.2.1 clause 5.1.6 prohibits the
                // SHA-1-based `x5t` parameter in every JAdES signature. The
                // other parameters require a signing-input or remote-key
                // policy outside this compact certificate-bound profile.
                "x5t" | "b64" | "crit" | "jku" | "x5u" | "jwk" | "zip" => {
                    let _ = map.next_value::<IgnoredAny>()?;
                    return Err(serde::de::Error::custom("invalid protected header"));
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(header)
    }
}

pub(crate) fn parse_protected_header(value: &[u8]) -> Result<ProtectedHeader, JadesError> {
    serde_json::from_slice(value)
        .map_err(|_| JadesError::new(JadesErrorReason::InvalidProtectedHeader))
}
