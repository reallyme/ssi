// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_crypto::dispatch::hash_digest;
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::sensitive::zeroize_json_value;
use crate::{SdJwtEnvelopeError, SdJwtHashAlgorithm, MAX_SD_JWT_DISCLOSURE_BYTES};

const OBJECT_DISCLOSURE_ELEMENTS: usize = 3;
const ARRAY_DISCLOSURE_ELEMENTS: usize = 2;
pub(crate) const SD_CLAIM_NAME: &str = "_sd";
pub(crate) const ARRAY_DIGEST_CLAIM_NAME: &str = "...";

#[derive(PartialEq)]
pub enum DisclosureKind {
    ObjectProperty {
        claim_name: String,
        claim_value: Value,
    },
    ArrayElement {
        claim_value: Value,
    },
}

impl fmt::Debug for DisclosureKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DisclosureKind([REDACTED])")
    }
}

impl Zeroize for DisclosureKind {
    fn zeroize(&mut self) {
        match self {
            Self::ObjectProperty {
                claim_name,
                claim_value,
            } => {
                claim_name.zeroize();
                zeroize_json_value(claim_value);
            }
            Self::ArrayElement { claim_value } => zeroize_json_value(claim_value),
        }
    }
}

#[derive(PartialEq)]
pub struct Disclosure {
    encoded: String,
    salt: String,
    kind: DisclosureKind,
}

impl fmt::Debug for Disclosure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Disclosure([REDACTED])")
    }
}

impl Zeroize for Disclosure {
    fn zeroize(&mut self) {
        self.encoded.zeroize();
        self.salt.zeroize();
        self.kind.zeroize();
    }
}

impl Drop for Disclosure {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Disclosure {}

impl Disclosure {
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    pub fn salt(&self) -> &str {
        &self.salt
    }

    pub fn kind(&self) -> &DisclosureKind {
        &self.kind
    }

    pub(crate) fn into_kind(mut self) -> DisclosureKind {
        core::mem::replace(
            &mut self.kind,
            DisclosureKind::ArrayElement {
                claim_value: Value::Null,
            },
        )
    }
}

pub fn create_object_property_disclosure(
    salt: &str,
    claim_name: &str,
    claim_value: Value,
) -> Result<Disclosure, SdJwtEnvelopeError> {
    validate_object_claim_name(claim_name)?;
    validate_salt(salt)?;

    let mut values = vec![
        Value::String(salt.to_owned()),
        Value::String(claim_name.to_owned()),
        claim_value,
    ];
    let stored_claim_value = values
        .get(OBJECT_DISCLOSURE_ELEMENTS - 1)
        .cloned()
        .ok_or(SdJwtEnvelopeError::InvalidDisclosureFormat)?;
    let array = Value::Array(core::mem::take(&mut values));
    let json = serde_json::to_vec(&array)?;
    let encoded = bytes_to_base64url(&json);

    Ok(Disclosure {
        encoded,
        salt: salt.to_owned(),
        kind: DisclosureKind::ObjectProperty {
            claim_name: claim_name.to_owned(),
            claim_value: stored_claim_value,
        },
    })
}

pub fn create_array_element_disclosure(
    salt: &str,
    claim_value: Value,
) -> Result<Disclosure, SdJwtEnvelopeError> {
    validate_salt(salt)?;

    let mut values = vec![Value::String(salt.to_owned()), claim_value];
    let stored_claim_value = values
        .get(ARRAY_DISCLOSURE_ELEMENTS - 1)
        .cloned()
        .ok_or(SdJwtEnvelopeError::InvalidDisclosureFormat)?;
    let array = Value::Array(core::mem::take(&mut values));
    let json = serde_json::to_vec(&array)?;
    let encoded = bytes_to_base64url(&json);

    Ok(Disclosure {
        encoded,
        salt: salt.to_owned(),
        kind: DisclosureKind::ArrayElement {
            claim_value: stored_claim_value,
        },
    })
}

pub fn decode_disclosure(encoded: &str) -> Result<Disclosure, SdJwtEnvelopeError> {
    if encoded.is_empty() || encoded.len() > MAX_SD_JWT_DISCLOSURE_BYTES || !encoded.is_ascii() {
        return Err(SdJwtEnvelopeError::InvalidDisclosureEncoding);
    }

    let decoded = Zeroizing::new(base64url_to_bytes(encoded)?);
    if decoded.len() > MAX_SD_JWT_DISCLOSURE_BYTES {
        return Err(SdJwtEnvelopeError::InvalidDisclosureEncoding);
    }
    let value: Value = serde_json::from_slice(&decoded)?;
    let mut elements = match value {
        Value::Array(elements) => elements,
        _ => return Err(SdJwtEnvelopeError::InvalidDisclosureFormat),
    };

    match elements.len() {
        OBJECT_DISCLOSURE_ELEMENTS => decode_object_property_disclosure(encoded, &mut elements),
        ARRAY_DISCLOSURE_ELEMENTS => decode_array_element_disclosure(encoded, &mut elements),
        _ => Err(SdJwtEnvelopeError::InvalidDisclosureFormat),
    }
}

pub fn digest_disclosure(
    encoded: &str,
    algorithm: SdJwtHashAlgorithm,
) -> Result<String, SdJwtEnvelopeError> {
    if encoded.is_empty() || !encoded.is_ascii() {
        return Err(SdJwtEnvelopeError::InvalidDisclosureEncoding);
    }

    // SD-JWT binds the exact base64url Disclosure spelling. Hashing decoded JSON
    // would incorrectly accept alternate whitespace or Unicode representations.
    let digest = hash_digest(algorithm.dispatch_algorithm(), encoded.as_bytes())?;
    Ok(bytes_to_base64url(&digest))
}

pub(crate) fn validate_object_claim_name(claim_name: &str) -> Result<(), SdJwtEnvelopeError> {
    if claim_name.is_empty() || claim_name == SD_CLAIM_NAME || claim_name == ARRAY_DIGEST_CLAIM_NAME
    {
        return Err(SdJwtEnvelopeError::InvalidDisclosureClaimName);
    }

    Ok(())
}

fn validate_salt(salt: &str) -> Result<(), SdJwtEnvelopeError> {
    let decoded = Zeroizing::new(
        base64url_to_bytes(salt).map_err(|_| SdJwtEnvelopeError::InvalidDisclosureFormat)?,
    );
    if decoded.len() < 16 || decoded.len() > 64 {
        return Err(SdJwtEnvelopeError::InvalidDisclosureFormat);
    }

    Ok(())
}

fn decode_object_property_disclosure(
    encoded: &str,
    elements: &mut Vec<Value>,
) -> Result<Disclosure, SdJwtEnvelopeError> {
    let claim_value = elements
        .pop()
        .ok_or(SdJwtEnvelopeError::InvalidDisclosureFormat)?;
    let claim_name = match elements
        .pop()
        .ok_or(SdJwtEnvelopeError::InvalidDisclosureFormat)?
    {
        Value::String(claim_name) => claim_name,
        _ => return Err(SdJwtEnvelopeError::InvalidDisclosureFormat),
    };
    let salt = match elements
        .pop()
        .ok_or(SdJwtEnvelopeError::InvalidDisclosureFormat)?
    {
        Value::String(salt) => salt,
        _ => return Err(SdJwtEnvelopeError::InvalidDisclosureFormat),
    };

    validate_object_claim_name(&claim_name)?;
    validate_salt(&salt)?;

    Ok(Disclosure {
        encoded: encoded.to_owned(),
        salt,
        kind: DisclosureKind::ObjectProperty {
            claim_name,
            claim_value,
        },
    })
}

fn decode_array_element_disclosure(
    encoded: &str,
    elements: &mut Vec<Value>,
) -> Result<Disclosure, SdJwtEnvelopeError> {
    let claim_value = elements
        .pop()
        .ok_or(SdJwtEnvelopeError::InvalidDisclosureFormat)?;
    let salt = match elements
        .pop()
        .ok_or(SdJwtEnvelopeError::InvalidDisclosureFormat)?
    {
        Value::String(salt) => salt,
        _ => return Err(SdJwtEnvelopeError::InvalidDisclosureFormat),
    };
    validate_salt(&salt)?;

    Ok(Disclosure {
        encoded: encoded.to_owned(),
        salt,
        kind: DisclosureKind::ArrayElement { claim_value },
    })
}
