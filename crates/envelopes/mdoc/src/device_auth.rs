// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::cbor::{cbor_bytes_to_value, cbor_value_to_bytes, expect_map};
use crate::{MdocEnvelopeError, MdocInvalidInputReason};
use reallyme_cose::{
    cose_key_from_slice, cose_key_to_public_bytes, cose_sign1_detached, cose_verify1_detached,
    Algorithm,
};

/// ISO 18013-5 DeviceAuthentication context string.
pub const DEVICE_AUTHENTICATION_CONTEXT: &str = "DeviceAuthentication";

/// Signs ISO `DeviceAuthenticationBytes` as detached COSE_Sign1 payloads.
pub trait DeviceAuthSigner {
    /// Sign exact tag-24 `DeviceAuthenticationBytes` as a detached payload.
    fn sign_device_auth(
        &self,
        device_authentication_cbor: &[u8],
    ) -> Result<Vec<u8>, MdocEnvelopeError>;
}

/// DeviceAuth signer backed by `reallyme-cose`.
pub struct CoseDeviceAuthSigner<'a> {
    /// COSE/crypto algorithm to use for DeviceAuth.
    pub alg: Algorithm,

    /// Device private key bytes accepted by the selected ReallyMe Crypto lane.
    pub private_key: &'a [u8],

    /// Optional COSE key identifier written into the protected header.
    pub kid: Option<&'a [u8]>,
}

impl DeviceAuthSigner for CoseDeviceAuthSigner<'_> {
    fn sign_device_auth(
        &self,
        device_authentication_cbor: &[u8],
    ) -> Result<Vec<u8>, MdocEnvelopeError> {
        cose_sign1_detached(
            self.alg,
            device_authentication_cbor,
            self.private_key,
            self.kid,
        )
        .map(|signed| signed.to_vec())
        .map_err(|_| MdocEnvelopeError::Signing)
    }
}

/// Input needed to build ISO 18013-5 DeviceAuthentication bytes.
pub struct DeviceAuthenticationInput<'a> {
    /// Caller-supplied SessionTranscript CBOR bytes.
    ///
    /// This crate verifies and binds the opaque ISO transcript value, but does
    /// not construct OID4VP handover or browser/DC-API transcript variants.
    pub session_transcript_cbor: &'a [u8],

    /// mdoc document type bound into the DeviceAuthentication payload.
    pub doc_type: &'a str,

    /// CBOR bytes of `deviceSigned.nameSpaces`.
    pub device_name_spaces_cbor: &'a [u8],
}

/// Input needed to validate DeviceAuth against the signed MSO device key.
pub struct DeviceAuthenticationValidationInput<'a> {
    /// COSE_Sign1 bytes from `deviceAuth.deviceSignature`.
    pub device_auth: &'a [u8],

    /// COSE_Key CBOR bytes from the MobileSecurityObject deviceKeyInfo.
    pub device_key_cose_key_cbor: &'a [u8],

    /// Caller-supplied SessionTranscript CBOR bytes expected for this exchange.
    pub expected_session_transcript_cbor: &'a [u8],

    /// mdoc document type expected in DeviceAuthentication.
    pub doc_type: &'a str,

    /// CBOR bytes of `deviceSigned.nameSpaces`.
    pub device_name_spaces_cbor: &'a [u8],
}

/// Build canonical ISO `DeviceAuthenticationBytes`.
///
/// ISO/IEC 18013-5 signs tag 24 over a byte string containing the encoded
/// `DeviceAuthentication` array. Its fourth element is itself the tag-24
/// `DeviceNameSpacesBytes`, not the decoded namespaces map. Preserving these
/// two wrappers is required for byte-exact holder-signature interoperability.
pub fn build_device_authentication_cbor(
    input: &DeviceAuthenticationInput<'_>,
) -> Result<Vec<u8>, MdocEnvelopeError> {
    if input.session_transcript_cbor.is_empty() {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::InvalidSessionTranscript,
        ));
    }
    if input.doc_type.trim().is_empty() {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::EmptyDocType,
        ));
    }

    let session_transcript = cbor_bytes_to_value(input.session_transcript_cbor).map_err(|_| {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidSessionTranscript)
    })?;
    let device_name_spaces = cbor_bytes_to_value(input.device_name_spaces_cbor).map_err(|_| {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceNameSpaces)
    })?;
    expect_map(
        &device_name_spaces,
        MdocInvalidInputReason::InvalidDeviceNameSpaces,
    )?;

    let device_authentication = cbor_value_to_bytes(&ciborium::value::Value::Array(vec![
        ciborium::value::Value::Text(DEVICE_AUTHENTICATION_CONTEXT.to_owned()),
        session_transcript.as_value().clone(),
        ciborium::value::Value::Text(input.doc_type.to_owned()),
        ciborium::value::Value::Tag(
            crate::ENCODED_CBOR_DATA_ITEM_TAG,
            Box::new(ciborium::value::Value::Bytes(
                input.device_name_spaces_cbor.to_vec(),
            )),
        ),
    ]))?;

    cbor_value_to_bytes(&ciborium::value::Value::Tag(
        crate::ENCODED_CBOR_DATA_ITEM_TAG,
        Box::new(ciborium::value::Value::Bytes(device_authentication)),
    ))
}

/// Validate detached DeviceAuth and return the expected authenticated bytes.
pub fn validate_device_auth(
    input: &DeviceAuthenticationValidationInput<'_>,
) -> Result<Vec<u8>, MdocEnvelopeError> {
    let expected = build_device_authentication_cbor(&DeviceAuthenticationInput {
        session_transcript_cbor: input.expected_session_transcript_cbor,
        doc_type: input.doc_type,
        device_name_spaces_cbor: input.device_name_spaces_cbor,
    })?;
    let public_key = device_public_key_from_cose_key_cbor(input.device_key_cose_key_cbor)?;
    cose_verify1_detached(input.device_auth, &expected, |_, _| {
        Some(public_key.clone())
    })
    .map_err(|_| MdocEnvelopeError::InvalidDeviceSignature)?;

    Ok(expected)
}

/// Extract public key bytes from an ISO mdoc device COSE_Key.
pub fn device_public_key_from_cose_key_cbor(
    device_key_cose_key_cbor: &[u8],
) -> Result<Vec<u8>, MdocEnvelopeError> {
    let key = cose_key_from_slice(device_key_cose_key_cbor).map_err(|_| {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceAuthentication)
    })?;
    cose_key_to_public_bytes(&key).map_err(|_| {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceAuthentication)
    })
}
