// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DID method conformance-vector tests.

use reallyme_did_method_cheqd::{
    generate_did_cheqd, parse_did_cheqd, CheqdIdentifierKind, DidCheqdErrorReason,
};
use reallyme_did_method_ebsi::{
    generate_did_ebsi, parse_did_ebsi, DidEbsiErrorReason, EbsiDidVersion,
};
use reallyme_did_method_ion::{parse_did_ion, short_form_did_ion, DidIonErrorReason, IonNetwork};
use reallyme_did_method_jwk::{generate_did_jwk_from_json_bytes, parse_did_jwk, DidJwkErrorReason};
use reallyme_did_method_key::{
    generate_did_key, parse_did_key, DidKeyErrorReason, DidKeyMulticodec,
};
use reallyme_did_method_me::{parse_did_me, DidMeErrorReason};
use reallyme_did_method_web::{did_web_document_url, parse_did_web, DidWebErrorReason};
use serde_json::Value;
use thiserror::Error;

const DID_METHOD_VECTORS: &str = include_str!("../../../../../vectors/did-methods.json");

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
enum VectorTestError {
    #[error("vector JSON is invalid")]
    InvalidJson,
    #[error("expected field is missing")]
    MissingField,
    #[error("expected field had the wrong type")]
    WrongFieldType,
    #[error("unexpected DID method in vector suite")]
    UnexpectedMethod,
    #[error("unexpected enum value in vector suite")]
    UnexpectedEnumValue,
}

#[test]
fn did_method_vectors_are_valid() -> Result<(), Box<dyn std::error::Error>> {
    let root: Value =
        serde_json::from_str(DID_METHOD_VECTORS).map_err(|_| VectorTestError::InvalidJson)?;
    let suites = required_array(&root, "suites")?;

    for suite in suites {
        match required_str(suite, "method")? {
            "did:me" => verify_did_me_suite(suite)?,
            "did:key" => verify_did_key_suite(suite)?,
            "did:jwk" => verify_did_jwk_suite(suite)?,
            "did:web" => verify_did_web_suite(suite)?,
            "did:ebsi" => verify_did_ebsi_suite(suite)?,
            "did:cheqd" => verify_did_cheqd_suite(suite)?,
            "did:ion" => verify_did_ion_suite(suite)?,
            _ => return Err(Box::new(VectorTestError::UnexpectedMethod)),
        }
    }

    Ok(())
}

#[test]
fn did_method_valid_vectors_are_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let root: Value =
        serde_json::from_str(DID_METHOD_VECTORS).map_err(|_| VectorTestError::InvalidJson)?;
    let suites = required_array(&root, "suites")?;

    for suite in suites {
        match required_str(suite, "method")? {
            "did:me" => verify_did_me_valid_vectors(suite)?,
            "did:key" => verify_did_key_valid_vectors(suite)?,
            "did:jwk" => verify_did_jwk_valid_vectors(suite)?,
            "did:web" => verify_did_web_valid_vectors(suite)?,
            "did:ebsi" => verify_did_ebsi_valid_vectors(suite)?,
            "did:cheqd" => verify_did_cheqd_valid_vectors(suite)?,
            "did:ion" => verify_did_ion_valid_vectors(suite)?,
            _ => return Err(Box::new(VectorTestError::UnexpectedMethod)),
        }
    }

    Ok(())
}

#[test]
fn did_method_invalid_vectors_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let root: Value =
        serde_json::from_str(DID_METHOD_VECTORS).map_err(|_| VectorTestError::InvalidJson)?;
    let suites = required_array(&root, "suites")?;

    for suite in suites {
        match required_str(suite, "method")? {
            "did:me" => verify_did_me_invalid_vectors(suite)?,
            "did:key" => verify_did_key_invalid_vectors(suite)?,
            "did:jwk" => verify_did_jwk_invalid_vectors(suite)?,
            "did:web" => verify_did_web_invalid_vectors(suite)?,
            "did:ebsi" => verify_did_ebsi_invalid_vectors(suite)?,
            "did:cheqd" => verify_did_cheqd_invalid_vectors(suite)?,
            "did:ion" => verify_did_ion_invalid_vectors(suite)?,
            _ => return Err(Box::new(VectorTestError::UnexpectedMethod)),
        }
    }

    Ok(())
}

fn verify_did_me_suite(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    verify_did_me_valid_vectors(suite)?;
    verify_did_me_invalid_vectors(suite)
}

fn verify_did_me_valid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "valid")? {
        let parsed = parse_did_me(required_str(case, "did")?)?;
        assert_eq!(
            hex_lower(&parsed.payload)?,
            required_str(case, "payload_hex")?
        );
    }
    Ok(())
}

fn verify_did_me_invalid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "invalid")? {
        let reason = parse_did_me(required_str(case, "did")?)
            .err()
            .map(|error| error.reason);
        assert_eq!(reason, Some(did_me_reason(required_str(case, "reason")?)?));
    }
    Ok(())
}

fn verify_did_key_suite(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    verify_did_key_valid_vectors(suite)?;
    verify_did_key_invalid_vectors(suite)
}

fn verify_did_key_valid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "valid")? {
        let parsed = parse_did_key(required_str(case, "did")?)?;
        assert_eq!(
            parsed.multicodec,
            did_key_multicodec(required_str(case, "multicodec")?)?
        );
        assert_eq!(
            parsed.public_key.len(),
            required_usize(case, "public_key_len")?
        );
        assert_eq!(
            generate_did_key(parsed.multicodec, &parsed.public_key, parsed.multibase)?,
            required_str(case, "did")?
        );
    }
    Ok(())
}

fn verify_did_key_invalid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "invalid")? {
        let reason = parse_did_key(required_str(case, "did")?)
            .err()
            .map(|error| error.reason);
        assert_eq!(reason, Some(did_key_reason(required_str(case, "reason")?)?));
    }
    Ok(())
}

fn verify_did_jwk_suite(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    verify_did_jwk_valid_vectors(suite)?;
    verify_did_jwk_invalid_vectors(suite)
}

fn verify_did_jwk_valid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "valid")? {
        let did = required_str(case, "did")?;
        parse_did_jwk(did)?;
        assert_eq!(
            generate_did_jwk_from_json_bytes(required_str(case, "jwk_json")?.as_bytes())?,
            did
        );
    }
    Ok(())
}

fn verify_did_jwk_invalid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "invalid")? {
        let reason = generate_did_jwk_from_json_bytes(required_str(case, "jwk_json")?.as_bytes())
            .err()
            .map(|error| error.reason);
        assert_eq!(reason, Some(did_jwk_reason(required_str(case, "reason")?)?));
    }
    Ok(())
}

fn verify_did_web_suite(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    verify_did_web_valid_vectors(suite)?;
    verify_did_web_invalid_vectors(suite)
}

fn verify_did_web_valid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "valid")? {
        let did = required_str(case, "did")?;
        parse_did_web(did)?;
        assert_eq!(
            did_web_document_url(did)?,
            required_str(case, "document_url")?
        );
    }
    Ok(())
}

fn verify_did_web_invalid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "invalid")? {
        let reason = parse_did_web(required_str(case, "did")?)
            .err()
            .map(|error| error.reason);
        assert_eq!(reason, Some(did_web_reason(required_str(case, "reason")?)?));
    }
    Ok(())
}

fn verify_did_ebsi_suite(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    verify_did_ebsi_valid_vectors(suite)?;
    verify_did_ebsi_invalid_vectors(suite)
}

fn verify_did_ebsi_valid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "valid")? {
        let did = required_str(case, "did")?;
        let parsed = parse_did_ebsi(did)?;
        assert_eq!(
            parsed.version,
            ebsi_version(required_str(case, "version")?)?
        );
        assert_eq!(parsed.payload.len(), required_usize(case, "payload_len")?);
        assert_eq!(generate_did_ebsi(parsed.version, &parsed.payload)?, did);
    }
    Ok(())
}

fn verify_did_ebsi_invalid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "invalid")? {
        let reason = parse_did_ebsi(required_str(case, "did")?)
            .err()
            .map(|error| error.reason);
        assert_eq!(
            reason,
            Some(did_ebsi_reason(required_str(case, "reason")?)?)
        );
    }
    Ok(())
}

fn verify_did_cheqd_suite(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    verify_did_cheqd_valid_vectors(suite)?;
    verify_did_cheqd_invalid_vectors(suite)
}

fn verify_did_cheqd_valid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "valid")? {
        let did = required_str(case, "did")?;
        let parsed = parse_did_cheqd(did)?;
        assert_eq!(parsed.namespace, optional_str(case, "namespace")?);
        assert_eq!(parsed.unique_id, required_str(case, "unique_id")?);
        assert_eq!(parsed.kind, cheqd_kind(required_str(case, "kind")?)?);
        assert_eq!(generate_did_cheqd(parsed.namespace, parsed.unique_id)?, did);
    }
    Ok(())
}

fn verify_did_cheqd_invalid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "invalid")? {
        let reason = parse_did_cheqd(required_str(case, "did")?)
            .err()
            .map(|error| error.reason);
        assert_eq!(
            reason,
            Some(did_cheqd_reason(required_str(case, "reason")?)?)
        );
    }
    Ok(())
}

fn verify_did_ion_suite(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    verify_did_ion_valid_vectors(suite)?;
    verify_did_ion_invalid_vectors(suite)
}

fn verify_did_ion_valid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "valid")? {
        let did = required_str(case, "did")?;
        let parsed = parse_did_ion(did)?;
        assert_eq!(parsed.network, ion_network(required_str(case, "network")?)?);
        assert_eq!(parsed.did_suffix, required_str(case, "did_suffix")?);
        assert_eq!(short_form_did_ion(did)?, required_str(case, "short_form")?);
    }
    Ok(())
}

fn verify_did_ion_invalid_vectors(suite: &Value) -> Result<(), Box<dyn std::error::Error>> {
    for case in required_array(suite, "invalid")? {
        let reason = parse_did_ion(required_str(case, "did")?)
            .err()
            .map(|error| error.reason);
        assert_eq!(reason, Some(did_ion_reason(required_str(case, "reason")?)?));
    }
    Ok(())
}

fn required_array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>, VectorTestError> {
    value
        .get(field)
        .ok_or(VectorTestError::MissingField)?
        .as_array()
        .ok_or(VectorTestError::WrongFieldType)
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, VectorTestError> {
    value
        .get(field)
        .ok_or(VectorTestError::MissingField)?
        .as_str()
        .ok_or(VectorTestError::WrongFieldType)
}

fn optional_str<'a>(value: &'a Value, field: &str) -> Result<Option<&'a str>, VectorTestError> {
    match value.get(field) {
        Some(Value::Null) | None => Ok(None),
        Some(inner) => inner
            .as_str()
            .map(Some)
            .ok_or(VectorTestError::WrongFieldType),
    }
}

fn required_usize(value: &Value, field: &str) -> Result<usize, VectorTestError> {
    let raw = value
        .get(field)
        .ok_or(VectorTestError::MissingField)?
        .as_u64()
        .ok_or(VectorTestError::WrongFieldType)?;
    usize::try_from(raw).map_err(|_| VectorTestError::WrongFieldType)
}

fn did_me_reason(value: &str) -> Result<DidMeErrorReason, VectorTestError> {
    match value {
        "InvalidChecksum" => Ok(DidMeErrorReason::InvalidChecksum),
        _ => Err(VectorTestError::UnexpectedEnumValue),
    }
}

fn did_key_multicodec(value: &str) -> Result<DidKeyMulticodec, VectorTestError> {
    match value {
        "Secp256k1" => Ok(DidKeyMulticodec::Secp256k1),
        "X25519" => Ok(DidKeyMulticodec::X25519),
        "Ed25519" => Ok(DidKeyMulticodec::Ed25519),
        "P256" => Ok(DidKeyMulticodec::P256),
        "P384" => Ok(DidKeyMulticodec::P384),
        _ => Err(VectorTestError::UnexpectedEnumValue),
    }
}

fn did_key_reason(value: &str) -> Result<DidKeyErrorReason, VectorTestError> {
    match value {
        "UnsupportedMultibase" => Ok(DidKeyErrorReason::UnsupportedMultibase),
        _ => Err(VectorTestError::UnexpectedEnumValue),
    }
}

fn did_jwk_reason(value: &str) -> Result<DidJwkErrorReason, VectorTestError> {
    match value {
        "PrivateKeyMaterial" => Ok(DidJwkErrorReason::PrivateKeyMaterial),
        _ => Err(VectorTestError::UnexpectedEnumValue),
    }
}

fn did_web_reason(value: &str) -> Result<DidWebErrorReason, VectorTestError> {
    match value {
        "InvalidDomain" => Ok(DidWebErrorReason::InvalidDomain),
        _ => Err(VectorTestError::UnexpectedEnumValue),
    }
}

fn ebsi_version(value: &str) -> Result<EbsiDidVersion, VectorTestError> {
    match value {
        "LegalEntity" => Ok(EbsiDidVersion::LegalEntity),
        _ => Err(VectorTestError::UnexpectedEnumValue),
    }
}

fn did_ebsi_reason(value: &str) -> Result<DidEbsiErrorReason, VectorTestError> {
    match value {
        "MissingMultibasePrefix" => Ok(DidEbsiErrorReason::MissingMultibasePrefix),
        _ => Err(VectorTestError::UnexpectedEnumValue),
    }
}

fn cheqd_kind(value: &str) -> Result<CheqdIdentifierKind, VectorTestError> {
    match value {
        "Uuid" => Ok(CheqdIdentifierKind::Uuid),
        "IndyStyle" => Ok(CheqdIdentifierKind::IndyStyle),
        _ => Err(VectorTestError::UnexpectedEnumValue),
    }
}

fn did_cheqd_reason(value: &str) -> Result<DidCheqdErrorReason, VectorTestError> {
    match value {
        "InvalidNamespace" => Ok(DidCheqdErrorReason::InvalidNamespace),
        _ => Err(VectorTestError::UnexpectedEnumValue),
    }
}

fn ion_network(value: &str) -> Result<IonNetwork, VectorTestError> {
    match value {
        "Mainnet" => Ok(IonNetwork::Mainnet),
        "Testnet3" => Ok(IonNetwork::Testnet3),
        _ => Err(VectorTestError::UnexpectedEnumValue),
    }
}

fn did_ion_reason(value: &str) -> Result<DidIonErrorReason, VectorTestError> {
    match value {
        "InvalidSuffix" => Ok(DidIonErrorReason::InvalidSuffix),
        _ => Err(VectorTestError::UnexpectedEnumValue),
    }
}

fn hex_lower(bytes: &[u8]) -> Result<String, VectorTestError> {
    let capacity = bytes
        .len()
        .checked_mul(2)
        .ok_or(VectorTestError::WrongFieldType)?;
    let mut out = String::with_capacity(capacity);
    for byte in bytes {
        push_hex_byte(&mut out, *byte);
    }
    Ok(out)
}

fn push_hex_byte(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(char::from(HEX[usize::from(byte >> 4)]));
    out.push(char::from(HEX[usize::from(byte & 0x0f)]));
}
