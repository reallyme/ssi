// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::arithmetic_side_effects)]

use super::{
    response_nonce_for_request, unique_matching_digest_in_responses, ExpectedCertId,
    MatchingDigest, OID_BASIC_OCSP_RESPONSE, OID_OCSP_NONCE, OID_SHA1, OID_SHA256,
};
use identity_revocation_ocsp_core::OcspError;

const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128);
    let mut encoded = Vec::with_capacity(value.len() + 2);
    encoded.push(tag);
    encoded.push(u8::try_from(value.len()).unwrap());
    encoded.extend_from_slice(value);
    encoded
}

fn basic_response(response_data: &[u8]) -> Vec<u8> {
    let mut algorithm = tlv(0x06, OID_SHA256_WITH_RSA);
    algorithm.extend_from_slice(&tlv(0x05, &[]));
    let mut basic = tlv(0x30, response_data);
    basic.extend_from_slice(&tlv(0x30, &algorithm));
    // DER BIT STRING content begins with the unused-bit count.
    basic.extend_from_slice(&tlv(0x03, &[0]));
    tlv(0x30, &basic)
}

fn single_response_with_extensions(
    oid: &[u8],
    name: &[u8],
    key: &[u8],
    serial: &[u8],
    extensions: Option<&[u8]>,
) -> Vec<u8> {
    let mut algorithm = tlv(0x06, oid);
    algorithm.extend_from_slice(&tlv(0x05, &[]));
    let mut cert_id = tlv(0x30, &algorithm);
    cert_id.extend_from_slice(&tlv(0x04, name));
    cert_id.extend_from_slice(&tlv(0x04, key));
    cert_id.extend_from_slice(&tlv(0x02, serial));
    let cert_id = tlv(0x30, &cert_id);

    // The selector deliberately needs only the first field of each
    // SingleResponse. The remaining valid-shaped fields prove that the
    // entry boundary cannot be confused with the next entry.
    let mut single = cert_id;
    single.extend_from_slice(&tlv(0x80, &[]));
    single.extend_from_slice(&tlv(0x18, b"20260101000000Z"));
    if let Some(extensions) = extensions {
        single.extend_from_slice(&tlv(0xa1, &tlv(0x30, extensions)));
    }
    tlv(0x30, &single)
}

fn single_response(oid: &[u8], name: &[u8], key: &[u8], serial: &[u8]) -> Vec<u8> {
    single_response_with_extensions(oid, name, key, serial, None)
}

fn expected() -> ExpectedCertId {
    ExpectedCertId {
        sha1_name: vec![1; 20],
        sha1_key: vec![2; 20],
        sha256_name: vec![3; 32],
        sha256_key: vec![4; 32],
        serial: vec![5],
    }
}

fn response_with_nonce_extension(extension_value: &[u8]) -> Vec<u8> {
    let mut extension = tlv(0x06, OID_OCSP_NONCE);
    extension.extend_from_slice(&tlv(0x04, extension_value));
    let extensions = tlv(0x30, &tlv(0x30, &extension));

    let mut response_data = tlv(0xa1, &[]);
    response_data.extend_from_slice(&tlv(0x18, b"20260101000000Z"));
    response_data.extend_from_slice(&tlv(0x30, &[]));
    response_data.extend_from_slice(&tlv(0xa1, &extensions));
    let basic_response = basic_response(&response_data);

    let mut response_bytes = tlv(0x06, OID_BASIC_OCSP_RESPONSE);
    response_bytes.extend_from_slice(&tlv(0x04, &basic_response));
    let mut response = tlv(0x0a, &[0]);
    response.extend_from_slice(&tlv(0xa0, &tlv(0x30, &response_bytes)));
    tlv(0x30, &response)
}

fn response_with_extension(oid: &[u8], critical: bool, extension_value: &[u8]) -> Vec<u8> {
    let mut extension = tlv(0x06, oid);
    if critical {
        extension.extend_from_slice(&tlv(0x01, &[0xff]));
    }
    extension.extend_from_slice(&tlv(0x04, extension_value));
    let extensions = tlv(0x30, &tlv(0x30, &extension));

    let mut response_data = tlv(0xa1, &[]);
    response_data.extend_from_slice(&tlv(0x18, b"20260101000000Z"));
    response_data.extend_from_slice(&tlv(0x30, &[]));
    response_data.extend_from_slice(&tlv(0xa1, &extensions));
    let basic_response = basic_response(&response_data);
    let mut response_bytes = tlv(0x06, OID_BASIC_OCSP_RESPONSE);
    response_bytes.extend_from_slice(&tlv(0x04, &basic_response));
    let mut response = tlv(0x0a, &[0]);
    response.extend_from_slice(&tlv(0xa0, &tlv(0x30, &response_bytes)));
    tlv(0x30, &response)
}

fn response_with_encoded_extensions(encoded_extensions: &[u8]) -> Vec<u8> {
    let extensions = tlv(0x30, encoded_extensions);
    let mut response_data = tlv(0xa1, &[]);
    response_data.extend_from_slice(&tlv(0x18, b"20260101000000Z"));
    response_data.extend_from_slice(&tlv(0x30, &[]));
    response_data.extend_from_slice(&tlv(0xa1, &extensions));
    let basic_response = basic_response(&response_data);
    let mut response_bytes = tlv(0x06, OID_BASIC_OCSP_RESPONSE);
    response_bytes.extend_from_slice(&tlv(0x04, &basic_response));
    let mut response = tlv(0x0a, &[0]);
    response.extend_from_slice(&tlv(0xa0, &tlv(0x30, &response_bytes)));
    tlv(0x30, &response)
}

#[test]
fn selects_one_sha256_or_sha1_response() {
    let expected = expected();
    let sha256 = single_response(
        OID_SHA256,
        &expected.sha256_name,
        &expected.sha256_key,
        &expected.serial,
    );
    assert_eq!(
        unique_matching_digest_in_responses(&sha256, &expected),
        Ok(MatchingDigest::Sha256)
    );

    let sha1 = single_response(
        OID_SHA1,
        &expected.sha1_name,
        &expected.sha1_key,
        &expected.serial,
    );
    assert_eq!(
        unique_matching_digest_in_responses(&sha1, &expected),
        Ok(MatchingDigest::Sha1)
    );
}

#[test]
fn rejects_duplicate_logical_matches_across_digest_algorithms() {
    let expected = expected();
    let mut responses = single_response(
        OID_SHA256,
        &expected.sha256_name,
        &expected.sha256_key,
        &expected.serial,
    );
    responses.extend_from_slice(&single_response(
        OID_SHA1,
        &expected.sha1_name,
        &expected.sha1_key,
        &expected.serial,
    ));

    assert_eq!(
        unique_matching_digest_in_responses(&responses, &expected),
        Err(OcspError::InvalidResponse)
    );
}

#[test]
fn ignores_unrecognized_digest_on_unrelated_response() {
    let expected = expected();
    let mut responses = single_response(&[0x2a, 0x03], &[9], &[8], &[7]);
    responses.extend_from_slice(&single_response(
        OID_SHA256,
        &expected.sha256_name,
        &expected.sha256_key,
        &expected.serial,
    ));

    assert_eq!(
        unique_matching_digest_in_responses(&responses, &expected),
        Ok(MatchingDigest::Sha256)
    );
}

#[test]
fn rejects_unrecognized_digest_for_the_target_serial() {
    let expected = expected();
    let mut responses = single_response(
        OID_SHA256,
        &expected.sha256_name,
        &expected.sha256_key,
        &expected.serial,
    );
    responses.extend_from_slice(&single_response(
        &[0x2a, 0x03],
        &[9],
        &[8],
        &expected.serial,
    ));

    assert_eq!(
        unique_matching_digest_in_responses(&responses, &expected),
        Err(OcspError::InvalidResponse)
    );
}

#[test]
fn malformed_nonce_is_rejected_even_when_the_request_did_not_use_a_nonce() {
    let response = response_with_nonce_extension(&tlv(0x04, &[]));

    assert_eq!(
        response_nonce_for_request(&response, false),
        Err(OcspError::InvalidResponse)
    );
    assert_eq!(
        response_nonce_for_request(&response, true),
        Err(OcspError::InvalidResponse)
    );
}

#[test]
fn rejects_unrecognized_critical_response_extension_without_a_requested_nonce() {
    let response = response_with_extension(&[0x2a, 0x03], true, &[]);
    assert_eq!(
        response_nonce_for_request(&response, false),
        Err(OcspError::InvalidResponse)
    );
}

#[test]
fn critical_response_extension_is_not_hidden_by_an_earlier_malformed_nonce() {
    let mut malformed_nonce = tlv(0x06, OID_OCSP_NONCE);
    malformed_nonce.extend_from_slice(&tlv(0x04, &tlv(0x04, &[])));
    let mut unknown_critical = tlv(0x06, &[0x2a, 0x03]);
    unknown_critical.extend_from_slice(&tlv(0x01, &[0xff]));
    unknown_critical.extend_from_slice(&tlv(0x04, &[]));
    let mut encoded = tlv(0x30, &malformed_nonce);
    encoded.extend_from_slice(&tlv(0x30, &unknown_critical));
    let response = response_with_encoded_extensions(&encoded);

    assert_eq!(
        response_nonce_for_request(&response, false),
        Err(OcspError::InvalidResponse)
    );
}

#[test]
fn rejects_critical_extension_on_matching_single_response() {
    let expected = expected();
    let mut extension = tlv(0x06, &[0x2a, 0x03]);
    extension.extend_from_slice(&tlv(0x01, &[0xff]));
    extension.extend_from_slice(&tlv(0x04, &[]));
    let responses = single_response_with_extensions(
        OID_SHA256,
        &expected.sha256_name,
        &expected.sha256_key,
        &expected.serial,
        Some(&tlv(0x30, &extension)),
    );

    assert_eq!(
        unique_matching_digest_in_responses(&responses, &expected),
        Err(OcspError::InvalidResponse)
    );
}

#[test]
fn rejects_nonce_longer_than_32_bytes_when_nonce_binding_is_required() {
    let response = response_with_nonce_extension(&tlv(0x04, &[7; 33]));
    assert_eq!(
        response_nonce_for_request(&response, true),
        Err(OcspError::InvalidResponse)
    );
}
