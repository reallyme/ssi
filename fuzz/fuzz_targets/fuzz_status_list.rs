// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_credential_status::{
    status_bit, status_list_signing_payload, validate_status_list, StatusList, StatusListAlgorithm,
    StatusListSignature, StatusPurpose,
};

const MAX_FUZZ_INPUT_BYTES: usize = 4096;
const MAX_FUZZ_STATUS_BITS: u16 = 1024;
const STATUS_HEADER_BYTES: usize = 7;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES || data.len() < STATUS_HEADER_BYTES {
        return;
    }

    let length_seed = u16::from_be_bytes([data[0], data[1]]);
    let length = u64::from((length_seed % MAX_FUZZ_STATUS_BITS) + 1);
    let encoded_len = required_status_bytes(length);
    let Some(encoded_end) = STATUS_HEADER_BYTES.checked_add(encoded_len) else {
        return;
    };
    if encoded_end > data.len() {
        return;
    }

    let purpose = if data[2] & 1 == 0 {
        StatusPurpose::Revocation
    } else {
        StatusPurpose::Suspension
    };
    let alg = match data[3] % 3 {
        0 => StatusListAlgorithm::Ed25519,
        1 => StatusListAlgorithm::P256,
        _ => StatusListAlgorithm::Secp256k1,
    };
    let issued_at = u64::from(data[4]).saturating_add(1);
    let next_update = issued_at.saturating_add(u64::from(data[5]).saturating_add(1));
    let index = u64::from(data[6]) % length;
    let id_end = match encoded_end.checked_add(32) {
        Some(value) => value,
        None => return,
    };
    let list_id = if data.len() >= id_end {
        let mut value = [0_u8; 32];
        value.copy_from_slice(&data[encoded_end..id_end]);
        Some(value)
    } else {
        None
    };

    let list = StatusList {
        issuer: "did:example:fuzz-status".to_owned(),
        purpose,
        issued_at,
        next_update,
        encoded_list: data[STATUS_HEADER_BYTES..encoded_end].to_vec(),
        length,
        list_id,
        signature: StatusListSignature {
            alg,
            sig_bytes: data[encoded_end..].to_vec(),
        },
    };

    let _ = validate_status_list(&list);
    let _ = status_list_signing_payload(&list);
    let _ = status_bit(&list, index);
});

fn required_status_bytes(length: u64) -> usize {
    let adjusted = length.saturating_add(7);
    let bytes = adjusted / 8;
    match usize::try_from(bytes) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    }
}
