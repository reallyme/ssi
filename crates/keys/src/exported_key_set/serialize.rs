// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::io::Write;

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use super::{ExportedKeySet, ExportedPrivateKey};

const MAX_EXPORTED_KEY_SET_JSON_BYTES: usize = 64 * 1_024 * 1_024;

pub(super) fn to_json(exported: &ExportedKeySet) -> Result<Zeroizing<String>, crate::KeySetError> {
    let capacity = exported_json_capacity(exported)?;
    let mut writer = BoundedExportWriter::new(capacity);
    serde_json::to_writer(
        &mut writer,
        &ExportedKeySetWire {
            private: ExportedPrivateMap(&exported.private),
            public: &exported.public,
        },
    )
    .map_err(|_| crate::KeySetError::SerializationFailed)?;
    writer.into_string()
}

#[derive(Serialize)]
struct ExportedKeySetWire<'a> {
    private: ExportedPrivateMap<'a>,
    public: &'a BTreeMap<String, String>,
}

struct ExportedPrivateMap<'a>(&'a BTreeMap<String, ExportedPrivateKey>);

impl Serialize for ExportedPrivateMap<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (identifier, key) in self.0 {
            map.serialize_entry(identifier, key.as_str())?;
        }
        map.end()
    }
}

fn exported_json_capacity(exported: &ExportedKeySet) -> Result<usize, crate::KeySetError> {
    let mut capacity = 32_usize;
    for (identifier, private_key) in &exported.private {
        capacity = add_json_string_capacity(capacity, identifier)?;
        capacity = add_json_string_capacity(capacity, private_key.as_str())?;
        capacity = capacity
            .checked_add(2)
            .ok_or(crate::KeySetError::SerializationFailed)?;
    }
    for (identifier, public_key) in &exported.public {
        capacity = add_json_string_capacity(capacity, identifier)?;
        capacity = add_json_string_capacity(capacity, public_key)?;
        capacity = capacity
            .checked_add(2)
            .ok_or(crate::KeySetError::SerializationFailed)?;
    }
    if capacity > MAX_EXPORTED_KEY_SET_JSON_BYTES {
        return Err(crate::KeySetError::SerializationFailed);
    }
    Ok(capacity)
}

fn add_json_string_capacity(capacity: usize, value: &str) -> Result<usize, crate::KeySetError> {
    let escaped = value
        .len()
        .checked_mul(6)
        .and_then(|length| length.checked_add(2))
        .ok_or(crate::KeySetError::SerializationFailed)?;
    capacity
        .checked_add(escaped)
        .ok_or(crate::KeySetError::SerializationFailed)
}

struct BoundedExportWriter {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl BoundedExportWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(limit)),
            limit,
        }
    }

    fn into_string(mut self) -> Result<Zeroizing<String>, crate::KeySetError> {
        match String::from_utf8(core::mem::take(&mut *self.bytes)) {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                Err(crate::KeySetError::SerializationFailed)
            }
        }
    }
}

impl Write for BoundedExportWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let new_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("key-set JSON limit exceeded"))?;
        if new_len > self.limit {
            return Err(std::io::Error::other("key-set JSON limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
