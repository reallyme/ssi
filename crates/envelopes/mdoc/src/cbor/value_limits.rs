// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn validate_ciborium_value(value: &Value, depth: usize) -> Result<(), MdocEnvelopeError> {
    if depth > MAX_MDOC_CBOR_DEPTH {
        return Err(MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::CborDepthExceeded,
        ));
    }

    let next_depth = depth.checked_add(1).ok_or(MdocEnvelopeError::InvalidInput(
        MdocInvalidInputReason::CborDepthExceeded,
    ))?;
    match value {
        Value::Array(items) => {
            if items.len() > MAX_MDOC_CBOR_ARRAY_ITEMS {
                return Err(MdocEnvelopeError::InvalidInput(
                    MdocInvalidInputReason::CborArrayTooLarge,
                ));
            }
            for item in items {
                validate_ciborium_value(item, next_depth)?;
            }
        }
        Value::Map(entries) => {
            if entries.len() > MAX_MDOC_CBOR_MAP_ENTRIES {
                return Err(MdocEnvelopeError::InvalidInput(
                    MdocInvalidInputReason::CborMapTooLarge,
                ));
            }
            for (key, item) in entries {
                validate_ciborium_value(key, next_depth)?;
                validate_ciborium_value(item, next_depth)?;
            }
        }
        Value::Tag(_, item) => validate_ciborium_value(item, next_depth)?,
        Value::Integer(_)
        | Value::Bytes(_)
        | Value::Float(_)
        | Value::Text(_)
        | Value::Bool(_)
        | Value::Null => {}
        _ => {}
    }

    Ok(())
}
