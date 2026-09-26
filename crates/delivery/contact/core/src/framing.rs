// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    decode_contact_frame_cbor, encode_contact_frame_cbor, ContactDeliveryError, ContactFrame,
    ContactLimits,
};

/// Fragment raw message bytes into CBOR-encoded frames.
pub fn fragment_message(
    session_id: &[u8],
    message_id: u32,
    message_bytes: &[u8],
    limits: &ContactLimits,
) -> Result<Vec<Vec<u8>>, ContactDeliveryError> {
    limits.validate()?;
    if message_bytes.len() > limits.max_message_bytes {
        return Err(ContactDeliveryError::MessageTooLarge);
    }
    if session_id.len() != limits.session_id_len {
        return Err(ContactDeliveryError::InvalidInput);
    }

    // Compute the maximum chunk size that still fits in `max_frame_bytes`.
    // This avoids relying on fixed overhead estimates, which can break when
    // CBOR length encodings cross thresholds (e.g., 24/256/etc).
    let seq_worst = u16::try_from(
        limits
            .max_frames
            .saturating_sub(1)
            .min(usize::from(u16::MAX)),
    )
    .unwrap_or(u16::MAX);
    let total_worst =
        u16::try_from(limits.max_frames.min(usize::from(u16::MAX))).unwrap_or(u16::MAX);

    let frame_len_for_chunk_len = |chunk_len: usize| -> Result<usize, ContactDeliveryError> {
        let frame = ContactFrame {
            version: "1.0".into(),
            session_id: session_id.to_vec(),
            message_id,
            // Use worst-case (largest) CBOR integer encodings to avoid underestimating
            // overhead when seq/total cross thresholds (e.g., 24/256/etc).
            seq: seq_worst,
            total: total_worst.max(1),
            chunk: vec![0u8; chunk_len],
        };
        let frame_bytes = encode_contact_frame_cbor(&frame)?;
        Ok(frame_bytes.len())
    };

    // If an empty-chunk frame can't fit, nothing will.
    if frame_len_for_chunk_len(0)? > limits.max_frame_bytes {
        return Err(ContactDeliveryError::FrameTooLarge);
    }

    // Binary search the max chunk len that fits.
    let mut lo = 0usize;
    let mut hi = limits.max_frame_bytes; // upper bound; actual chunk will be smaller
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if frame_len_for_chunk_len(mid)? <= limits.max_frame_bytes {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let max_chunk = lo;
    if max_chunk == 0 && !message_bytes.is_empty() {
        return Err(ContactDeliveryError::FrameTooLarge);
    }

    // Encode frames; if frame size is still exceeded (due to exact seq/total CBOR sizing),
    // shrink the chunk size and retry. This remains deterministic.
    let mut max_chunk = max_chunk;

    loop {
        if message_bytes.is_empty() {
            let frame = ContactFrame {
                version: "1.0".into(),
                session_id: session_id.to_vec(),
                message_id,
                seq: 0,
                total: 1,
                chunk: vec![],
            };

            let frame_bytes = encode_contact_frame_cbor(&frame)?;
            if frame_bytes.len() > limits.max_frame_bytes {
                return Err(ContactDeliveryError::FrameTooLarge);
            }
            return Ok(vec![frame_bytes]);
        }

        if max_chunk == 0 {
            return Err(ContactDeliveryError::FrameTooLarge);
        }

        let total = message_bytes.len().div_ceil(max_chunk).max(1);
        if total > limits.max_frames {
            return Err(ContactDeliveryError::TooManyFrames);
        }
        let total_u16 = u16::try_from(total).map_err(|_| ContactDeliveryError::TooManyFrames)?;

        let mut out = Vec::with_capacity(total);
        let mut too_large = false;

        for (idx, chunk) in message_bytes.chunks(max_chunk).enumerate() {
            let seq_u16 = u16::try_from(idx).map_err(|_| ContactDeliveryError::TooManyFrames)?;

            let frame = ContactFrame {
                version: "1.0".into(),
                session_id: session_id.to_vec(),
                message_id,
                seq: seq_u16,
                total: total_u16,
                chunk: chunk.to_vec(),
            };

            let frame_bytes = encode_contact_frame_cbor(&frame)?;
            if frame_bytes.len() > limits.max_frame_bytes {
                too_large = true;
                break;
            }
            out.push(frame_bytes);
        }

        if !too_large {
            return Ok(out);
        }

        max_chunk = max_chunk.saturating_sub(1);
    }
}

/// Reassemble CBOR-encoded frames into the original message bytes.
pub fn reassemble_frames(
    frames_cbor: &[Vec<u8>],
    limits: &ContactLimits,
) -> Result<Vec<u8>, ContactDeliveryError> {
    limits.validate()?;
    if frames_cbor.is_empty() {
        return Err(ContactDeliveryError::InvalidInput);
    }
    if frames_cbor.len() > limits.max_frames {
        return Err(ContactDeliveryError::TooManyFrames);
    }

    let mut frames: Vec<ContactFrame> = Vec::with_capacity(frames_cbor.len());
    for b in frames_cbor {
        if b.len() > limits.max_frame_bytes {
            return Err(ContactDeliveryError::FrameTooLarge);
        }
        frames.push(decode_contact_frame_cbor(b)?);
    }

    // Ensure all share the same session/message and total.
    let first = &frames[0];
    if first.session_id.len() != limits.session_id_len {
        return Err(ContactDeliveryError::InvalidInput);
    }
    let total = usize::from(first.total);
    if total == 0 || total > limits.max_frames {
        return Err(ContactDeliveryError::InvalidInput);
    }
    if frames.len() != total {
        return Err(ContactDeliveryError::InvalidInput);
    }

    for f in &frames {
        if f.version != "1.0" {
            return Err(ContactDeliveryError::InvalidInput);
        }
        if f.session_id != first.session_id
            || f.message_id != first.message_id
            || f.total != first.total
        {
            return Err(ContactDeliveryError::InvalidInput);
        }
    }

    // Sort by seq and ensure contiguous.
    frames.sort_by_key(|f| f.seq);
    for (i, f) in frames.iter().enumerate() {
        if usize::from(f.seq) != i {
            return Err(ContactDeliveryError::InvalidInput);
        }
    }

    let mut out = Vec::new();
    for f in frames {
        out.extend_from_slice(&f.chunk);
        if out.len() > limits.max_message_bytes {
            return Err(ContactDeliveryError::MessageTooLarge);
        }
    }

    Ok(out)
}
