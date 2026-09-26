// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Character screening for audit-facing text fields.

/// Return true when `value` contains characters that can corrupt or disguise
/// audit records when rendered: Unicode control characters (general category
/// Cc, including CR, LF, TAB, and NUL), line and paragraph separators, and
/// bidirectional formatting characters that reorder displayed text
/// (Unicode Technical Standard #39 / CVE-2021-42574 "Trojan Source").
pub(crate) fn contains_unsafe_text_chars(value: &str) -> bool {
    value.chars().any(is_unsafe_char)
}

fn is_unsafe_char(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            // ARABIC LETTER MARK
            '\u{061C}'
            // LEFT-TO-RIGHT MARK, RIGHT-TO-LEFT MARK
            | '\u{200E}' | '\u{200F}'
            // LINE SEPARATOR, PARAGRAPH SEPARATOR
            | '\u{2028}' | '\u{2029}'
            // LRE, RLE, PDF, LRO, RLO
            | '\u{202A}'..='\u{202E}'
            // LRI, RLI, FSI, PDI
            | '\u{2066}'..='\u{2069}'
        )
}

#[cfg(test)]
#[path = "screen_text_tests.rs"]
mod tests;
