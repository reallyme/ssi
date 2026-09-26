// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::contains_unsafe_text_chars;

#[test]
fn accepts_printable_text_including_non_latin_scripts() {
    for value in [
        "ETSI EN 319 401",
        "Prüfstelle GmbH",
        "مزود الخدمة",
        "信頼サービス",
    ] {
        assert!(!contains_unsafe_text_chars(value), "{value}");
    }
}

#[test]
fn rejects_control_separator_and_bidi_characters() {
    for value in [
        "line\nbreak",
        "carriage\rreturn",
        "tab\tseparated",
        "nul\0byte",
        "escape\u{1B}[31m",
        "delete\u{7F}",
        "c1\u{85}control",
        "line\u{2028}separator",
        "paragraph\u{2029}separator",
        "arabic\u{061C}mark",
        "ltr\u{200E}mark",
        "rtl\u{200F}mark",
        "override\u{202E}txt.exe",
        "embedding\u{202A}start",
        "isolate\u{2066}start",
        "isolate\u{2069}end",
    ] {
        assert!(contains_unsafe_text_chars(value), "{value:?}");
    }
}
