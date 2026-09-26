// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{validate_json, JsonBoundaryError, JsonBoundaryErrorReason};

#[test]
fn accepts_nested_unique_names_and_scalar_types() {
    assert_eq!(
        validate_json(br#"{"a":[null,true,1,-1,1.5,"x",{"a":2}]}"#),
        Ok(())
    );
}

#[test]
fn rejects_ambiguous_malformed_and_unbounded_documents() {
    let invalid = Err(JsonBoundaryError {
        reason: JsonBoundaryErrorReason::InvalidDocument,
    });
    for input in [
        br#"{"id":1,"id":2}"#.as_slice(),
        br#"{"id":1,"\u0069d":2}"#,
        br#"[{"key":{"x":1,"x":2}}]"#,
        br#"{} {}"#,
        br#"{"x":}"#,
        b"",
    ] {
        assert_eq!(validate_json(input), invalid);
    }
    assert_eq!(
        validate_json(format!("{}0{}", "[".repeat(34), "]".repeat(34)).as_bytes()),
        invalid
    );
    assert_eq!(validate_json(&vec![b' '; 1_048_577]), invalid);
    assert_eq!(
        validate_json(format!("[{}0]", "0,".repeat(16_384)).as_bytes()),
        invalid
    );
}
