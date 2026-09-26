// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn disclosure_dependencies(path: &str) -> Vec<String> {
    if !path.starts_with("$.") {
        return vec![path.to_string()];
    }

    let mut out = Vec::new();
    let chars: Vec<char> = path.chars().collect();
    let mut i = 1usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '.' || c == '[' {
            let prefix: String = chars[..i].iter().collect();
            if prefix.len() > 2 {
                out.push(prefix);
            }
        }
        i += 1;
    }

    out.push(path.to_string());
    out.sort();
    out.dedup();
    out
}
