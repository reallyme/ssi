// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn disclosure_dependencies(path: &str) -> Vec<String> {
    if !path.starts_with("$.") {
        return vec![path.to_string()];
    }

    let mut out = Vec::new();
    let chars: Vec<char> = path.chars().collect();
    for (index, character) in chars.iter().enumerate().skip(1) {
        if *character == '.' || *character == '[' {
            let prefix: String = chars.iter().take(index).collect();
            if prefix.len() > 2 {
                out.push(prefix);
            }
        }
    }

    out.push(path.to_string());
    out.sort();
    out.dedup();
    out
}
