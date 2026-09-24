// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn collect_expected_digests(
    value: &Value,
    out: &mut BTreeSet<String>,
) -> Result<(), IetfSdJwtVcError> {
    match value {
        Value::Object(map) => {
            if let Some(sd) = map.get("_sd") {
                let arr = sd.as_array().ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
                for v in arr {
                    let s = v.as_str().ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
                    out.insert(s.to_string());
                }
            }
            if let Some(placeholder) = map.get("...") {
                let s = placeholder
                    .as_str()
                    .ok_or(IetfSdJwtVcError::InvalidSdClaim)?;
                out.insert(s.to_string());
            }
            for (k, v) in map {
                if k != "_sd" && k != "_sd_alg" && k != "..." {
                    collect_expected_digests(v, out)?;
                }
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_expected_digests(v, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

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
