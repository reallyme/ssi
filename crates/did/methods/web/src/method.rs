// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure did:web identifier parsing, canonicalization, and URL derivation.

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

use crate::error::{DidWebError, DidWebErrorReason};

const DID_WEB_PREFIX: &str = "did:web:";
const PORT_COLON: &str = "%3A";
const DID_JSON_NAME: &str = "did.json";
const WELL_KNOWN_PATH: &str = ".well-known";
const MAX_DID_LEN: usize = 4 * 1024;
const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
const MAX_PATH_SEGMENT_LEN: usize = 255;
const MAX_PATH_SEGMENTS: usize = 32;

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}')
    .add(b'~');

/// Parsed canonical did:web identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidWebIdentifier {
    canonical: String,
    domain: String,
    port: Option<u16>,
    path_segments: Vec<String>,
}

impl DidWebIdentifier {
    /// Borrow the canonical DID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Borrow the canonical DNS authority name.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Return the optional explicitly encoded port.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// Borrow canonical percent-encoded path segments.
    #[must_use]
    pub fn path_segments(&self) -> &[String] {
        &self.path_segments
    }
}

/// Input used to generate a did:web identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebDidInput<'a> {
    /// Canonical lowercase fully-qualified ASCII DNS name.
    pub domain: &'a str,
    /// Optional nonzero TCP port.
    pub port: Option<u16>,
    /// Unencoded UTF-8 path segments.
    pub path_segments: &'a [&'a str],
}

/// Generate a canonical did:web identifier from structured input.
pub fn generate_did_web(input: WebDidInput<'_>) -> Result<String, DidWebError> {
    validate_domain(input.domain)?;
    if input.path_segments.len() > MAX_PATH_SEGMENTS {
        return Err(DidWebError::new(DidWebErrorReason::InvalidPath));
    }

    let mut did = String::from(DID_WEB_PREFIX);
    did.push_str(input.domain);
    if let Some(port) = input.port {
        if port == 0 {
            return Err(DidWebError::new(DidWebErrorReason::InvalidPort));
        }
        did.push_str(PORT_COLON);
        did.push_str(&port.to_string());
    }

    for segment in input.path_segments {
        if segment.is_empty() || segment == &"." || segment == &".." {
            return Err(DidWebError::new(DidWebErrorReason::InvalidPath));
        }
        let encoded = utf8_percent_encode(segment, PATH_SEGMENT_ENCODE_SET).to_string();
        if encoded.len() > MAX_PATH_SEGMENT_LEN {
            return Err(DidWebError::new(DidWebErrorReason::InvalidPath));
        }
        did.push(':');
        did.push_str(&encoded);
    }

    parse_did_web(&did)?;
    Ok(did)
}

/// Parse and require the canonical did:web representation.
pub fn parse_did_web(did: &str) -> Result<DidWebIdentifier, DidWebError> {
    if did.len() > MAX_DID_LEN {
        return Err(DidWebError::new(DidWebErrorReason::IdentifierTooLong));
    }
    let method_specific = did
        .strip_prefix(DID_WEB_PREFIX)
        .ok_or(DidWebError::new(DidWebErrorReason::InvalidPrefix))?;
    let mut parts = method_specific.split(':');
    let authority = parts
        .next()
        .ok_or(DidWebError::new(DidWebErrorReason::InvalidDomain))?;
    let (domain, port) = parse_authority(authority)?;
    let path_segments: Vec<String> = parts
        .map(|segment| {
            let normalized = validate_path_segment(segment)?;
            if normalized != segment {
                return Err(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding));
            }
            Ok(normalized)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if path_segments.len() > MAX_PATH_SEGMENTS {
        return Err(DidWebError::new(DidWebErrorReason::InvalidPath));
    }

    Ok(DidWebIdentifier {
        canonical: did.to_owned(),
        domain: domain.to_owned(),
        port,
        path_segments,
    })
}

/// Normalize domain case and percent-escape case into the canonical form.
pub fn canonicalize_did_web(did: &str) -> Result<String, DidWebError> {
    if did.len() > MAX_DID_LEN {
        return Err(DidWebError::new(DidWebErrorReason::IdentifierTooLong));
    }
    let method_specific = did
        .strip_prefix(DID_WEB_PREFIX)
        .ok_or(DidWebError::new(DidWebErrorReason::InvalidPrefix))?;
    let normalized = normalize_percent_escapes(method_specific)?;
    let mut parts = normalized.split(':');
    let authority = parts
        .next()
        .ok_or(DidWebError::new(DidWebErrorReason::InvalidDomain))?;
    let normalized_authority = normalize_authority(authority)?;
    let mut canonical = String::from(DID_WEB_PREFIX);
    canonical.push_str(&normalized_authority);
    for segment in parts {
        let canonical_segment = validate_path_segment(segment)?;
        canonical.push(':');
        canonical.push_str(&canonical_segment);
    }
    parse_did_web(&canonical)?;
    Ok(canonical)
}

/// Map a canonical did:web identifier to its HTTPS DID document URL.
pub fn did_web_document_url(did: &str) -> Result<String, DidWebError> {
    let parsed = parse_did_web(did)?;
    let mut url = String::from("https://");
    url.push_str(parsed.domain());
    if let Some(port) = parsed.port() {
        url.push(':');
        url.push_str(&port.to_string());
    }
    url.push('/');
    if parsed.path_segments().is_empty() {
        url.push_str(WELL_KNOWN_PATH);
    } else {
        url.push_str(&parsed.path_segments().join("/"));
    }
    url.push('/');
    url.push_str(DID_JSON_NAME);
    Ok(url)
}

/// Return true when the DID is syntactically valid and canonical.
#[must_use]
pub fn is_valid_did_web(did: &str) -> bool {
    parse_did_web(did).is_ok()
}

fn parse_authority(authority: &str) -> Result<(&str, Option<u16>), DidWebError> {
    if authority.match_indices(PORT_COLON).count() > 1 || authority.contains("%3a") {
        return Err(DidWebError::new(DidWebErrorReason::InvalidPort));
    }
    let (domain, port) = match authority.find(PORT_COLON) {
        Some(index) => {
            let port_start = index
                .checked_add(PORT_COLON.len())
                .ok_or(DidWebError::new(DidWebErrorReason::InvalidPort))?;
            (&authority[..index], Some(&authority[port_start..]))
        }
        None => (authority, None),
    };
    validate_domain(domain)?;
    Ok((domain, port.map(parse_port).transpose()?))
}

fn normalize_authority(authority: &str) -> Result<String, DidWebError> {
    let normalized = authority.replace("%3a", PORT_COLON);
    let lower = normalized.to_ascii_lowercase().replace("%3a", PORT_COLON);
    let (domain, port) = parse_authority(&lower)?;
    let mut output = domain.to_owned();
    if let Some(port) = port {
        output.push_str(PORT_COLON);
        output.push_str(&port.to_string());
    }
    Ok(output)
}

fn parse_port(port: &str) -> Result<u16, DidWebError> {
    if port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || (port.len() > 1 && port.starts_with('0'))
    {
        return Err(DidWebError::new(DidWebErrorReason::InvalidPort));
    }
    let parsed = port
        .parse::<u16>()
        .map_err(|_| DidWebError::new(DidWebErrorReason::InvalidPort))?;
    if parsed == 0 {
        return Err(DidWebError::new(DidWebErrorReason::InvalidPort));
    }
    Ok(parsed)
}

fn validate_domain(domain: &str) -> Result<(), DidWebError> {
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_LEN
        || domain != domain.to_ascii_lowercase()
        || domain.bytes().any(|byte| !byte.is_ascii())
        || domain
            .bytes()
            .any(|byte| matches!(byte, b':' | b'/' | b'%' | b'?' | b'#' | b'@'))
        || domain.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(DidWebError::new(DidWebErrorReason::InvalidDomain));
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err(DidWebError::new(DidWebErrorReason::InvalidDomain));
    }
    for label in labels {
        if label.is_empty()
            || label.len() > MAX_LABEL_LEN
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(DidWebError::new(DidWebErrorReason::InvalidDomain));
        }
    }
    Ok(())
}

fn validate_path_segment(segment: &str) -> Result<String, DidWebError> {
    if segment.is_empty() || segment.len() > MAX_PATH_SEGMENT_LEN {
        return Err(DidWebError::new(DidWebErrorReason::InvalidPath));
    }
    let normalized = normalize_percent_escapes(segment)?;
    if normalized
        .bytes()
        .filter(|byte| *byte != b'%')
        .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(DidWebError::new(DidWebErrorReason::InvalidPath));
    }
    let decoded = percent_decode_for_validation(&normalized)?;
    // A decoded separator would change the HTTPS path structure once a server
    // decodes the segment, so encoded `/` and `\` are rejected.
    if decoded == b"."
        || decoded == b".."
        || decoded.iter().any(|byte| matches!(byte, b'/' | b'\\'))
        || core::str::from_utf8(&decoded).is_err()
    {
        return Err(DidWebError::new(DidWebErrorReason::InvalidPath));
    }
    if normalized
        .bytes()
        .any(|byte| matches!(byte, b'/' | b'?' | b'#'))
    {
        return Err(DidWebError::new(DidWebErrorReason::InvalidPath));
    }
    Ok(normalized)
}

fn normalize_percent_escapes(value: &str) -> Result<String, DidWebError> {
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte != b'%' {
            if !byte.is_ascii() || byte.is_ascii_control() || byte == b' ' {
                return Err(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding));
            }
            output.push(char::from(byte));
            index = index
                .checked_add(1)
                .ok_or(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding))?;
            continue;
        }
        let first_index = index
            .checked_add(1)
            .ok_or(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding))?;
        let second_index = index
            .checked_add(2)
            .ok_or(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding))?;
        let first = *bytes
            .get(first_index)
            .ok_or(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding))?;
        let second = *bytes
            .get(second_index)
            .ok_or(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding))?;
        let decoded = decode_hex(first, second)?;
        // Characters that DID syntax allows raw (`idchar`) must not be
        // percent-encoded. `~` is not a DID `idchar`, so `%7E` is its only
        // valid spelling and is accepted here.
        if decoded.is_ascii_alphanumeric() || matches!(decoded, b'-' | b'.' | b'_') {
            return Err(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding));
        }
        output.push('%');
        output.push(char::from(first.to_ascii_uppercase()));
        output.push(char::from(second.to_ascii_uppercase()));
        index = index
            .checked_add(3)
            .ok_or(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding))?;
    }
    Ok(output)
}

fn percent_decode_for_validation(value: &str) -> Result<Vec<u8>, DidWebError> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let first_index = index
                .checked_add(1)
                .ok_or(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding))?;
            let second_index = index
                .checked_add(2)
                .ok_or(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding))?;
            let first = *bytes
                .get(first_index)
                .ok_or(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding))?;
            let second = *bytes
                .get(second_index)
                .ok_or(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding))?;
            let decoded = decode_hex(first, second)?;
            if decoded == 0 || decoded.is_ascii_control() {
                return Err(DidWebError::new(DidWebErrorReason::InvalidPath));
            }
            output.push(decoded);
            index = index
                .checked_add(3)
                .ok_or(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding))?;
        } else {
            output.push(bytes[index]);
            index = index
                .checked_add(1)
                .ok_or(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding))?;
        }
    }
    Ok(output)
}

fn decode_hex(first: u8, second: u8) -> Result<u8, DidWebError> {
    let high = hex_nibble(first)?;
    let low = hex_nibble(second)?;
    Ok((high << 4) | low)
}

fn hex_nibble(value: u8) -> Result<u8, DidWebError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(DidWebError::new(DidWebErrorReason::InvalidPercentEncoding)),
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
