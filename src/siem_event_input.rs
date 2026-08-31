//! Bounded, fail-closed parsing and normalization for Wardnet SIEM export events.
//!
//! This module is deliberately free of network and filesystem side effects so
//! the exact production parser can be exercised by stable property tests and
//! coverage-guided fuzzing.

#![forbid(unsafe_code)]

use serde::Deserialize;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::Read;
use std::net::IpAddr;
use waf_ids_core::MAX_ROUTE_ID_CHARS;

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_EVENTS: usize = 100_000;
const MAX_ACTION_CHARS: usize = 64;
const MAX_REASON_CHARS: usize = 2_048;
const MAX_PATH_CHARS: usize = 2_048;

#[derive(Debug, Deserialize)]
struct SourceEvent {
    id: u64,
    timestamp_unix: u64,
    client_ip: Option<IpAddr>,
    route_id: Option<String>,
    action: String,
    reason: String,
    score: u16,
    path: String,
    #[serde(default)]
    trace_id: Option<String>,
    #[serde(default)]
    span_id: Option<String>,
    #[serde(default)]
    trace_flags: Option<String>,
}

/// Validated W3C trace context retained for OTLP and RFC 5424 correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    /// Lowercase 16-byte trace identifier encoded as 32 hexadecimal characters.
    pub trace_id: String,
    /// Lowercase 8-byte span identifier encoded as 16 hexadecimal characters.
    pub span_id: String,
    /// Lowercase one-byte W3C trace flags encoded as two hexadecimal characters.
    pub trace_flags: String,
    /// Numeric trace flags used by OTLP log records.
    pub flags: u8,
}

/// Sanitized Wardnet event safe to hand to a standards-specific renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedEvent {
    /// Positive, strictly increasing Wardnet event identifier.
    pub id: u64,
    /// Positive Unix timestamp in seconds.
    pub timestamp_unix: u64,
    /// Canonical client IP address when the source event provided one.
    pub client_ip: Option<String>,
    /// Sanitized optional Wardnet route identifier.
    pub route_id: Option<String>,
    /// Sanitized enforcement action.
    pub action: String,
    /// Sanitized and credential-redacted decision reason.
    pub reason: String,
    /// Wardnet security score.
    pub score: u16,
    /// Sanitized path with query string and fragment removed.
    pub path: String,
    /// Validated trace context when supplied by the source event.
    pub trace_context: Option<TraceContext>,
}

/// Read, bound, parse, order-check, and normalize one complete NDJSON batch.
///
/// No result is returned until the entire input has passed validation, allowing
/// callers to preserve the exporter's no-partial-output contract.
pub fn read_events<R: Read>(reader: R) -> Result<Vec<NormalizedEvent>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read standard input: {error}"))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("input exceeds the {MAX_INPUT_BYTES}-byte limit"));
    }
    let input = String::from_utf8(bytes).map_err(|_| "input is not valid UTF-8".to_string())?;

    let mut events = Vec::new();
    let mut event_ids = HashSet::new();
    let mut previous_event_id = 0_u64;
    for (line_index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_number = line_index + 1;
        if line.len() > MAX_LINE_BYTES {
            return Err(format!(
                "line {line_number} exceeds the {MAX_LINE_BYTES}-byte limit"
            ));
        }
        if events.len() >= MAX_EVENTS {
            return Err(format!("input contains more than {MAX_EVENTS} events"));
        }
        let source: SourceEvent = serde_json::from_str(line)
            .map_err(|error| format!("line {line_number}: invalid event JSON: {error}"))?;
        if source.id < previous_event_id {
            return Err(format!(
                "line {line_number}: event id {} is lower than previous event id {previous_event_id}",
                source.id
            ));
        }
        if !event_ids.insert(source.id) {
            return Err(format!(
                "line {line_number}: duplicate event id {}",
                source.id
            ));
        }
        previous_event_id = source.id;
        events.push(normalize_event(source, line_number)?);
    }
    Ok(events)
}

fn normalize_event(source: SourceEvent, line_number: usize) -> Result<NormalizedEvent, String> {
    if source.id == 0 {
        return Err(format!("line {line_number}: event id must be positive"));
    }
    if source.timestamp_unix == 0 {
        return Err(format!(
            "line {line_number}: timestamp_unix must be positive"
        ));
    }
    checked_time(source.timestamp_unix, 1_000_000_000, line_number)?;
    let action = required_sanitized("action", &source.action, MAX_ACTION_CHARS, line_number)?;
    let reason = bounded_reason(&source.reason, line_number)?;
    let path = sanitize_path(&source.path, line_number)?;
    let route_id = source
        .route_id
        .as_deref()
        .map(|route| bounded_route_id(route, line_number))
        .transpose()?;
    let trace_context = validate_trace_context(
        source.trace_id.as_deref(),
        source.span_id.as_deref(),
        source.trace_flags.as_deref(),
        line_number,
    )?;

    Ok(NormalizedEvent {
        id: source.id,
        timestamp_unix: source.timestamp_unix,
        client_ip: source.client_ip.map(|address| address.to_string()),
        route_id,
        action,
        reason,
        score: source.score,
        path,
        trace_context,
    })
}

fn required_sanitized(
    field: &str,
    value: &str,
    maximum: usize,
    line_number: usize,
) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("line {line_number}: {field} must not be empty"));
    }
    if value.chars().count() > maximum {
        return Err(format!(
            "line {line_number}: {field} exceeds the {maximum}-character limit"
        ));
    }
    let sanitized = sanitize_text(value, maximum);
    if sanitized.is_empty() {
        return Err(format!(
            "line {line_number}: {field} contains no exportable text"
        ));
    }
    Ok(sanitized)
}

fn bounded_reason(value: &str, line_number: usize) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("line {line_number}: reason must not be empty"));
    }
    let original_chars = value.chars().count();
    let sanitized = sanitize_text(value, usize::MAX);
    if sanitized.is_empty() {
        return Err(format!(
            "line {line_number}: reason contains no exportable text"
        ));
    }
    if sanitized.chars().count() <= MAX_REASON_CHARS {
        return Ok(sanitized);
    }

    let marker = format!(" [TRUNCATED; original_chars={original_chars}]");
    let prefix_chars = MAX_REASON_CHARS.saturating_sub(marker.chars().count());
    Ok(format!(
        "{}{}",
        truncate_chars(&sanitized, prefix_chars),
        marker
    ))
}

fn bounded_route_id(value: &str, line_number: usize) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("line {line_number}: route_id must not be empty"));
    }
    let sanitized = sanitize_text(value, usize::MAX);
    if sanitized.is_empty() {
        return Err(format!(
            "line {line_number}: route_id contains no exportable text"
        ));
    }
    if sanitized.chars().count() <= MAX_ROUTE_ID_CHARS {
        return Ok(sanitized);
    }

    let suffix = route_id_suffix(value);
    let prefix_chars = MAX_ROUTE_ID_CHARS.saturating_sub(suffix.chars().count() + 1);
    Ok(format!(
        "{}~{suffix}",
        truncate_chars(&sanitized, prefix_chars)
    ))
}

fn route_id_suffix(value: &str) -> String {
    // Distinguish oversized legacy IDs that share the same visible prefix
    // without letting the exported identifier exceed the shared route limit.
    let mut hash = 0x811c9dc5_u32;
    for byte in value.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }

    let mut output = String::with_capacity(8);
    write!(&mut output, "{hash:08x}").expect("write hash");
    output
}

fn sanitize_path(value: &str, line_number: usize) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("line {line_number}: path must not be empty"));
    }
    let end = value
        .char_indices()
        .find_map(|(index, character)| matches!(character, '?' | '#').then_some(index))
        .unwrap_or(value.len());
    let path_value = &value[..end];
    if path_value.chars().count() > MAX_PATH_CHARS {
        return Err(format!(
            "line {line_number}: path exceeds the {MAX_PATH_CHARS}-character limit"
        ));
    }
    let path = sanitize_text(path_value, MAX_PATH_CHARS);
    if path.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(path)
    }
}

fn sanitize_text(value: &str, maximum: usize) -> String {
    let normalized: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();

    let mut output = String::new();
    let mut redact_next = false;
    let mut quote_pending: Option<char> = None;
    for token in normalized.split_whitespace() {
        if !output.is_empty() {
            output.push(' ');
        }
        if let Some(quote) = quote_pending {
            // A quoted credential value (e.g. `password="hunter two"`)
            // opened in an earlier whitespace-delimited token and has not
            // closed yet. Redact this whole token rather than re-parsing it
            // as an unrelated key/value pair, so the space inside the quoted
            // value cannot leak a trailing fragment in plaintext.
            output.push_str("[REDACTED]");
            if token.contains(quote) {
                quote_pending = None;
            }
            redact_next = false;
            continue;
        }
        let (redacted, keep_redacting) = if redact_next && matches!(token, ":" | "=") {
            // Operators commonly render assignments with whitespace around
            // the separator (`token = value`). The separator is not the
            // credential, so retain it and redact the following token.
            (token.to_string(), true)
        } else if redact_next {
            let separator = token
                .chars()
                .next()
                .filter(|character| matches!(character, ':' | '='));
            let redacted = separator.map_or_else(
                || "[REDACTED]".to_string(),
                |separator| format!("{separator}[REDACTED]"),
            );
            // Preserve the two-token `Authorization: Bearer value` chain.
            (redacted, is_authorization_marker(token))
        } else {
            let redacted = redact_token(token);
            (redacted, is_authorization_marker(token))
        };
        if redacted != token
            && let Some(quote) = unclosed_quote(token)
        {
            quote_pending = Some(quote);
        }
        output.push_str(&redacted);
        redact_next = keep_redacting;
    }
    truncate_chars(&output, maximum)
}

/// Returns the quote character if `token` contains an odd number of `"` or
/// `'`, meaning a quoted value inside it was opened but not closed within
/// this single whitespace-delimited token.
fn unclosed_quote(token: &str) -> Option<char> {
    ['"', '\'']
        .into_iter()
        .find(|quote| token.matches(*quote).count() % 2 == 1)
}

/// Marker names that indicate the following token (or an `=`/`:` assignment
/// within the same token) carries a credential value. Compared after
/// lower-casing and folding `-` to `_` so header-style names (`X-Api-Key`,
/// `access-token`) match the same canonical set as `api_key`/`access_token`.
const MARKER_NAMES: [&str; 9] = [
    "authorization",
    "bearer",
    "basic",
    "token",
    "password",
    "secret",
    "api_key",
    "apikey",
    "access_token",
];

fn canonicalize_marker(token: &str) -> String {
    token.to_ascii_lowercase().replace('-', "_")
}

fn is_authorization_marker(token: &str) -> bool {
    let marker = canonicalize_marker(token.trim_end_matches([':', '=']));
    MARKER_NAMES
        .iter()
        .any(|candidate| marker == *candidate || marker == format!("x_{candidate}"))
}

fn redact_token(token: &str) -> String {
    // `access_token`/`api_key`/... trigger on assignment (`key=value` or
    // `key:value` inside one token); `bearer`/`basic` are marker-only,
    // so they are excluded here (they redact the *next* token instead,
    // via `is_authorization_marker`).
    let normalized = canonicalize_marker(token);
    for name in MARKER_NAMES
        .iter()
        .filter(|name| !matches!(**name, "bearer" | "basic"))
    {
        for variant in [name.to_string(), format!("x_{name}")] {
            for separator in ['=', ':'] {
                let key = format!("{variant}{separator}");
                if let Some(index) = boundary_match_index(&normalized, &key) {
                    // A bare `token:`/`password=` token is a marker whose
                    // value follows after whitespace, not an assignment with
                    // an empty credential value.
                    if index + key.len() == token.len() {
                        continue;
                    }
                    return format!(
                        "{}{}[REDACTED]",
                        &token[..index],
                        &token[index..index + key.len()]
                    );
                }
            }
        }
    }

    const SECRET_PREFIXES: [&str; 6] = ["sk-", "ghp_", "github_pat_", "xoxb-", "xoxp-", "AIza"];
    for prefix in SECRET_PREFIXES {
        if let Some(index) = boundary_match_index(token, prefix) {
            return format!("{}[REDACTED]", &token[..index]);
        }
    }
    token.to_string()
}

/// Find `needle` in `haystack` at a word boundary: not immediately preceded
/// by an alphanumeric character or `_`. Prevents `token:` from matching
/// inside `access-token:` (normalized `access_token:`) as though it were a
/// bare `token:` assignment.
fn boundary_match_index(haystack: &str, needle: &str) -> Option<usize> {
    haystack.match_indices(needle).find_map(|(index, _)| {
        let boundary = match haystack[..index].chars().next_back() {
            None => true,
            Some(character) => !character.is_ascii_alphanumeric() && character != '_',
        };
        boundary.then_some(index)
    })
}

/// Return whether a label contains material that resembles an authorization
/// marker, assignment, or common secret prefix and therefore must be rejected.
pub fn contains_secret_marker(value: &str) -> bool {
    let mut redact_next = false;
    for token in value.split_whitespace() {
        if redact_next || redact_token(token) != token {
            return true;
        }
        redact_next = is_authorization_marker(token);
    }
    false
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value.to_string();
    }
    value.chars().take(maximum).collect()
}

fn validate_trace_context(
    trace_id: Option<&str>,
    span_id: Option<&str>,
    trace_flags: Option<&str>,
    line_number: usize,
) -> Result<Option<TraceContext>, String> {
    match (trace_id, span_id, trace_flags) {
        (None, None, None) => Ok(None),
        (Some(trace_id), Some(span_id), flags) => {
            let trace_id = validate_hex_identifier("trace id", trace_id, 32, line_number)?;
            let span_id = validate_hex_identifier("span id", span_id, 16, line_number)?;
            let trace_flags = flags.unwrap_or("00");
            if trace_flags.len() != 2 || !trace_flags.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!(
                    "line {line_number}: trace context has invalid trace flags"
                ));
            }
            let normalized_flags = trace_flags.to_ascii_lowercase();
            let flags = u8::from_str_radix(&normalized_flags, 16).map_err(|_| {
                format!("line {line_number}: trace context has invalid trace flags")
            })?;
            if flags & !0x01 != 0 {
                return Err(format!(
                    "line {line_number}: trace context has unsupported trace flags"
                ));
            }
            Ok(Some(TraceContext {
                trace_id,
                span_id,
                trace_flags: normalized_flags,
                flags,
            }))
        }
        _ => Err(format!(
            "line {line_number}: trace context requires trace_id and span_id together"
        )),
    }
}

fn validate_hex_identifier(
    label: &str,
    value: &str,
    required_length: usize,
    line_number: usize,
) -> Result<String, String> {
    if value.len() != required_length
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err(format!(
            "line {line_number}: trace context has invalid {label}"
        ));
    }
    Ok(value.to_ascii_lowercase())
}

/// Multiply a Unix-seconds value by a renderer-specific scale without overflow.
pub fn checked_time(value: u64, multiplier: u64, line_number: usize) -> Result<u64, String> {
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("line {line_number}: timestamp_unix is out of range"))
}
