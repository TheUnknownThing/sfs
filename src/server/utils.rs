use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use sqlx::Error as SqlxError;
use std::path::Path;
use time::OffsetDateTime;

use crate::templates::PasteLanguageOption;

use super::constants::{CODE_ALPHABET, CODE_SEGMENT_LENGTH, CODE_TOTAL_LENGTH};

/// Human-friendly byte size formatter used in multiple views.
pub fn human_readable_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_index = 0;

    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit_index])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit_index])
    } else {
        format!("{value:.2} {}", UNITS[unit_index])
    }
}

/// Format an [`OffsetDateTime`] in the canonical UTC display format.
pub fn format_datetime_utc(dt: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute()
    )
}

/// Generate a short two-segment download code (e.g. `ABCD-EFGH`).
pub fn generate_download_code() -> String {
    let raw = nanoid::nanoid!(CODE_TOTAL_LENGTH, &CODE_ALPHABET);
    format!(
        "{}-{}",
        &raw[..CODE_SEGMENT_LENGTH],
        &raw[CODE_SEGMENT_LENGTH..]
    )
}

/// Resolve a user-provided paste language string into a known option.
pub fn resolve_paste_language<'a>(
    value: &str,
    languages: &'a [PasteLanguageOption],
) -> &'a PasteLanguageOption {
    assert!(
        !languages.is_empty(),
        "PASTE_LANGUAGES must contain at least one entry"
    );

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return &languages[0];
    }

    languages
        .iter()
        .find(|option| option.value.eq_ignore_ascii_case(trimmed))
        .unwrap_or(&languages[0])
}

/// Normalise a public file code into the canonical `XXXX-XXXX` format.
pub fn normalize_lookup_code(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut normalized = String::with_capacity(CODE_TOTAL_LENGTH + 1);
    let mut collected = Vec::with_capacity(CODE_TOTAL_LENGTH);

    for ch in trimmed.chars() {
        if ch == '-' || ch.is_ascii_whitespace() {
            continue;
        }

        if !ch.is_ascii() {
            return None;
        }

        collected.push(ch.to_ascii_uppercase());
    }

    if collected.len() != CODE_TOTAL_LENGTH {
        return None;
    }

    for (index, ch) in collected.into_iter().enumerate() {
        if !CODE_ALPHABET.contains(&ch) {
            return None;
        }

        if index == CODE_SEGMENT_LENGTH {
            normalized.push('-');
        }

        normalized.push(ch);
    }

    Some(normalized)
}

/// Produce a filesystem-safe file name, falling back to a default when necessary.
pub fn sanitize_filename(raw: Option<&str>) -> String {
    const FALLBACK: &str = "upload.bin";
    let Some(name) = raw else {
        return FALLBACK.to_string();
    };

    let trimmed = name.trim();
    if trimmed.is_empty() {
        return FALLBACK.to_string();
    }

    let candidate = Path::new(trimmed)
        .file_name()
        .and_then(|segment| segment.to_str())
        .unwrap_or(FALLBACK);

    let cleaned: String = candidate.chars().filter(|c| !c.is_control()).collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return FALLBACK.to_string();
    }

    cleaned.chars().take(255).collect()
}

/// Desired presentation mode for `Content-Disposition` headers.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ContentDisposition {
    Attachment,
    Inline,
}

/// Build a Content-Disposition header value with ASCII fallback and optional inline behaviour.
pub fn build_content_disposition_header(filename: &str, mode: ContentDisposition) -> HeaderValue {
    let mut fallback = String::with_capacity(filename.len());
    let mut contains_non_ascii = false;

    for ch in filename.chars() {
        if matches!(ch, ' '..='~') && ch != '"' && ch != '\\' {
            fallback.push(ch);
        } else {
            contains_non_ascii |= !ch.is_ascii();
            fallback.push('_');
        }
    }

    if fallback.is_empty() {
        fallback.push_str("download.bin");
    }

    if fallback.len() > 255 {
        fallback.truncate(255);
    }

    let truncated_original: String = filename.chars().take(255).collect();
    let needs_extended = contains_non_ascii || truncated_original.len() != filename.len();

    let disposition = match mode {
        ContentDisposition::Attachment => "attachment",
        ContentDisposition::Inline => "inline",
    };

    let header_value = if needs_extended {
        let encoded = encode_filename_for_rfc5987(&truncated_original);
        format!("{disposition}; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
    } else {
        format!("{disposition}; filename=\"{fallback}\"")
    };

    let fallback_header = match mode {
        ContentDisposition::Attachment => HeaderValue::from_static("attachment"),
        ContentDisposition::Inline => HeaderValue::from_static("inline"),
    };

    HeaderValue::from_str(&header_value).unwrap_or(fallback_header)
}

/// Percent-encode a filename for RFC 5987 usage.
pub fn encode_filename_for_rfc5987(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());

    for byte in input.as_bytes() {
        match *byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'&'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~' => encoded.push(*byte as char),
            _ => {
                encoded.push('%');
                encoded.push_str(&format!("{:02X}", byte));
            }
        }
    }

    encoded
}

/// Translate a SQLx database error into a uniqueness constraint violation check.
pub fn is_unique_violation(err: &SqlxError) -> bool {
    match err {
        SqlxError::Database(db_err) => db_err
            .code()
            .map(|code| code.as_ref() == "2067" || code.as_ref() == "1555")
            .unwrap_or(false),
        _ => false,
    }
}

/// Canonical application server error response body.
pub fn server_error_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Unable to process your request. Please try again later.",
    )
        .into_response()
}

/// Shared response for missing file codes.
pub fn file_not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        "We couldn't find a file with that code. Double-check the code and try again.",
    )
        .into_response()
}

/// Shared response for expired files.
pub fn file_expired_response() -> Response {
    (
        StatusCode::GONE,
        "This file is no longer available. The link has expired.",
    )
        .into_response()
}

/// Response used when a direct download token cannot be verified.
pub fn download_unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        "That direct link is no longer valid. Visit the file page to generate a new one.",
    )
        .into_response()
}

/// Convenience for attaching a `Retry-After` header to rate-limited responses.
pub fn attach_retry_after(response: &mut Response, seconds: u64) {
    if let Ok(value) = HeaderValue::from_str(&seconds.max(1).to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
}
