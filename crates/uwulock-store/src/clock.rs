//! Time, written one way.
//!
//! Every time in the database is text like `2026-09-25T12:00:00.000000Z`: UTC, to the
//! microsecond, the way Bitwarden's clients get it. So it sorts the way it reads, compares as
//! text, and goes out to a client without being converted.

use time::format_description::FormatItem;
use time::macros::format_description;
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

const FORMAT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z");

/// Now, in the database's format.
pub fn now() -> String {
    format(OffsetDateTime::now_utc())
}

/// `when`, in the database's format.
pub fn format(when: OffsetDateTime) -> String {
    when.to_offset(time::UtcOffset::UTC).format(FORMAT).expect("a UTC time always formats")
}

/// `seconds` from now (or ago, when negative), in the database's format.
pub fn in_seconds(seconds: i64) -> String {
    format(OffsetDateTime::now_utc() + Duration::seconds(seconds))
}

/// A time as the database writes it, or as a client sends one back: RFC 3339 with any number
/// of fractional digits, `Z` or an offset.
pub fn parse(text: &str) -> Option<OffsetDateTime> {
    if let Ok(when) = OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339) {
        return Some(when);
    }
    // Some clients leave out the zone; Bitwarden means UTC then.
    PrimitiveDateTime::parse(
        text.trim_end_matches('Z'),
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second][optional [.[subsecond]]]"),
    )
    .ok()
    .map(PrimitiveDateTime::assume_utc)
}

/// Milliseconds since 1970 for a time in the database's format, as `/accounts/revision-date`
/// answers. Nothing for text that is not a time.
pub fn millis(text: &str) -> Option<i64> {
    parse(text).map(|when| (when.unix_timestamp_nanos() / 1_000_000) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_written_the_way_the_clients_get_them() {
        let text = now();
        assert_eq!(text.len(), 27, "{text}");
        assert!(text.ends_with('Z') && text.as_bytes()[19] == b'.', "{text}");
        assert!(parse(&text).is_some());
    }

    #[test]
    fn what_clients_send_back_is_understood() {
        for text in [
            "2026-09-25T12:00:00Z",
            "2026-09-25T12:00:00.123Z",
            "2026-09-25T12:00:00.1234567Z",
            "2026-09-25T14:00:00+02:00",
            "2026-09-25T12:00:00.5",
        ] {
            let when = parse(text).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(when.to_offset(time::UtcOffset::UTC).hour(), 12, "{text}");
        }
        assert!(parse("yesterday").is_none());
    }

    #[test]
    fn they_sort_as_text() {
        let earlier = in_seconds(-1);
        let later = in_seconds(1);
        assert!(earlier < now() && now() < later);
        assert_eq!(millis("1970-01-01T00:00:01.000000Z"), Some(1000));
    }
}
