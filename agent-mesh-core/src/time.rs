//! Millisecond timestamps and RFC 3339 rendering.
//!
//! The store orders by an integer sequence, never by a clock, so time here is only ever for
//! display and for deadlines. That is why a dependency-free UTC formatter is enough: nothing
//! correctness-critical rests on it.

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    let now = std::time::SystemTime::now();
    match now.duration_since(std::time::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_millis()).unwrap_or(i64::MAX),
        // A clock before 1970 is not worth a panic; deadlines still work relative to each other.
        Err(err) => -i64::try_from(err.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

/// Render epoch milliseconds as RFC 3339 in UTC, e.g. `2026-09-03T14:14:22.031Z`.
pub fn rfc3339(ms: i64) -> String {
    let (days, ms_of_day) = {
        let days = ms.div_euclid(86_400_000);
        let rem = ms.rem_euclid(86_400_000);
        (days, rem)
    };
    let (year, month, day) = civil_from_days(days);
    let seconds_of_day = ms_of_day / 1000;
    let millis = ms_of_day % 1000;
    let (hour, minute, second) = (
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60,
    );
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Howard Hinnant's `civil_from_days`, valid for the whole proleptic Gregorian range.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parse a human duration such as `10m`, `30s`, `2h`, `500ms` into milliseconds.
pub fn parse_duration_ms(value: &str) -> Result<i64, String> {
    let value = value.trim();
    let (digits, unit) = value
        .find(|c: char| !c.is_ascii_digit())
        .map_or((value, "s"), |at| value.split_at(at));
    if digits.is_empty() {
        return Err(format!("`{value}` has no leading number"));
    }
    let magnitude: i64 = digits
        .parse()
        .map_err(|_| format!("`{digits}` is not a number"))?;
    let scale = match unit {
        "ms" => 1,
        "s" | "" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        other => return Err(format!("unknown time unit `{other}`; use ms, s, m, h or d")),
    };
    magnitude
        .checked_mul(scale)
        .ok_or_else(|| format!("`{value}` overflows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_000), "1970-01-01T00:00:01.000Z");
        // 2026-09-03T14:14:22.031Z
        assert_eq!(rfc3339(1_788_444_862_031), "2026-09-03T14:14:22.031Z");
        // A leap day, to exercise the civil conversion.
        assert_eq!(rfc3339(1_709_164_800_000), "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn durations_parse_every_supported_unit() {
        assert_eq!(parse_duration_ms("500ms").unwrap(), 500);
        assert_eq!(parse_duration_ms("30s").unwrap(), 30_000);
        assert_eq!(parse_duration_ms("10m").unwrap(), 600_000);
        assert_eq!(parse_duration_ms("2h").unwrap(), 7_200_000);
        assert_eq!(parse_duration_ms("7d").unwrap(), 604_800_000);
        assert_eq!(
            parse_duration_ms("45").unwrap(),
            45_000,
            "bare means seconds"
        );
        assert!(parse_duration_ms("m").is_err());
        assert!(parse_duration_ms("10y").is_err());
    }
}
