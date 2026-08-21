//! Shared parsers for Host process evidence read from `/proc`.
//!
//! Atomic lifecycle owns process handles and exact retirement in its installed
//! platform adapters. This module retains only the stat parser shared by Start
//! and full inventory.

/// `starttime` — field 22 of `/proc/<pid>/stat`, in clock ticks since boot.
///
/// Field 2 (`comm`) is wrapped in parentheses and may itself contain spaces and
/// parentheses (it is the first 15 bytes of the executable's basename, which
/// the kernel does not sanitize), so the fields cannot be taken by splitting the
/// line on whitespace. Splitting after the *last* `)` is the documented way to
/// parse this file. Getting it wrong yields a plausible but wrong start time,
/// which would later let a recycled pid pass for a surviving process.
pub(crate) fn parse_start_ticks(stat: &str) -> Option<u64> {
    // Everything after the comm field starts at field 3 (`state`), so field 22
    // is at index 19.
    let (_, after_comm) = stat.rsplit_once(')')?;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::parse_start_ticks;

    #[test]
    fn start_ticks_come_from_the_field_after_the_last_paren() {
        // Real shape of /proc/<pid>/stat, truncated after starttime.
        let stat =
            "4242 (cats-blockd) S 1 4242 4242 0 -1 4194560 512 0 0 0 11 3 0 0 20 0 5 0 918273 ";
        assert_eq!(parse_start_ticks(stat), Some(918_273));

        // comm is the unsanitized executable basename, so it can contain
        // spaces and parentheses. Splitting on whitespace, or on the first
        // `)`, silently returns a different field's value here.
        let tricky =
            "4242 (odd ) name (x) S 1 4242 4242 0 -1 4194560 512 0 0 0 11 3 0 0 20 0 5 0 918273 ";
        assert_eq!(parse_start_ticks(tricky), Some(918_273));

        let trailing_paren =
            "4242 (weird)) S 1 4242 4242 0 -1 4194560 512 0 0 0 11 3 0 0 20 0 5 0 4242424 0 0";
        assert_eq!(parse_start_ticks(trailing_paren), Some(4_242_424));
    }

    #[test]
    fn a_malformed_stat_line_yields_no_start_ticks() {
        assert_eq!(parse_start_ticks(""), None);
        assert_eq!(parse_start_ticks("4242 (cats-blockd S 1 2 3"), None);
        // Truncated before field 22.
        assert_eq!(parse_start_ticks("4242 (cats-blockd) S 1 4242"), None);
        // Field 22 present but not a number.
        assert_eq!(
            parse_start_ticks(
                "4242 (cats-blockd) S 1 4242 4242 0 -1 4194560 512 0 0 0 11 3 0 0 20 0 5 0 x"
            ),
            None
        );
    }
}
