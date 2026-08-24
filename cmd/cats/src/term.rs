//! Terminal primitives for human-readable CLI output.
//!
//! Deliberately dependency-free. The CLI ships no color, table or terminal
//! crate, and none of the three is hard enough to justify a production
//! dependency: the whole surface is width measurement, SGR escapes and column
//! padding.
//!
//! Two rules shape the design:
//!
//! * Color only ever *accelerates* reading. Every distinction it draws is also
//!   carried by the text, so `NO_COLOR`, a pipe or a dumb terminal loses
//!   nothing but speed.
//! * Only ASCII is emitted. Box drawing, arrows and status glyphs are all
//!   East Asian Ambiguous width, so a terminal configured for CJK renders them
//!   two columns wide and every table drawn with them misaligns.

use std::fmt::Write as _;
use std::io::IsTerminal;

/// When to emit SGR escapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ColorChoice {
    /// Colorize when stdout is a terminal and the environment permits it.
    #[default]
    Auto,
    Always,
    Never,
}

/// Foreground styles. The palette is ordered by how hot and how expensive a
/// Cat state is, so a fleet scans top-to-bottom by cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Style {
    /// No escape at all, not an explicit default-foreground escape.
    Plain,
    Dim,
    Bold,
    Green,
    Yellow,
    Cyan,
    /// Bright rather than plain blue: plain blue is unreadably dark on the
    /// default macOS Terminal and Solarized-style themes.
    Blue,
    Red,
}

impl Style {
    const fn sgr(self) -> Option<&'static str> {
        match self {
            Self::Plain => None,
            Self::Dim => Some("2"),
            Self::Bold => Some("1"),
            Self::Green => Some("32"),
            Self::Yellow => Some("33"),
            Self::Cyan => Some("36"),
            Self::Blue => Some("94"),
            Self::Red => Some("31"),
        }
    }
}

/// Resolved output capabilities for one stdout.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Term {
    color: bool,
    /// `None` when stdout is not a terminal: piped output is never truncated.
    width: Option<usize>,
    height: Option<usize>,
}

impl Term {
    /// Capabilities of the current process stdout.
    pub(crate) fn stdout(choice: ColorChoice) -> Self {
        let tty = std::io::stdout().is_terminal();
        let size = tty.then(terminal_size).flatten();
        Self {
            color: color_enabled(choice, tty, &EnvVars::from_process()),
            width: size.map(|(columns, _)| columns),
            height: size.map(|(_, rows)| rows),
        }
    }

    /// A fixed capability set, for tests and for rendering into a string whose
    /// destination is not this process stdout.
    #[cfg(test)]
    pub(crate) fn fixed(color: bool, width: Option<usize>) -> Self {
        Self {
            color,
            width,
            height: None,
        }
    }

    pub(crate) const fn width(self) -> Option<usize> {
        self.width
    }

    pub(crate) const fn height(self) -> Option<usize> {
        self.height
    }

    /// Wraps `text` in `style`, or returns it unchanged when color is off.
    pub(crate) fn paint(self, text: &str, style: Style) -> String {
        match style.sgr().filter(|_| self.color) {
            Some(sgr) => format!("\x1b[{sgr}m{text}\x1b[0m"),
            None => text.to_owned(),
        }
    }
}

/// The environment variables that can veto color, read once.
struct EnvVars {
    no_color: Option<String>,
    clicolor: Option<String>,
    clicolor_force: Option<String>,
    term: Option<String>,
}

impl EnvVars {
    fn from_process() -> Self {
        Self {
            no_color: std::env::var("NO_COLOR").ok(),
            clicolor: std::env::var("CLICOLOR").ok(),
            clicolor_force: std::env::var("CLICOLOR_FORCE").ok(),
            term: std::env::var("TERM").ok(),
        }
    }
}

/// Pure so the precedence rules are testable without touching process state.
///
/// `--color=always` beats the environment because it is an explicit request
/// from this invocation; every other signal can only turn color off.
fn color_enabled(choice: ColorChoice, tty: bool, env: &EnvVars) -> bool {
    match choice {
        ColorChoice::Never => return false,
        ColorChoice::Always => return true,
        ColorChoice::Auto => {}
    }
    // https://no-color.org: any non-empty value disables color.
    if env
        .no_color
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        return false;
    }
    if env.clicolor.as_deref() == Some("0") {
        return false;
    }
    if env.term.as_deref() == Some("dumb") {
        return false;
    }
    if env
        .clicolor_force
        .as_deref()
        .is_some_and(|value| !value.is_empty() && value != "0")
    {
        return true;
    }
    tty
}

/// `(columns, rows)` of the stdout window.
#[cfg(unix)]
fn terminal_size() -> Option<(usize, usize)> {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `size` is a fully initialized `winsize` owned by this frame, so
    // the kernel writes into valid, exclusively borrowed memory. The result is
    // only read when the ioctl reports success.
    let queried = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ as _, &mut size) };
    // Both dimensions must be real: a zero row count would make the frame
    // height clamp truncate every redraw to a single line.
    (queried == 0 && size.ws_col > 0 && size.ws_row > 0)
        .then(|| (usize::from(size.ws_col), usize::from(size.ws_row)))
}

#[cfg(not(unix))]
fn terminal_size() -> Option<(usize, usize)> {
    None
}

/// Visible width of already-rendered text, ignoring SGR escapes.
///
/// Counts scalar values, which is exact for the ASCII this module emits and
/// for the slugs and paths the control plane validates. A server error message
/// containing wide characters can still pad short; that costs alignment on one
/// row, never correctness.
fn visible_width(text: &str) -> usize {
    let mut width = 0;
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        if character == '\x1b' {
            skip_escape(&mut chars, None);
            continue;
        }
        width += 1;
    }
    width
}

/// Consumes one escape sequence whose introducing `\x1b` was already taken,
/// optionally echoing it into `out`.
///
/// A CSI sequence is `\x1b` `[`, parameter and intermediate bytes, then a final
/// byte in `0x40..=0x7e`. The opening `[` is itself in that range, so it has to
/// be consumed before the scan for the final byte starts -- scanning first ends
/// the sequence immediately and counts the whole escape as visible text.
/// Anything else after `\x1b` is a two-character escape.
fn skip_escape(chars: &mut std::str::Chars<'_>, mut out: Option<&mut String>) {
    let Some(introducer) = chars.next() else {
        return;
    };
    if let Some(out) = out.as_deref_mut() {
        out.push(introducer);
    }
    if introducer != '[' {
        return;
    }
    for escaped in chars.by_ref() {
        if let Some(out) = out.as_deref_mut() {
            out.push(escaped);
        }
        if ('@'..='~').contains(&escaped) {
            break;
        }
    }
}

/// Truncates `text` to `limit` visible columns, marking the cut with `...`.
///
/// Used only where a wrapped line would corrupt the display, which today means
/// the in-place `--watch` redraw: it moves the cursor up by the number of lines
/// it printed, so every logical line must occupy exactly one physical row.
pub(crate) fn truncate_visible(text: &str, limit: usize) -> String {
    if visible_width(text) <= limit {
        return text.to_owned();
    }
    if limit <= 3 {
        return ".".repeat(limit);
    }
    let keep = limit - 3;
    let mut out = String::with_capacity(text.len());
    let mut width = 0;
    let mut styled = false;
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        if character == '\x1b' {
            styled = true;
            out.push(character);
            skip_escape(&mut chars, Some(&mut out));
            continue;
        }
        if width == keep {
            break;
        }
        out.push(character);
        width += 1;
    }
    out.push_str("...");
    if styled {
        // A style opened before the cut is still open. Unstyled text gets no
        // reset: those bytes are invisible but they are still bytes, and a
        // caller measuring the result would count them.
        out.push_str("\x1b[0m");
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Align {
    Left,
    Right,
}

/// One rendered table cell: final text plus the width it occupies.
///
/// Carrying the width lets a cell mix styles -- a state transition paints its
/// source, arrow and target differently -- without the table having to parse
/// escapes back out to pad it.
#[derive(Debug, Clone)]
pub(crate) struct Cell {
    text: String,
    width: usize,
}

impl Cell {
    pub(crate) fn plain(text: impl Into<String>) -> Self {
        let text = text.into();
        let width = text.chars().count();
        Self { text, width }
    }

    pub(crate) fn styled(term: Term, text: &str, style: Style) -> Self {
        Self {
            text: term.paint(text, style),
            width: text.chars().count(),
        }
    }

    /// Pre-composed text whose visible width is measured from the escapes.
    pub(crate) fn composed(text: String) -> Self {
        let width = visible_width(&text);
        Self { text, width }
    }

    /// The rendered text, for the one place a cell is shown outside a table:
    /// the detail card reuses the state cell as its title.
    pub(crate) fn into_text(self) -> String {
        self.text
    }
}

/// A left-to-right column table with a dim header and a two-space gutter.
pub(crate) struct Table {
    term: Term,
    headers: Vec<(&'static str, Align)>,
    rows: Vec<Vec<Cell>>,
}

const GUTTER: &str = "  ";

impl Table {
    pub(crate) fn new(term: Term, headers: Vec<(&'static str, Align)>) -> Self {
        Self {
            term,
            headers,
            rows: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, row: Vec<Cell>) {
        debug_assert_eq!(row.len(), self.headers.len(), "row arity");
        self.rows.push(row);
    }

    /// Renders the table, one line per row, without a trailing newline.
    ///
    /// The final column is never padded, so no line carries trailing
    /// whitespace into a diff, a pipe or a copied selection.
    pub(crate) fn render(&self) -> String {
        let widths: Vec<usize> = self
            .headers
            .iter()
            .enumerate()
            .map(|(column, (header, _))| {
                self.rows
                    .iter()
                    .filter_map(|row| row.get(column).map(|cell| cell.width))
                    .chain(std::iter::once(header.chars().count()))
                    .max()
                    .unwrap_or_default()
            })
            .collect();

        let mut out = String::new();
        let header_cells: Vec<Cell> = self
            .headers
            .iter()
            .map(|(header, _)| Cell::styled(self.term, header, Style::Dim))
            .collect();
        self.write_row(&mut out, &header_cells, &widths);
        for row in &self.rows {
            out.push('\n');
            self.write_row(&mut out, row, &widths);
        }
        out
    }

    fn write_row(&self, out: &mut String, row: &[Cell], widths: &[usize]) {
        let last = row.len().saturating_sub(1);
        for (column, cell) in row.iter().enumerate() {
            if column > 0 {
                out.push_str(GUTTER);
            }
            let pad = widths
                .get(column)
                .copied()
                .unwrap_or_default()
                .saturating_sub(cell.width);
            let align = self
                .headers
                .get(column)
                .map_or(Align::Left, |(_, align)| *align);
            match align {
                Align::Right => {
                    for _ in 0..pad {
                        out.push(' ');
                    }
                    out.push_str(&cell.text);
                }
                Align::Left => {
                    out.push_str(&cell.text);
                    if column != last {
                        for _ in 0..pad {
                            out.push(' ');
                        }
                    }
                }
            }
        }
    }
}

/// Compact age for a list column: one unit, largest that fits.
pub(crate) fn format_age(elapsed_ms: i64) -> String {
    let seconds = elapsed_ms.max(0) / 1_000;
    if seconds < 60 {
        return format!("{seconds}s");
    }
    let minutes = seconds / 60;
    if minutes < 60 {
        return format!("{minutes}m");
    }
    let hours = minutes / 60;
    if hours < 24 {
        return format!("{hours}h");
    }
    format!("{}d", hours / 24)
}

/// Two-unit duration for a detail line, with sub-second precision below 10s
/// because that is the range the lifecycle latency targets live in.
pub(crate) fn format_duration(elapsed_ms: i64) -> String {
    let millis = elapsed_ms.max(0);
    if millis < 10_000 {
        return format!("{}.{:03}s", millis / 1_000, millis % 1_000);
    }
    let seconds = millis / 1_000;
    if seconds < 60 {
        return format!("{seconds}s");
    }
    let (minutes, seconds) = (seconds / 60, seconds % 60);
    if minutes < 60 {
        return format!("{minutes}m {seconds}s");
    }
    let (hours, minutes) = (minutes / 60, minutes % 60);
    if hours < 24 {
        return format!("{hours}h {minutes}m");
    }
    format!("{}d {}h", hours / 24, hours % 24)
}

/// Binary byte size. One decimal only when it carries information.
pub(crate) fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    let label = UNITS[unit];
    if unit == 0 || (value - value.round()).abs() < 0.05 {
        format!("{} {label}", value.round())
    } else {
        format!("{value:.1} {label}")
    }
}

/// Local wall-clock stamp with an explicit UTC offset, e.g.
/// `2026-08-24 18:09:31 +0800`.
///
/// Uses `localtime_r` rather than a date crate so the offset and DST come from
/// the platform zone database. Falls back to UTC when the platform declines to
/// convert, which keeps an out-of-range stamp printable instead of fatal.
pub(crate) fn format_timestamp(unix_ms: i64) -> String {
    match local_time(unix_ms) {
        Some(stamp) => stamp,
        None => format!("{unix_ms} (unix ms)"),
    }
}

/// Local `HH:MM:SS`, for the `--watch` header clock.
pub(crate) fn format_clock(unix_ms: i64) -> String {
    match local_time(unix_ms) {
        Some(stamp) => stamp.split(' ').nth(1).map(str::to_owned).unwrap_or(stamp),
        None => String::new(),
    }
}

#[cfg(unix)]
fn local_time(unix_ms: i64) -> Option<String> {
    let seconds = unix_ms.div_euclid(1_000);
    // `time_t` is 64-bit on the targets built today and 32-bit on some others,
    // where this conversion is the only thing standing between a far-future
    // timestamp and a wrapped date. The narrow allow keeps the portable form.
    #[allow(clippy::useless_conversion)]
    let time: libc::time_t = seconds.try_into().ok()?;
    // SAFETY: `libc::tm` is plain data with no invalid bit patterns, so an
    // all-zero value is a valid initial state for `localtime_r` to overwrite.
    let mut parts: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `time` and `parts` are live, exclusively borrowed locals for the
    // duration of the call. `localtime_r` writes only through the out pointer
    // and returns null instead of writing when it cannot convert.
    let converted = unsafe { libc::localtime_r(&time, &mut parts) };
    if converted.is_null() {
        return None;
    }
    let offset_minutes = parts.tm_gmtoff / 60;
    let sign = if offset_minutes < 0 { '-' } else { '+' };
    let offset_minutes = offset_minutes.abs();
    let mut out = String::with_capacity(26);
    let _ = write!(
        out,
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {sign}{:02}{:02}",
        parts.tm_year + 1900,
        parts.tm_mon + 1,
        parts.tm_mday,
        parts.tm_hour,
        parts.tm_min,
        parts.tm_sec,
        offset_minutes / 60,
        offset_minutes % 60,
    );
    Some(out)
}

#[cfg(not(unix))]
fn local_time(_unix_ms: i64) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(no_color: Option<&str>, clicolor: Option<&str>, term: Option<&str>) -> EnvVars {
        EnvVars {
            no_color: no_color.map(str::to_owned),
            clicolor: clicolor.map(str::to_owned),
            clicolor_force: None,
            term: term.map(str::to_owned),
        }
    }

    #[test]
    fn color_follows_the_terminal_by_default() {
        assert!(color_enabled(
            ColorChoice::Auto,
            true,
            &env(None, None, None)
        ));
        assert!(!color_enabled(
            ColorChoice::Auto,
            false,
            &env(None, None, None)
        ));
    }

    #[test]
    fn the_environment_can_only_veto_automatic_color() {
        for vetoed in [
            env(Some("1"), None, None),
            env(None, Some("0"), None),
            env(None, None, Some("dumb")),
        ] {
            assert!(!color_enabled(ColorChoice::Auto, true, &vetoed));
            assert!(
                color_enabled(ColorChoice::Always, false, &vetoed),
                "an explicit --color=always outranks the environment"
            );
        }
        assert!(!color_enabled(
            ColorChoice::Never,
            true,
            &env(None, None, None)
        ));
    }

    #[test]
    fn an_empty_no_color_does_not_disable_color() {
        assert!(color_enabled(
            ColorChoice::Auto,
            true,
            &env(Some(""), None, None)
        ));
    }

    #[test]
    fn clicolor_force_enables_color_off_a_terminal() {
        let mut forced = env(None, None, None);
        forced.clicolor_force = Some("1".to_owned());
        assert!(color_enabled(ColorChoice::Auto, false, &forced));
        forced.no_color = Some("1".to_owned());
        assert!(
            !color_enabled(ColorChoice::Auto, false, &forced),
            "NO_COLOR outranks CLICOLOR_FORCE"
        );
    }

    #[test]
    fn styling_is_absent_without_color() {
        let plain = Term::fixed(false, None);
        assert_eq!(plain.paint("running", Style::Green), "running");
        let colored = Term::fixed(true, None);
        assert_eq!(
            colored.paint("running", Style::Green),
            "\x1b[32mrunning\x1b[0m"
        );
        assert_eq!(
            colored.paint("x", Style::Plain),
            "x",
            "Plain must emit no escape at all"
        );
    }

    #[test]
    fn visible_width_ignores_escapes() {
        let colored = Term::fixed(true, None);
        assert_eq!(visible_width(&colored.paint("running", Style::Green)), 7);
        assert_eq!(visible_width("running"), 7);
    }

    #[test]
    fn a_table_aligns_columns_and_leaves_no_trailing_space() {
        let term = Term::fixed(false, None);
        let mut table = Table::new(
            term,
            vec![
                ("NAME", Align::Left),
                ("CPU", Align::Right),
                ("ID", Align::Left),
            ],
        );
        table.push(vec![
            Cell::plain("web"),
            Cell::plain("2"),
            Cell::plain("cat_01"),
        ]);
        table.push(vec![
            Cell::plain("database"),
            Cell::plain("16"),
            Cell::plain("cat_02"),
        ]);
        assert_eq!(
            table.render(),
            "NAME      CPU  ID\n\
             web         2  cat_01\n\
             database   16  cat_02"
        );
    }

    #[test]
    fn a_table_pads_around_styled_cells_by_visible_width() {
        let term = Term::fixed(true, None);
        let mut table = Table::new(term, vec![("STATE", Align::Left), ("AGE", Align::Left)]);
        table.push(vec![
            Cell::styled(term, "running", Style::Green),
            Cell::plain("3d"),
        ]);
        table.push(vec![Cell::plain("suspended"), Cell::plain("2d")]);
        let rendered = table.render();
        let running = rendered.lines().nth(1).expect("row");
        assert!(
            running.ends_with("3d"),
            "the escape must not consume the pad: {running:?}"
        );
        assert_eq!(
            visible_width(running),
            "suspended  2d".len(),
            "styled and plain rows must align"
        );
    }

    #[test]
    fn truncation_closes_an_open_style() {
        let term = Term::fixed(true, None);
        let long = term.paint("abcdefghij", Style::Red);
        let cut = truncate_visible(&long, 6);
        assert_eq!(visible_width(&cut), 6);
        assert!(cut.ends_with("\x1b[0m"), "{cut:?}");
        assert!(cut.contains("abc..."), "{cut:?}");
        assert_eq!(truncate_visible("short", 40), "short");
        assert_eq!(
            truncate_visible("abcdefghij", 6),
            "abc...",
            "unstyled text is cut without gaining an escape"
        );
    }

    #[test]
    fn ages_pick_one_unit() {
        assert_eq!(format_age(0), "0s");
        assert_eq!(format_age(45_000), "45s");
        assert_eq!(format_age(59_999), "59s");
        assert_eq!(format_age(60_000), "1m");
        assert_eq!(format_age(3_600_000 - 1), "59m");
        assert_eq!(format_age(3_600_000), "1h");
        assert_eq!(format_age(86_400_000 - 1), "23h");
        assert_eq!(format_age(86_400_000), "1d");
        assert_eq!(format_age(-5), "0s", "clock skew must not print a negative");
    }

    #[test]
    fn durations_keep_millisecond_precision_where_the_targets_live() {
        assert_eq!(format_duration(480), "0.480s");
        assert_eq!(format_duration(1_420), "1.420s");
        assert_eq!(format_duration(9_999), "9.999s");
        assert_eq!(format_duration(10_000), "10s");
        assert_eq!(format_duration(75_000), "1m 15s");
        assert_eq!(format_duration(3_600_000 + 720_000), "1h 12m");
        assert_eq!(format_duration(86_400_000 * 3 + 3_600_000 * 4), "3d 4h");
    }

    #[test]
    fn byte_sizes_drop_a_pointless_decimal() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2 GiB");
        assert_eq!(format_bytes(1536 * 1024 * 1024), "1.5 GiB");
        assert_eq!(format_bytes(20 * 1024 * 1024 * 1024), "20 GiB");
    }

    #[test]
    fn timestamps_carry_an_explicit_offset() {
        let stamp = format_timestamp(1_756_000_000_000);
        assert_eq!(stamp.len(), 25, "{stamp:?}");
        assert!(
            stamp.starts_with("2025-") || stamp.starts_with("2026-"),
            "{stamp:?}"
        );
        let clock = format_clock(1_756_000_000_000);
        assert_eq!(clock.len(), 8, "{clock:?}");
    }
}
