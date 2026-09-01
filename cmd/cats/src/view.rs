//! Human-readable renderings of the semantic Cat and Disk reads.
//!
//! Every function here is a pure projection of one already-fetched snapshot, so
//! the layout is testable without a control plane and `--watch` can redraw from
//! a cached snapshot without refetching.

use cats_protocol::metering::{UsageMetric, UsageReport};
use cats_protocol::semantic_control::{CatAction, CatState, CatView, DiskView};

use crate::term::{
    format_age, format_bytes, format_duration, format_timestamp, Align, Cell, Style, Table, Term,
};

/// Widest detail-card key (`workspace`) plus a space, so every value starts in
/// the same column.
const KEY_WIDTH: usize = 10;
/// Widest usage metric label (`storage cold`).
const USAGE_LABEL_WIDTH: usize = 13;

/// Colors ordered by how hot and how expensive the state is, so a fleet reads
/// top-down by cost: green is serving, yellow still holds host memory, cyan
/// holds only a local snapshot, blue holds nothing on a host.
const fn state_style(state: CatState) -> Style {
    match state {
        CatState::Running => Style::Green,
        CatState::Suspended => Style::Yellow,
        CatState::Warm => Style::Cyan,
        CatState::Cold => Style::Blue,
        CatState::Failure => Style::Red,
        CatState::Destroyed => Style::Dim,
    }
}

const fn state_label(state: CatState) -> &'static str {
    match state {
        CatState::Running => "running",
        CatState::Suspended => "suspended",
        CatState::Warm => "warm",
        CatState::Cold => "cold",
        CatState::Failure => "failure",
        CatState::Destroyed => "destroyed",
    }
}

const fn action_label(action: CatAction) -> &'static str {
    match action {
        CatAction::Create => "create",
        CatAction::Run => "run",
        CatAction::Suspend => "suspend",
        CatAction::Warm => "warm",
        CatAction::Cold => "cold",
        CatAction::Destroy => "destroy",
    }
}

/// What the CLI shows in a state column: either one settled state or the
/// transition currently being applied to it.
///
/// The settled state alone is a half-truth while an action is in flight -- a
/// Cat reading `cold` may be seconds from serving -- so the transition is part
/// of the state, not a separate column.
enum StateDisplay {
    Settled(CatState),
    /// No settled state yet; the Cat is still being created.
    Creating,
    Transition {
        from: CatState,
        to: CatState,
    },
    /// The in-flight action targets the state the Cat already holds, which is
    /// what a retried or idempotent transition looks like.
    Reapplying {
        state: CatState,
        action: CatAction,
    },
}

impl StateDisplay {
    fn of(cat: &CatView) -> Self {
        match (cat.state, cat.current_action) {
            (None, _) => Self::Creating,
            (Some(state), None) => Self::Settled(state),
            (Some(state), Some(action)) => {
                let to = action.target_state();
                if to == state {
                    Self::Reapplying { state, action }
                } else {
                    Self::Transition { from: state, to }
                }
            }
        }
    }

    /// Renders into a cell, painting only the state a reader must act on: the
    /// source of a transition is dim because it is already history.
    fn cell(&self, term: Term) -> Cell {
        match self {
            Self::Settled(state) => Cell::styled(term, state_label(*state), state_style(*state)),
            Self::Creating => Cell::styled(term, "creating", Style::Cyan),
            Self::Transition { from, to } => Cell::composed(format!(
                "{} {} {}",
                term.paint(state_label(*from), Style::Dim),
                term.paint("->", Style::Dim),
                term.paint(state_label(*to), state_style(*to)),
            )),
            Self::Reapplying { state, action } => Cell::composed(format!(
                "{} {}",
                term.paint(state_label(*state), state_style(*state)),
                term.paint(&format!("({})", action_label(*action)), Style::Dim),
            )),
        }
    }

    /// True while the control plane is applying an action, which is when
    /// `--watch` has something to wait for.
    const fn in_flight(&self) -> bool {
        !matches!(self, Self::Settled(_))
    }
}

/// The state a Cat is in, or the transition being applied to it, as one short
/// phrase. Used where a whole table or card would be too much: an action
/// confirmation and the `--watch` change history.
pub(crate) fn state_summary(term: Term, cat: &CatView) -> String {
    StateDisplay::of(cat).cell(term).into_text()
}

/// One row per Cat, aligned, with placement deliberately absent.
///
/// Which Node runs a Cat is an operations fact: it is not addressable by any
/// user command, it changes without a user action, and showing it invites
/// treating a Node name as part of the product. It stays in `--json`, which is
/// the verbatim API response.
pub(crate) fn cats_table(term: Term, cats: &[CatView], now_ms: i64) -> String {
    let mut table = Table::new(
        term,
        vec![
            ("NAME", Align::Left),
            ("STATE", Align::Left),
            ("CPU", Align::Right),
            ("MEMORY", Align::Right),
            ("DISKS", Align::Right),
            ("AGE", Align::Right),
            ("ID", Align::Left),
        ],
    );
    let mut ordered: Vec<&CatView> = cats.iter().collect();
    ordered.sort_by(|left, right| left.cat_slug.as_str().cmp(right.cat_slug.as_str()));
    for cat in ordered {
        let age = now_ms.saturating_sub(i64_from_ms(cat.created_at_unix_ms));
        table.push(vec![
            Cell::plain(cat.cat_slug.as_str()),
            StateDisplay::of(cat).cell(term),
            Cell::plain(cat.cpu.to_string()),
            Cell::plain(format_bytes(cat.memory_bytes)),
            Cell::plain(cat.mounts.len().to_string()),
            Cell::plain(format_age(age)),
            Cell::styled(term, cat.cat_id.as_str(), Style::Dim),
        ]);
    }
    table.render()
}

/// Everything one Cat can currently be asked about, in one screen.
pub(crate) fn cat_card(
    term: Term,
    cat: &CatView,
    workspace: Option<&str>,
    disks: &[DiskView],
    usage: Option<&UsageOutcome>,
    now_ms: i64,
) -> String {
    let display = StateDisplay::of(cat);
    let created = i64_from_ms(cat.created_at_unix_ms);

    // Keyed lines are collected before rendering so a multi-line value -- a
    // failure message -- can continue under an empty key without the renderer
    // needing a special case.
    let mut fields: Vec<(&str, String)> = vec![
        ("id", cat.cat_id.to_string()),
        ("state", state_detail(term, cat, &display, now_ms)),
        (
            "spec",
            format!("{} vCPU, {}", cat.cpu, format_bytes(cat.memory_bytes)),
        ),
        ("image", abbreviate_digest(&cat.boot_image)),
        (
            "created",
            format!(
                "{}  {}",
                format_timestamp(created),
                term.paint(
                    &format!("({} ago)", format_age(now_ms.saturating_sub(created))),
                    Style::Dim,
                ),
            ),
        ),
    ];
    if let Some(workspace) = workspace {
        fields.insert(1, ("workspace", workspace.to_owned()));
    }
    if let Some(last_run) = last_run_field(term, cat, now_ms) {
        let after_state = fields
            .iter()
            .position(|(key, _)| *key == "state")
            .map_or(fields.len(), |state| state + 1);
        fields.insert(after_state, last_run);
    }
    if let Some(destroyed) = cat.destroyed_at_unix_ms {
        fields.push(("destroyed", format_timestamp(i64_from_ms(destroyed))));
    }
    if let Some(error) = &cat.last_error {
        fields.push((
            "error",
            term.paint(&error_code_label(error.code), Style::Red),
        ));
        for line in error.message.lines() {
            fields.push(("", line.to_owned()));
        }
    }

    let mut out = format!(
        "{}  {}\n",
        term.paint(cat.cat_slug.as_str(), Style::Bold),
        display.cell(term).into_text(),
    );
    for (key, value) in fields {
        // The key is padded before it is painted: padding a string that already
        // carries escapes counts them as width and misaligns every value.
        out.push_str(&format!(
            "\n  {} {value}",
            term.paint(&format!("{key:<KEY_WIDTH$}"), Style::Dim),
        ));
    }

    out.push_str(&disks_section(term, cat, disks));
    if let Some(usage) = usage {
        out.push_str(&usage_section(term, usage));
    }
    out
}

/// `Debug` would render `GuestStartFailed`; the wire name is
/// `guest_start_failed`, and that is the string a user can search for in logs
/// and docs. Serde is the single source of that spelling.
fn error_code_label(code: cats_protocol::semantic_control::SemanticErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{code:?}"))
}

/// The state line: what it is, how long it has held, and since when.
fn state_detail(term: Term, cat: &CatView, display: &StateDisplay, now_ms: i64) -> String {
    let updated = i64_from_ms(cat.updated_at_unix_ms);
    let held = now_ms.saturating_sub(updated);
    let rendered = display.cell(term).into_text();
    if !display.in_flight() {
        // Settled: the settling write is the last one to touch the row, so
        // `updated_at` is exactly when the Cat entered this state.
        return format!(
            "{rendered} {} {}  {}",
            term.paint("for", Style::Dim),
            format_age(held),
            term.paint(
                &format!("(since {})", format_timestamp(updated)),
                Style::Dim
            ),
        );
    }

    // In flight, the two clocks answer different questions and both matter.
    // `current_action_started_at` is how long this has been going;
    // `updated_at` is an activity clock that the retry rotations and the
    // foreground activity refresh advance while the same occurrence continues.
    // Reading the activity clock as the duration would report a small, freshly
    // reset number for an action that has been stuck for minutes.
    let Some(started) = cat.current_action_started_at_unix_ms.map(i64_from_ms) else {
        // A Control that predates the field. Say what is known and stop: the
        // activity clock is the wrong answer to "how long", and there is no
        // other source for the right one.
        return format!("{rendered} {}", term.paint("in flight", Style::Dim));
    };
    let running_for = format!(
        "{rendered} {} {}",
        term.paint("in flight for", Style::Dim),
        format_duration(now_ms.saturating_sub(started)),
    );
    // The activity clause is only worth a line once that clock has actually
    // moved past the start; on a fresh action they are the same instant.
    if updated.saturating_sub(started) >= 1_000 {
        format!(
            "{running_for}  {}",
            term.paint(
                &format!("(last activity {} ago)", format_age(held)),
                Style::Dim,
            ),
        )
    } else {
        format!(
            "{running_for}  {}",
            term.paint(
                &format!("(since {})", format_timestamp(started)),
                Style::Dim
            ),
        )
    }
}

/// When this Cat last actually ran, for any Cat that is not running now.
///
/// A running Cat needs no such line: its state line already says how long the
/// current run has held.
///
/// An absent stamp is rendered "not recorded" rather than "never", because the
/// two are indistinguishable here: a Cat that has genuinely never run and a
/// Control that predates the field both report `None`. "Never" would be a claim
/// this projection cannot make.
fn last_run_field(term: Term, cat: &CatView, now_ms: i64) -> Option<(&'static str, String)> {
    if cat.state == Some(CatState::Running) {
        return None;
    }
    Some(match cat.last_running_at_unix_ms.map(i64_from_ms) {
        Some(ran) => (
            "last ran",
            format!(
                "{} {}  {}",
                format_age(now_ms.saturating_sub(ran)),
                term.paint("ago", Style::Dim),
                term.paint(&format!("(until {})", format_timestamp(ran)), Style::Dim),
            ),
        ),
        None => ("last ran", term.paint("not recorded", Style::Dim)),
    })
}

/// PersistentDisk mounts only. The RootDisk follows the Cat and has no product
/// read, so listing mounts as "disks" without qualification would imply the
/// root is missing.
fn disks_section(term: Term, cat: &CatView, disks: &[DiskView]) -> String {
    if cat.mounts.is_empty() {
        return String::new();
    }
    let mut table = Table::new(
        term,
        vec![
            ("DISK", Align::Left),
            ("PATH", Align::Left),
            ("SIZE", Align::Right),
        ],
    );
    for mount in &cat.mounts {
        let size = disks
            .iter()
            .find(|disk| disk.disk_id == mount.disk_id)
            .map_or_else(|| "-".to_owned(), |disk| format_bytes(disk.size_bytes));
        table.push(vec![
            Cell::plain(mount.disk_slug.as_str()),
            Cell::plain(mount.mount_path.as_str()),
            Cell::plain(size),
        ]);
    }
    format!(
        "\n\n  {}\n{}",
        term.paint("persistent disks", Style::Dim),
        indent(&table.render(), 4)
    )
}

/// What a usage lookup produced. A billing read must never be the reason
/// `cats show` fails, so its failure is a rendered line, not an error return.
pub(crate) enum UsageOutcome {
    Report {
        window_label: String,
        report: Box<UsageReport>,
    },
    Unavailable {
        window_label: String,
        reason: String,
    },
}

fn usage_section(term: Term, usage: &UsageOutcome) -> String {
    match usage {
        UsageOutcome::Unavailable {
            window_label,
            reason,
        } => format!(
            "\n\n  {}\n    {}",
            term.paint(&format!("usage ({window_label})"), Style::Dim),
            term.paint(&format!("unavailable: {reason}"), Style::Dim),
        ),
        UsageOutcome::Report {
            window_label,
            report,
        } => {
            let mut lines = Vec::new();
            for item in &report.items {
                if let Some(rendered) = usage_quantity(item.metric, &item.quantity) {
                    lines.push(format!(
                        "{:<USAGE_LABEL_WIDTH$} {rendered}",
                        metric_label(item.metric)
                    ));
                }
            }
            if let Some(cost) = format_money(&report.amount_nanos, &report.currency) {
                lines.push(format!(
                    "{:<USAGE_LABEL_WIDTH$} {cost} {}",
                    "cost",
                    term.paint(&format!("({})", report.status), Style::Dim)
                ));
            }
            if lines.is_empty() {
                lines.push(term.paint("no metered activity", Style::Dim));
            }
            format!(
                "\n\n  {}\n{}",
                term.paint(&format!("usage ({window_label})"), Style::Dim),
                indent(&lines.join("\n"), 4)
            )
        }
    }
}

const fn metric_label(metric: UsageMetric) -> &'static str {
    match metric {
        UsageMetric::CpuUsec => "cpu",
        UsageMetric::MemoryByteMillis => "memory",
        UsageMetric::StorageHotByteMillis => "storage hot",
        UsageMetric::StorageColdByteMillis => "storage cold",
        UsageMetric::NetworkEgressBytes => "egress",
    }
}

/// Converts a canonical meter quantity into the unit a person prices in.
///
/// Returns `None` for an unparseable or zero quantity so a metric that did not
/// accrue is absent rather than printed as a confident zero.
fn usage_quantity(metric: UsageMetric, quantity: &str) -> Option<String> {
    let raw: u128 = quantity.parse().ok()?;
    if raw == 0 {
        return None;
    }
    let raw = raw as f64;
    Some(match metric {
        // microseconds -> vCPU-hours
        UsageMetric::CpuUsec => format!("{:.3} vCPU-hour", raw / 3_600_000_000.0),
        // byte-milliseconds -> GiB-hours
        UsageMetric::MemoryByteMillis
        | UsageMetric::StorageHotByteMillis
        | UsageMetric::StorageColdByteMillis => {
            format!("{:.2} GiB-hour", raw / (1_073_741_824.0 * 3_600_000.0))
        }
        UsageMetric::NetworkEgressBytes => format_bytes(quantity.parse().ok()?),
    })
}

/// Nanos are the wire unit; people read currency. Four decimals keep a
/// sub-cent provisional total from rendering as zero.
fn format_money(amount_nanos: &str, currency: &str) -> Option<String> {
    let nanos: u128 = amount_nanos.parse().ok()?;
    Some(format!(
        "{:.4} {}",
        nanos as f64 / 1_000_000_000.0,
        currency.to_uppercase()
    ))
}

/// A 71-character digest is not readable and not actionable at a glance; the
/// full value stays in `--json`.
fn abbreviate_digest(image: &str) -> String {
    let Some((algorithm, hex)) = image.split_once(':') else {
        return image.to_owned();
    };
    if hex.len() <= 20 {
        return image.to_owned();
    }
    format!("{algorithm}:{}...{}", &hex[..8], &hex[hex.len() - 6..])
}

fn indent(block: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    block
        .lines()
        .map(|line| format!("{pad}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Wire timestamps are unsigned; local arithmetic is signed so clock skew
/// subtracts to a negative that the formatters clamp instead of wrapping.
fn i64_from_ms(unix_ms: u64) -> i64 {
    i64::try_from(unix_ms).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_protocol::runtime_reconciliation::Id;
    use cats_protocol::semantic_control::{
        CatMountView, DiskStatus, NodeName, PersistentMountPath, ResourceSlug, SemanticErrorBody,
        SemanticErrorCode,
    };

    const NOW: i64 = 1_700_000_000_000;

    fn cat(slug: &str, state: Option<CatState>, action: Option<CatAction>) -> CatView {
        CatView {
            cat_id: Id::new(format!("cat_{slug}0000000001")).unwrap(),
            workspace_id: Id::new("ws_0000000001").unwrap(),
            cat_slug: ResourceSlug::new(slug).unwrap(),
            state,
            current_action: action,
            node_id: None,
            node_name: None,
            cpu: 2,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            boot_image: "sha256:9f2c1d84aa11223344556677889900aabbccddeeff00112233445566778899ab"
                .to_owned(),
            mounts: Vec::new(),
            last_error: None,
            created_at_unix_ms: (NOW - 3 * 86_400_000) as u64,
            updated_at_unix_ms: (NOW - 3_600_000) as u64,
            destroyed_at_unix_ms: None,
            // A fresh action: its own clock and the activity clock are the
            // same instant, which is what the store writes on admission.
            current_action_started_at_unix_ms: action.map(|_| (NOW - 3_600_000) as u64),
            last_running_at_unix_ms: Some((NOW - 3_600_000) as u64),
        }
    }

    #[test]
    fn the_list_hides_placement_and_keeps_columns_aligned() {
        let term = Term::fixed(false, None);
        let mut running = cat("web", Some(CatState::Running), None);
        running.node_id = Some(Id::new("node_0001").unwrap());
        running.node_name = Some(NodeName::new("metal-1").unwrap());
        let cats = vec![running, cat("api", Some(CatState::Cold), None)];
        let rendered = cats_table(term, &cats, NOW);
        assert!(
            !rendered.contains("metal-1") && !rendered.contains("node_"),
            "placement must not reach the product list: {rendered}"
        );
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("NAME"));
        assert!(
            lines[1].starts_with("api"),
            "rows sort by name: {:?}",
            lines[1]
        );
        let state_column = lines[0].find("STATE").expect("header");
        for row in &lines[1..] {
            assert!(
                row[state_column..].starts_with("cold")
                    || row[state_column..].starts_with("running"),
                "state column misaligned: {row:?}"
            );
        }
    }

    #[test]
    fn a_transition_shows_both_ends() {
        let term = Term::fixed(false, None);
        let starting = cat("web", Some(CatState::Cold), Some(CatAction::Run));
        let rendered = cats_table(term, &[starting], NOW);
        assert!(rendered.contains("cold -> running"), "{rendered}");
    }

    #[test]
    fn a_cat_without_a_settled_state_is_creating() {
        let term = Term::fixed(false, None);
        let creating = cat("web", None, Some(CatAction::Create));
        assert!(cats_table(term, &[creating], NOW).contains("creating"));
    }

    #[test]
    fn a_reapplied_action_names_itself_beside_the_state() {
        let term = Term::fixed(false, None);
        let retried = cat("web", Some(CatState::Running), Some(CatAction::Run));
        let rendered = cats_table(term, &[retried], NOW);
        assert!(rendered.contains("running (run)"), "{rendered}");
    }

    #[test]
    fn states_get_distinct_colors_and_none_without_color() {
        let colored = Term::fixed(true, None);
        let mut seen = std::collections::HashSet::new();
        for state in [
            CatState::Running,
            CatState::Suspended,
            CatState::Warm,
            CatState::Cold,
            CatState::Failure,
        ] {
            let rendered = cats_table(colored, &[cat("web", Some(state), None)], NOW);
            let escape = rendered
                .lines()
                .nth(1)
                .and_then(|row| row.split('m').next())
                .map(str::to_owned)
                .expect("row");
            assert!(seen.insert(escape.clone()), "duplicate color for {state:?}");
        }
        let plain = Term::fixed(false, None);
        assert!(
            !cats_table(plain, &[cat("web", Some(CatState::Running), None)], NOW).contains('\x1b'),
            "no escapes without color"
        );
    }

    #[test]
    fn the_card_reports_settled_and_in_flight_time_differently() {
        let term = Term::fixed(false, None);
        let settled = cat("web", Some(CatState::Running), None);
        let card = cat_card(term, &settled, Some("acct/prod"), &[], None, NOW);
        assert!(card.contains("running for 1h"), "{card}");
        assert!(card.contains("acct/prod"), "{card}");
        assert!(card.contains("2 vCPU, 2 GiB"), "{card}");
        assert!(card.contains("sha256:9f2c1d84...8899ab"), "{card}");
        assert!(!card.contains("persistent disks"), "no mounts, no section");

        let mut moving = cat("web", Some(CatState::Cold), Some(CatAction::Run));
        moving.updated_at_unix_ms = (NOW - 1_420) as u64;
        moving.current_action_started_at_unix_ms = Some((NOW - 1_420) as u64);
        let card = cat_card(term, &moving, None, &[], None, NOW);
        assert!(
            card.contains("cold -> running in flight for 1.420s"),
            "{card}"
        );
        assert!(
            card.contains("(since "),
            "a fresh action names its start, not an activity age: {card}"
        );
    }

    #[test]
    fn a_stuck_action_reports_its_own_age_and_its_activity_separately() {
        let term = Term::fixed(false, None);
        // The retry rotations and the foreground activity refresh advance
        // `updated_at` while the same occurrence continues. Reading that clock
        // as the action's age would report seconds for an action stuck for
        // minutes -- backwards from what a reader needs, and wrong exactly when
        // someone is watching because something is stuck.
        let mut stuck = cat("web", Some(CatState::Cold), Some(CatAction::Run));
        stuck.current_action_started_at_unix_ms = Some((NOW - 300_000) as u64);
        stuck.updated_at_unix_ms = (NOW - 3_000) as u64;
        let card = cat_card(term, &stuck, None, &[], None, NOW);
        assert!(
            card.contains("in flight for 5m 0s"),
            "the action's own clock decides the duration: {card}"
        );
        assert!(
            card.contains("(last activity 3s ago)"),
            "the activity clock still answers whether anything is working: {card}"
        );
    }

    #[test]
    fn an_action_clock_the_control_plane_omitted_invents_no_duration() {
        let term = Term::fixed(false, None);
        let mut moving = cat("web", Some(CatState::Cold), Some(CatAction::Run));
        moving.current_action_started_at_unix_ms = None;
        let card = cat_card(term, &moving, None, &[], None, NOW);
        assert!(card.contains("cold -> running in flight"), "{card}");
        assert!(
            !card.contains("in flight for"),
            "an absent clock must not become a fabricated duration: {card}"
        );
    }

    #[test]
    fn only_a_stopped_cat_reports_when_it_last_ran() {
        let term = Term::fixed(false, None);
        let running = cat("web", Some(CatState::Running), None);
        assert!(
            !cat_card(term, &running, None, &[], None, NOW).contains("last ran"),
            "a running Cat's state line already covers the current run"
        );

        let mut stopped = cat("web", Some(CatState::Warm), None);
        stopped.last_running_at_unix_ms = Some((NOW - 2 * 3_600_000) as u64);
        let card = cat_card(term, &stopped, None, &[], None, NOW);
        assert!(card.contains("last ran"), "{card}");
        assert!(
            card.contains("2h ago"),
            "the age survives running -> suspended -> warm: {card}"
        );

        // An absent stamp cannot be reported as "never": a Cat that has truly
        // never run and a Control that predates the field are the same `None`
        // here, and only one of them has never run.
        let mut unrecorded = cat("web", Some(CatState::Cold), None);
        unrecorded.last_running_at_unix_ms = None;
        let card = cat_card(term, &unrecorded, None, &[], None, NOW);
        assert!(card.contains("last ran"), "{card}");
        assert!(card.contains("not recorded"), "{card}");
        assert!(!card.contains("never"), "{card}");
    }

    #[test]
    fn the_card_hides_placement_too() {
        let term = Term::fixed(false, None);
        let mut placed = cat("web", Some(CatState::Running), None);
        placed.node_id = Some(Id::new("node_0001").unwrap());
        placed.node_name = Some(NodeName::new("metal-1").unwrap());
        let card = cat_card(term, &placed, Some("acct/prod"), &[], None, NOW);
        assert!(
            !card.contains("metal-1") && !card.contains("node_"),
            "placement is an operations fact, not a product one: {card}"
        );
    }

    #[test]
    fn the_card_expands_a_failure_message() {
        let term = Term::fixed(false, None);
        let mut failed = cat("web", Some(CatState::Failure), None);
        failed.last_error = Some(SemanticErrorBody {
            code: SemanticErrorCode::GuestStartFailed,
            message: "virtiofs daemon exited\nbefore the Guest mounted /var/data".to_owned(),
        });
        let card = cat_card(term, &failed, None, &[], None, NOW);
        assert!(card.contains("guest_start_failed"), "{card}");
        assert!(card.contains("virtiofs daemon exited"), "{card}");
        assert!(
            card.contains("before the Guest mounted /var/data"),
            "every message line survives: {card}"
        );
    }

    #[test]
    fn the_card_joins_mount_paths_to_disk_sizes() {
        let term = Term::fixed(false, None);
        let mut mounted = cat("web", Some(CatState::Running), None);
        mounted.mounts = vec![
            CatMountView {
                disk_id: Id::new("disk_0000000001").unwrap(),
                disk_slug: ResourceSlug::new("data").unwrap(),
                mount_path: PersistentMountPath::new("/var/data").unwrap(),
            },
            CatMountView {
                disk_id: Id::new("disk_0000000002").unwrap(),
                disk_slug: ResourceSlug::new("scratch").unwrap(),
                mount_path: PersistentMountPath::new("/mnt/tmp").unwrap(),
            },
        ];
        let disks = vec![DiskView {
            disk_id: Id::new("disk_0000000001").unwrap(),
            workspace_id: Id::new("ws_0000000001").unwrap(),
            disk_slug: ResourceSlug::new("data").unwrap(),
            size_bytes: 20 * 1024 * 1024 * 1024,
            head_generation: Some(7),
            status: DiskStatus::Normal,
            binding: None,
            created_at_unix_ms: 0,
            deleted_at_unix_ms: None,
        }];
        let card = cat_card(term, &mounted, None, &disks, None, NOW);
        assert!(card.contains("persistent disks"), "{card}");
        assert!(
            card.contains("data") && card.contains("/var/data"),
            "{card}"
        );
        assert!(card.contains("20 GiB"), "{card}");
        assert!(
            card.contains("scratch")
                && card
                    .lines()
                    .any(|line| line.contains("scratch") && line.trim_end().ends_with('-')),
            "an unresolved disk shows a dash, not a wrong size: {card}"
        );
    }

    #[test]
    fn usage_converts_meters_into_units_people_price_in() {
        assert_eq!(
            usage_quantity(UsageMetric::CpuUsec, "3600000000").as_deref(),
            Some("1.000 vCPU-hour")
        );
        assert_eq!(
            usage_quantity(
                UsageMetric::MemoryByteMillis,
                &(1_073_741_824_u128 * 3_600_000).to_string()
            )
            .as_deref(),
            Some("1.00 GiB-hour")
        );
        assert_eq!(
            usage_quantity(UsageMetric::NetworkEgressBytes, "412000000").as_deref(),
            Some("392.9 MiB")
        );
        assert_eq!(
            usage_quantity(UsageMetric::CpuUsec, "0"),
            None,
            "a metric that did not accrue is absent, not a confident zero"
        );
        assert_eq!(usage_quantity(UsageMetric::CpuUsec, "not-a-number"), None);
        assert_eq!(
            format_money("42100000", "usd").as_deref(),
            Some("0.0421 USD")
        );
    }

    #[test]
    fn a_failed_usage_lookup_renders_instead_of_failing() {
        let term = Term::fixed(false, None);
        let card = cat_card(
            term,
            &cat("web", Some(CatState::Running), None),
            None,
            &[],
            Some(&UsageOutcome::Unavailable {
                window_label: "last 24h".to_owned(),
                reason: "workspace has no billing ledger".to_owned(),
            }),
            NOW,
        );
        assert!(card.contains("usage (last 24h)"), "{card}");
        assert!(
            card.contains("unavailable: workspace has no billing ledger"),
            "{card}"
        );
    }

    #[test]
    fn a_short_or_unusual_image_reference_is_left_alone() {
        assert_eq!(abbreviate_digest("sha256:abcd"), "sha256:abcd");
        assert_eq!(abbreviate_digest("no-colon"), "no-colon");
    }
}
