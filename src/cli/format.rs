//! Terminal rendering.
//!
//! The table is hand-laid rather than delegated to a table crate, because the
//! column budget is dynamic: the title column gets whatever the fixed columns
//! leave over, so the output stays readable in a narrow terminal.

use owo_colors::{OwoColorize, Style};

use crate::types::{PortRecord, Protocol};

/// Colour is suppressed for pipes and when NO_COLOR is set, so `ports --json`
/// and `ports | grep` stay clean.
pub fn color_enabled() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
}

/// Apply a style only when colour is on.
pub fn paint(text: &str, style: Style) -> String {
    if color_enabled() {
        text.style(style).to_string()
    } else {
        text.to_string()
    }
}

pub fn bold(text: &str) -> String {
    paint(text, Style::new().bold())
}
pub fn dim(text: &str) -> String {
    paint(text, Style::new().dimmed())
}
pub fn gray(text: &str) -> String {
    paint(text, Style::new().bright_black())
}
pub fn red(text: &str) -> String {
    paint(text, Style::new().red())
}
pub fn green(text: &str) -> String {
    paint(text, Style::new().green())
}
pub fn yellow(text: &str) -> String {
    paint(text, Style::new().yellow())
}
pub fn blue(text: &str) -> String {
    paint(text, Style::new().blue())
}
pub fn cyan(text: &str) -> String {
    paint(text, Style::new().cyan())
}

/// Visible width, ignoring ANSI escapes so padding stays correct.
pub fn width(text: &str) -> usize {
    let mut count = 0;
    let mut in_escape = false;
    for ch in text.chars() {
        if in_escape {
            if ch == 'm' {
                in_escape = false;
            }
            continue;
        }
        if ch == '\u{1b}' {
            in_escape = true;
            continue;
        }
        count += 1;
    }
    count
}

fn pad(text: &str, to: usize) -> String {
    let visible = width(text);
    if visible >= to {
        text.to_string()
    } else {
        format!("{text}{}", " ".repeat(to - visible))
    }
}

/// Truncate to a visible width, appending an ellipsis when it does not fit.
fn truncate(text: &str, max: usize) -> String {
    if max <= 1 {
        return String::new();
    }
    if width(text) <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max - 1).collect();
    format!("{kept}…")
}

fn status_cell(status: u16) -> String {
    let text = status.to_string();
    match status {
        s if s >= 500 => red(&text),
        s if s >= 400 => yellow(&text),
        s if s >= 300 => cyan(&text),
        s if s >= 200 => green(&text),
        _ => gray(&text),
    }
}

fn protocol_cell(record: &PortRecord) -> String {
    // Remembered-but-unverified rows are dimmed uniformly, so the colour tells
    // you how much to trust the row before you read it.
    if record.stale {
        let text = if record.protocol == Protocol::Unknown {
            "?"
        } else {
            record.protocol.as_str()
        };
        return gray(text);
    }

    match record.protocol {
        Protocol::Https => green("https"),
        Protocol::Http => blue("http"),
        Protocol::Tcp => gray("tcp"),
        Protocol::Unknown => gray("?"),
    }
}

fn terminal_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(120)
}

pub struct TableOptions {
    /// Include ports that never answered HTTP.
    pub include_tcp: bool,
    pub max_width: usize,
}

impl Default for TableOptions {
    fn default() -> Self {
        Self {
            include_tcp: false,
            max_width: terminal_width(),
        }
    }
}

pub fn render_table(records: &[PortRecord], options: &TableOptions) -> String {
    let web: Vec<&PortRecord> = records.iter().filter(|r| r.protocol.is_web()).collect();
    let other: Vec<&PortRecord> = records.iter().filter(|r| !r.protocol.is_web()).collect();

    let mut lines: Vec<String> = Vec::new();

    if web.is_empty() {
        lines.push(dim("  No HTTP servers found."));
    } else {
        lines.extend(render_rows(&web, options.max_width));
    }

    if !other.is_empty() {
        lines.push(String::new());
        if options.include_tcp {
            lines.push(dim(&format!("  Other listeners ({})", other.len())));
            lines.extend(render_rows(&other, options.max_width));
        } else {
            let ports: Vec<String> = other.iter().map(|r| r.port.to_string()).collect();
            let plural = if other.len() == 1 { "" } else { "s" };
            let listed = truncate(&ports.join(", "), options.max_width.saturating_sub(30).max(20));
            lines.push(dim(&format!(
                "  {} non-HTTP listener{plural}: {listed}  {}",
                other.len(),
                gray("(--all to show)")
            )));
        }
    }

    lines.join("\n")
}

fn render_rows(records: &[&PortRecord], max_width: usize) -> Vec<String> {
    struct Row {
        port: String,
        protocol: String,
        status: String,
        title: String,
        source: String,
        extra: String,
    }

    let rows: Vec<Row> = records
        .iter()
        .map(|record| {
            let status = record
                .http
                .as_ref()
                .map(|h| status_cell(h.status))
                .unwrap_or_else(|| gray("—"));

            let title = record.label().to_string();

            // The title column already won these; repeating them in the source
            // column just costs width. This bites in two ways: a port with no
            // page title falls back to the project or process name, and a page
            // whose title *is* its package name says the same thing twice.
            let project = record
                .process
                .as_ref()
                .and_then(|p| p.project_name.as_deref())
                .filter(|p| *p != title);
            let process = record
                .process
                .as_ref()
                .and_then(|p| p.name.as_deref())
                .filter(|p| *p != title);

            // Prefer the project name; fall back to the binary, and show both
            // only when they add different information.
            let source = match (project, process) {
                (Some(project), Some(process)) if project != process => {
                    format!("{project} {}", gray(&format!("({process})")))
                }
                (Some(project), _) => project.to_string(),
                (None, Some(process)) => process.to_string(),
                (None, None) => String::new(),
            };

            Row {
                port: bold(&record.port.to_string()),
                protocol: protocol_cell(record),
                status,
                title,
                source,
                extra: record
                    .http
                    .as_ref()
                    .and_then(|h| h.framework.clone().or_else(|| h.server.clone()))
                    .unwrap_or_default(),
            }
        })
        .collect();

    let max_of = |f: &dyn Fn(&Row) -> usize, floor: usize| {
        rows.iter().map(f).max().unwrap_or(0).max(floor)
    };

    let w_port = max_of(&|r| width(&r.port), 4);
    let w_protocol = max_of(&|r| width(&r.protocol), 5);
    let w_status = max_of(&|r| width(&r.status), 3);
    let w_source = max_of(&|r| width(&r.source), 0).min(28);
    let w_extra = max_of(&|r| width(&r.extra), 0).min(14);

    // Whatever is left after the fixed columns goes to the title.
    let fixed = w_port + w_protocol + w_status + w_source + w_extra + 12;
    let w_title = max_width.saturating_sub(fixed).max(16);

    rows.iter()
        .map(|row| {
            let cells = [
                pad(&row.port, w_port),
                pad(&row.protocol, w_protocol),
                pad(&row.status, w_status),
                pad(&truncate(&row.title, w_title), w_title),
                pad(&gray(&truncate(&row.source, w_source)), w_source),
                dim(&truncate(&row.extra, w_extra)),
            ];
            format!("  {}", cells.join("  ")).trim_end().to_string()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DiscoveryTier, HttpInfo, PageMeta, ProcessInfo};

    fn web_record(port: u16, status: u16, title: &str) -> PortRecord {
        let mut record = PortRecord::new(port, DiscoveryTier::Lsof, "127.0.0.1", 0);
        record.protocol = Protocol::Http;
        record.http = Some(HttpInfo { status, ..Default::default() });
        record.meta = Some(PageMeta {
            title: Some(title.into()),
            ..Default::default()
        });
        record
    }

    #[test]
    fn width_ignores_ansi_escapes() {
        assert_eq!(width("plain"), 5);
        assert_eq!(width("\u{1b}[1mbold\u{1b}[22m"), 4);
    }

    #[test]
    fn truncate_marks_what_it_cut() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("truncate me", 5), "trun…");
        assert_eq!(width(&truncate("truncate me", 5)), 5);
    }

    #[test]
    fn renders_a_row_per_web_server() {
        let records = vec![web_record(3000, 200, "Acme"), web_record(5173, 200, "Vite")];
        let table = render_table(&records, &TableOptions::default());

        assert!(table.contains("3000"));
        assert!(table.contains("Acme"));
        assert!(table.contains("5173"));
        assert_eq!(table.lines().count(), 2);
    }

    #[test]
    fn non_http_listeners_are_summarised_unless_asked_for() {
        let mut tcp = PortRecord::new(7265, DiscoveryTier::Sweep, "127.0.0.1", 0);
        tcp.protocol = Protocol::Tcp;
        let records = vec![web_record(3000, 200, "Acme"), tcp];

        let summary = render_table(&records, &TableOptions::default());
        assert!(summary.contains("1 non-HTTP listener"));
        assert!(summary.contains("7265"));

        let full = render_table(
            &records,
            &TableOptions {
                include_tcp: true,
                ..Default::default()
            },
        );
        assert!(full.contains("Other listeners (1)"));
    }

    #[test]
    fn an_empty_result_says_so_rather_than_printing_nothing() {
        assert!(render_table(&[], &TableOptions::default()).contains("No HTTP servers found"));
    }

    #[test]
    fn the_source_column_does_not_repeat_the_title() {
        let mut record = web_record(3000, 200, "acme-web");
        record.process = Some(ProcessInfo {
            pid: 1,
            project_name: Some("acme-web".into()),
            name: Some("node".into()),
            ..Default::default()
        });

        let table = render_table(&[record], &TableOptions::default());
        // "acme-web" is the title, so the source column must not echo it.
        assert_eq!(table.matches("acme-web").count(), 1);
    }

    #[test]
    fn a_record_with_no_title_falls_back_through_project_then_process() {
        let mut record = PortRecord::new(3000, DiscoveryTier::Lsof, "127.0.0.1", 0);
        record.protocol = Protocol::Http;
        assert_eq!(record.label(), "(no title)");

        record.process = Some(ProcessInfo {
            pid: 1,
            name: Some("node".into()),
            ..Default::default()
        });
        assert_eq!(record.label(), "node");

        record.process.as_mut().unwrap().project_name = Some("acme".into());
        assert_eq!(record.label(), "acme");
    }
}
