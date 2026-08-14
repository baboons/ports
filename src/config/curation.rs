//! Rules for what not to show.
//!
//! Most of a real machine's listening ports are app IPC endpoints nobody will
//! ever open. Without a way to silence them the listing is mostly noise.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::{config_dir, write_atomic};
use crate::types::PortRecord;

const CURATION_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Curation {
    pub version: u32,
    #[serde(rename = "hiddenPorts", default)]
    pub hidden_ports: Vec<u16>,
    /// Inclusive "from-to" spans, e.g. "44000-44999".
    #[serde(rename = "hiddenRanges", default)]
    pub hidden_ranges: Vec<String>,
    /// Case-insensitive substrings matched against process name and command.
    #[serde(rename = "hiddenCommands", default)]
    pub hidden_commands: Vec<String>,
}

impl Default for Curation {
    fn default() -> Self {
        Self {
            version: CURATION_VERSION,
            hidden_ports: Vec::new(),
            hidden_ranges: Vec::new(),
            hidden_commands: Vec::new(),
        }
    }
}

impl Curation {
    pub fn is_empty(&self) -> bool {
        self.hidden_ports.is_empty()
            && self.hidden_ranges.is_empty()
            && self.hidden_commands.is_empty()
    }
}

/// Which kind of rule hid a port, so the UI can explain what un-hiding will do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HideReason {
    Port,
    Range,
    Command,
}

impl HideReason {
    pub fn as_str(self) -> &'static str {
        match self {
            HideReason::Port => "port",
            HideReason::Range => "range",
            HideReason::Command => "command",
        }
    }
}

pub fn curation_path() -> PathBuf {
    config_dir().join("curation.json")
}

/// Read the rules.
///
/// Never fails: a missing, unreadable or corrupt file means no rules, which is
/// always a safe answer — at worst you see more than you wanted.
pub fn load_curation() -> Curation {
    let Ok(raw) = std::fs::read_to_string(curation_path()) else {
        return Curation::default();
    };
    let mut curation: Curation = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(_) => return Curation::default(),
    };

    curation.version = CURATION_VERSION;
    curation.hidden_ports.retain(|port| *port >= 1);
    curation.hidden_ports.sort_unstable();
    curation.hidden_ports.dedup();
    curation.hidden_ranges.retain(|r| parse_range(r).is_some());
    curation
        .hidden_commands
        .retain(|c| !c.trim().is_empty());
    curation
}

/// Write the rules back, pretty-printed because people hand-edit this file.
pub fn save_curation(curation: &Curation) -> std::io::Result<()> {
    let mut json = serde_json::to_string_pretty(curation)
        .unwrap_or_else(|_| "{}".into());
    json.push('\n');
    write_atomic(&curation_path(), &json)
}

/// Parse an inclusive "from-to" span.
pub fn parse_range(value: &str) -> Option<(u16, u16)> {
    let (from, to) = value.split_once('-')?;
    let from: u32 = from.trim().parse().ok()?;
    let to: u32 = to.trim().parse().ok()?;
    if from < 1 || to > 65535 || from > to {
        return None;
    }
    Some((from as u16, to as u16))
}

/// Which rule, if any, hides this record.
///
/// Precedence is strict — port, then range, then command — so un-hiding can
/// tell you a broader rule still covers the port rather than leaving a button
/// that appears to do nothing.
pub fn hide_reason_for(record: &PortRecord, curation: &Curation) -> Option<HideReason> {
    if curation.hidden_ports.contains(&record.port) {
        return Some(HideReason::Port);
    }

    for raw in &curation.hidden_ranges {
        if let Some((from, to)) = parse_range(raw) {
            if record.port >= from && record.port <= to {
                return Some(HideReason::Range);
            }
        }
    }

    let haystack = {
        let process = record.process.as_ref();
        let name = process.and_then(|p| p.name.as_deref()).unwrap_or("");
        let command = process.and_then(|p| p.command.as_deref()).unwrap_or("");
        format!("{name} {command}").to_lowercase()
    };
    // Guarded: without a process the haystack is a single space, which a
    // needle of " " would match, hiding everything.
    if haystack.trim().is_empty() {
        return None;
    }

    for needle in &curation.hidden_commands {
        if haystack.contains(&needle.to_lowercase()) {
            return Some(HideReason::Command);
        }
    }

    None
}

pub fn is_hidden(record: &PortRecord, curation: &Curation) -> bool {
    hide_reason_for(record, curation).is_some()
}

pub fn with_hidden(mut curation: Curation, port: u16) -> Curation {
    if !curation.hidden_ports.contains(&port) {
        curation.hidden_ports.push(port);
        curation.hidden_ports.sort_unstable();
    }
    curation
}

/// Remove an exact-port rule only.
///
/// Ranges and command rules are left alone deliberately: they were written by
/// hand, and clicking "show" on one port should not silently delete a rule
/// covering a thousand others.
pub fn without_hidden(mut curation: Curation, port: u16) -> Curation {
    curation.hidden_ports.retain(|p| *p != port);
    curation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DiscoveryTier, ProcessInfo};

    fn record_with_process(port: u16, name: Option<&str>, command: Option<&str>) -> PortRecord {
        let mut record = PortRecord::new(port, DiscoveryTier::Lsof, "127.0.0.1", 0);
        if name.is_some() || command.is_some() {
            record.process = Some(ProcessInfo {
                pid: 1,
                name: name.map(str::to_string),
                command: command.map(str::to_string),
                ..Default::default()
            });
        }
        record
    }

    fn plain(port: u16) -> PortRecord {
        record_with_process(port, Some("node"), None)
    }

    #[test]
    fn accepts_sane_ranges_and_rejects_the_rest() {
        assert_eq!(parse_range("44000-44999"), Some((44000, 44999)));
        assert_eq!(parse_range(" 100 - 200 "), Some((100, 200)));
        assert_eq!(parse_range("200-100"), None);
        assert_eq!(parse_range("0-100"), None);
        assert_eq!(parse_range("1-70000"), None);
        assert_eq!(parse_range("nonsense"), None);
    }

    #[test]
    fn an_exact_port_rule_hides_only_that_port() {
        let curation = with_hidden(Curation::default(), 6463);
        assert_eq!(hide_reason_for(&plain(6463), &curation), Some(HideReason::Port));
        assert_eq!(hide_reason_for(&plain(6464), &curation), None);
    }

    #[test]
    fn a_range_rule_hides_its_whole_span_inclusive() {
        let curation = Curation {
            hidden_ranges: vec!["44000-44999".into()],
            ..Default::default()
        };
        for port in [44000u16, 44500, 44999] {
            assert_eq!(
                hide_reason_for(&plain(port), &curation),
                Some(HideReason::Range),
                "{port} should be hidden"
            );
        }
        assert_eq!(hide_reason_for(&plain(45000), &curation), None);
    }

    #[test]
    fn a_command_rule_matches_name_or_command_case_insensitively() {
        let curation = Curation {
            hidden_commands: vec!["discord".into()],
            ..Default::default()
        };

        assert_eq!(
            hide_reason_for(&record_with_process(1, Some("Discord Helper"), None), &curation),
            Some(HideReason::Command)
        );
        assert_eq!(
            hide_reason_for(
                &record_with_process(2, None, Some("/Applications/Discord.app/x")),
                &curation
            ),
            Some(HideReason::Command)
        );
        assert_eq!(
            hide_reason_for(&record_with_process(3, Some("node"), None), &curation),
            None
        );
        // No process at all must never match, whatever the needle.
        assert_eq!(hide_reason_for(&record_with_process(4, None, None), &curation), None);
    }

    #[test]
    fn un_hiding_removes_a_port_rule_but_leaves_broader_rules_alone() {
        let curation = Curation {
            hidden_ports: vec![44100],
            hidden_ranges: vec!["44000-44999".into()],
            ..Default::default()
        };

        let after = without_hidden(curation, 44100);
        assert!(after.hidden_ports.is_empty());
        assert_eq!(after.hidden_ranges, vec!["44000-44999".to_string()]);
        // Still hidden, but now you can be told why.
        assert_eq!(hide_reason_for(&plain(44100), &after), Some(HideReason::Range));
    }

    #[test]
    fn hiding_the_same_port_twice_does_not_duplicate_it() {
        let curation = with_hidden(with_hidden(Curation::default(), 3000), 3000);
        assert_eq!(curation.hidden_ports, vec![3000]);
    }

    #[test]
    fn hidden_ports_stay_sorted() {
        let mut curation = Curation::default();
        for port in [8080u16, 3000, 44450] {
            curation = with_hidden(curation, port);
        }
        assert_eq!(curation.hidden_ports, vec![3000, 8080, 44450]);
    }

    #[test]
    fn an_empty_curation_hides_nothing() {
        assert!(!is_hidden(&plain(3000), &Curation::default()));
    }

    #[test]
    fn a_corrupt_rules_file_is_treated_as_no_rules() {
        // Round-trip through the real serialiser to prove the shape is stable.
        let curation = Curation {
            hidden_ports: vec![6463],
            hidden_ranges: vec!["44000-44999".into()],
            hidden_commands: vec!["figma".into()],
            ..Default::default()
        };
        let json = serde_json::to_string(&curation).unwrap();
        let parsed: Curation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, curation);

        assert!(serde_json::from_str::<Curation>("{not json").is_err());
    }
}
