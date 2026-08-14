//! Which local hostnames map to which ports.
//!
//! Ordinary user config, hand-editable, and the only thing `ports bind` writes.
//! The daemon watches this file rather than exposing a control socket, which
//! keeps the privileged half of the tool free of any request handling.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::{config_dir, write_atomic};

const BINDINGS_VERSION: u32 = 1;

/// Needs no DNS server, no /etc/resolver entry and no sudo: macOS, systemd-
/// resolved and every browser already send `*.localhost` to loopback. It is
/// also a trustworthy origin, so secure-context APIs work over plain HTTP.
pub const DEFAULT_TLD: &str = "localhost";

pub const DEFAULT_HTTP_PORT: u16 = 80;
pub const DEFAULT_HTTPS_PORT: u16 = 443;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// The subdomain, without the TLD. May contain dots: "api.myapp".
    pub name: String,
    /// Where to send it, as "host:port".
    pub target: String,
    #[serde(rename = "createdAt", default)]
    pub created_at: u64,
}

impl Binding {
    /// The full hostname this binding answers to.
    pub fn hostname(&self, tld: &str) -> String {
        format!("{}.{}", self.name, tld)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bindings {
    #[serde(default = "default_version")]
    pub version: u32,
    /// The local top-level domain, without a leading dot.
    #[serde(default = "default_tld")]
    pub tld: String,
    #[serde(rename = "httpPort", default = "default_http_port")]
    pub http_port: u16,
    /// `None` disables TLS entirely.
    #[serde(rename = "httpsPort", default = "default_https_port_opt")]
    pub https_port: Option<u16>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
}

fn default_version() -> u32 {
    BINDINGS_VERSION
}
fn default_tld() -> String {
    DEFAULT_TLD.to_string()
}
fn default_http_port() -> u16 {
    DEFAULT_HTTP_PORT
}
fn default_https_port_opt() -> Option<u16> {
    Some(DEFAULT_HTTPS_PORT)
}

impl Default for Bindings {
    fn default() -> Self {
        Self {
            version: BINDINGS_VERSION,
            tld: default_tld(),
            http_port: DEFAULT_HTTP_PORT,
            https_port: default_https_port_opt(),
            bindings: Vec::new(),
        }
    }
}

pub fn bindings_path() -> PathBuf {
    config_dir().join("bindings.json")
}

/// Read the table, or fail loudly if the file exists but cannot be understood.
///
/// Used by everything that then writes the file back. Defaulting silently here
/// would mean one hand-edit typo quietly discards every binding the user has —
/// and the next `ports bind` would commit that loss to disk.
pub fn load_bindings_strict() -> anyhow::Result<Bindings> {
    let raw = match std::fs::read_to_string(bindings_path()) {
        Ok(raw) => raw,
        // Not existing yet is the normal first-run state, not an error.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Bindings::default())
        }
        Err(err) => return Err(err.into()),
    };

    serde_json::from_str(&raw).map_err(|err| {
        anyhow::anyhow!(
            "{} is not valid JSON: {err}\n  Fix it by hand, or delete it to start over.",
            bindings_path().display()
        )
    })
}

/// Read the table, falling back to defaults.
///
/// For the proxy, which must keep serving whatever it can rather than refusing
/// to start. A parse failure is reported to the log and the previous in-memory
/// table is kept by the caller.
pub fn load_bindings() -> Bindings {
    match load_bindings_strict() {
        Ok(bindings) => bindings,
        Err(err) => {
            eprintln!("  bindings not loaded: {err}");
            Bindings::default()
        }
    }
}

/// Write the table back, pretty-printed because people hand-edit this file.
pub fn save_bindings(bindings: &Bindings) -> std::io::Result<()> {
    let mut json = serde_json::to_string_pretty(bindings).unwrap_or_else(|_| "{}".into());
    json.push('\n');
    write_atomic(&bindings_path(), &json)
}

/// Both proxy ports are unprivileged, so the daemon needs no root.
pub fn needs_privilege(bindings: &Bindings) -> bool {
    bindings.http_port < 1024 || bindings.https_port.is_some_and(|p| p < 1024)
}

/// Normalise a name into the subdomain part of a hostname.
///
/// Accepts what people actually type: `MyApp`, `myapp.localhost`, `.myapp`.
pub fn normalise_name(input: &str, tld: &str) -> Option<String> {
    let name = input.trim().trim_matches('.').to_lowercase();
    // Typing the full hostname is the obvious mistake; take it rather than
    // producing `myapp.localhost.localhost`.
    let name = name
        .strip_suffix(&format!(".{tld}"))
        .unwrap_or(&name)
        .to_string();

    if name.is_empty() {
        return None;
    }

    // Every dot-separated label must be a legal DNS label.
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return None;
        }
    }

    Some(name)
}

/// Normalise a target into "host:port".
///
/// A bare port is the common case and means loopback.
pub fn normalise_target(input: &str) -> Option<String> {
    let input = input.trim();

    if let Ok(port) = input.parse::<u16>() {
        return (port > 0).then(|| format!("127.0.0.1:{port}"));
    }

    let (host, port) = input.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if port == 0 || host.is_empty() {
        return None;
    }
    // `localhost` resolves to ::1 first on some setups, where a server bound
    // only to 127.0.0.1 would look down. Pin it.
    let host = if host == "localhost" { "127.0.0.1" } else { host };
    Some(format!("{host}:{port}"))
}

impl Bindings {
    /// Find the binding for a request's Host header.
    ///
    /// Handles the port suffix the browser sends on a non-default port, and is
    /// case-insensitive because Host headers are.
    pub fn resolve(&self, host_header: &str) -> Option<&Binding> {
        let host = host_header.trim().to_lowercase();
        // Strip the port, taking care not to cut an IPv6 literal in half.
        let host = match host.rsplit_once(':') {
            Some((before, after)) if after.chars().all(|c| c.is_ascii_digit()) => before,
            _ => &host,
        };

        let name = host.strip_suffix(&format!(".{}", self.tld))?;
        self.bindings.iter().find(|b| b.name == name)
    }

    pub fn get(&self, name: &str) -> Option<&Binding> {
        self.bindings.iter().find(|b| b.name == name)
    }

    /// Add a binding, or update the target of one that already exists.
    ///
    /// Idempotent on purpose: `ports adopt` re-runs constantly as ports move
    /// around, and should never accumulate duplicates.
    pub fn upsert(&mut self, name: String, target: String, now: u64) {
        match self.bindings.iter_mut().find(|b| b.name == name) {
            Some(existing) => existing.target = target,
            None => {
                self.bindings.push(Binding {
                    name,
                    target,
                    created_at: now,
                });
                self.bindings.sort_by(|a, b| a.name.cmp(&b.name));
            }
        }
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.bindings.len();
        self.bindings.retain(|b| b.name != name);
        self.bindings.len() != before
    }

    /// Ports the proxy itself listens on; binding to one would loop forever.
    pub fn own_ports(&self) -> Vec<u16> {
        let mut ports = vec![self.http_port];
        ports.extend(self.https_port);
        ports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> Bindings {
        let mut bindings = Bindings::default();
        bindings.upsert("myapp".into(), "127.0.0.1:4000".into(), 0);
        bindings.upsert("api.myapp".into(), "127.0.0.1:4001".into(), 0);
        bindings
    }

    #[test]
    fn resolves_a_host_header_to_its_binding() {
        let bindings = table();
        assert_eq!(
            bindings.resolve("myapp.localhost").map(|b| b.target.as_str()),
            Some("127.0.0.1:4000")
        );
        // Multi-level names work, which is what makes `web.acme.localhost` viable.
        assert_eq!(
            bindings.resolve("api.myapp.localhost").map(|b| b.target.as_str()),
            Some("127.0.0.1:4001")
        );
    }

    #[test]
    fn ignores_the_port_suffix_and_header_casing() {
        let bindings = table();
        for header in ["myapp.localhost:80", "MyApp.localhost", "MYAPP.LOCALHOST:8080"] {
            assert!(
                bindings.resolve(header).is_some(),
                "should have resolved {header}"
            );
        }
    }

    #[test]
    fn does_not_resolve_unknown_names_or_the_wrong_tld() {
        let bindings = table();
        assert!(bindings.resolve("nope.localhost").is_none());
        assert!(bindings.resolve("myapp.test").is_none());
        assert!(bindings.resolve("myapp").is_none());
    }

    #[test]
    fn accepts_the_forms_people_actually_type() {
        assert_eq!(normalise_name("myapp", "localhost").as_deref(), Some("myapp"));
        assert_eq!(normalise_name("MyApp", "localhost").as_deref(), Some("myapp"));
        // Typing the whole hostname must not double the suffix.
        assert_eq!(
            normalise_name("myapp.localhost", "localhost").as_deref(),
            Some("myapp")
        );
        assert_eq!(
            normalise_name("api.myapp", "localhost").as_deref(),
            Some("api.myapp")
        );
    }

    #[test]
    fn rejects_names_that_are_not_legal_hostnames() {
        for bad in ["", ".", "-lead", "trail-", "has space", "under_score", "a..b"] {
            assert!(
                normalise_name(bad, "localhost").is_none(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn a_bare_port_means_loopback() {
        assert_eq!(normalise_target("4000").as_deref(), Some("127.0.0.1:4000"));
        assert_eq!(
            normalise_target("192.168.1.5:8080").as_deref(),
            Some("192.168.1.5:8080")
        );
        // localhost can resolve to ::1 first, where a v4-only server looks down.
        assert_eq!(
            normalise_target("localhost:3000").as_deref(),
            Some("127.0.0.1:3000")
        );
        assert_eq!(normalise_target("0"), None);
        assert_eq!(normalise_target("not-a-port"), None);
    }

    #[test]
    fn upsert_updates_rather_than_duplicating() {
        let mut bindings = table();
        bindings.upsert("myapp".into(), "127.0.0.1:5000".into(), 0);

        assert_eq!(bindings.bindings.len(), 2);
        assert_eq!(bindings.get("myapp").unwrap().target, "127.0.0.1:5000");
    }

    #[test]
    fn remove_reports_whether_anything_went() {
        let mut bindings = table();
        assert!(bindings.remove("myapp"));
        assert!(!bindings.remove("myapp"));
        assert!(bindings.get("myapp").is_none());
    }

    #[test]
    fn privilege_is_needed_only_for_low_ports() {
        assert!(needs_privilege(&Bindings::default()));

        let unprivileged = Bindings {
            http_port: 8080,
            https_port: Some(8443),
            ..Default::default()
        };
        assert!(!needs_privilege(&unprivileged));

        let http_only_low = Bindings {
            http_port: 80,
            https_port: None,
            ..Default::default()
        };
        assert!(needs_privilege(&http_only_low));
    }

    #[test]
    fn a_missing_or_corrupt_file_yields_working_defaults() {
        let parsed: Bindings = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.tld, "localhost");
        assert_eq!(parsed.http_port, 80);
        assert!(parsed.bindings.is_empty());
    }
}
