//! The single source of truth for what we know about one listening port.
//!
//! Shared between the scanner, the cache and the CLI. Field names are
//! serialised in camelCase so `ports --json` stays pipe-compatible with the
//! shape people already have `jq` filters written against.

use serde::{Deserialize, Serialize};

/// How a port was found. Lower tiers are faster and more trustworthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryTier {
    /// 0: replayed from disk, not yet revalidated.
    Cache,
    /// 1: enumerated from the process table.
    Lsof,
    /// 2: connect probe against the common dev-port list.
    Common,
    /// 3: connect probe from the full 1-65535 range.
    Sweep,
}

/// What the port turned out to be speaking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
    /// Accepts connections but did not answer HTTP.
    Tcp,
    /// Not probed yet.
    #[default]
    Unknown,
}

impl Protocol {
    /// Is this something you could open in a browser?
    pub fn is_web(self) -> bool {
        matches!(self, Protocol::Http | Protocol::Https)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Tcp => "tcp",
            Protocol::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}

/// A raw listener as reported by the process table, before any probing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub port: u16,
    /// Bind address exactly as reported, e.g. "127.0.0.1", "*", "::1".
    pub address: String,
    pub family: Family,
    pub pid: Option<u32>,
    /// Short command name, e.g. "node". Truncated by lsof itself.
    pub command: Option<String>,
    pub user: Option<String>,
}

/// Details of the TLS certificate presented by an https port.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(rename = "validTo", skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<String>,
    #[serde(rename = "selfSigned")]
    pub self_signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "altNames", skip_serializing_if = "Option::is_none")]
    pub alt_names: Option<Vec<String>>,
}

/// Everything we scraped out of the HTML head.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "ogTitle", skip_serializing_if = "Option::is_none")]
    pub og_title: Option<String>,
    #[serde(rename = "ogDescription", skip_serializing_if = "Option::is_none")]
    pub og_description: Option<String>,
    #[serde(rename = "ogImage", skip_serializing_if = "Option::is_none")]
    pub og_image: Option<String>,
    #[serde(rename = "themeColor", skip_serializing_if = "Option::is_none")]
    pub theme_color: Option<String>,
    /// Absolute URL of the best favicon candidate we found.
    #[serde(rename = "faviconUrl", skip_serializing_if = "Option::is_none")]
    pub favicon_url: Option<String>,
}

/// The kind of project a working directory turned out to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectType {
    Node,
    Python,
    Rust,
    Go,
    Ruby,
    Php,
    Unknown,
}

/// The process behind the port, resolved as far as we could get.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    /// Full command line, may be long.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Just the executable, e.g. "node".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Resolved from a manifest in cwd, e.g. package.json "name".
    #[serde(rename = "projectName", skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
    #[serde(rename = "projectType", skip_serializing_if = "Option::is_none")]
    pub project_type: Option<ProjectType>,
    /// Repository root above `cwd`, when one was found. Drives `ports adopt`.
    #[serde(rename = "projectRoot", skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
}

/// The result of actually speaking HTTP to the port.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpInfo {
    /// The first status the port returned, before any redirect was followed.
    pub status: u16,
    #[serde(rename = "statusText", skip_serializing_if = "Option::is_none")]
    pub status_text: Option<String>,
    /// Where a 3xx pointed us.
    #[serde(rename = "redirectTo", skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
    /// Status after following redirects, when it differs from `status`.
    ///
    /// Only set when the whole chain stayed on loopback: an external redirect
    /// is left unfollowed, so its absence means "this 3xx leads off the box".
    #[serde(rename = "finalStatus", skip_serializing_if = "Option::is_none")]
    pub final_status: Option<u16>,
    /// The URL the redirect chain settled on, if it moved.
    #[serde(rename = "finalUrl", skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(rename = "poweredBy", skip_serializing_if = "Option::is_none")]
    pub powered_by: Option<String>,
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Framework fingerprints picked out of the response headers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRecord {
    /// Stable identity. The port number, as a string.
    pub id: String,
    pub port: u16,
    /// Every bind address seen for this port. A dual-stacked dev server shows
    /// up as both 127.0.0.1 and ::1; that is one server, so it is one record.
    pub addresses: Vec<String>,
    /// The address we actually probed.
    #[serde(rename = "probedAddress")]
    pub probed_address: String,

    pub alive: bool,
    pub protocol: Protocol,
    pub tier: DiscoveryTier,

    /// True while this record is a cache replay awaiting revalidation.
    pub stale: bool,
    /// This is the ports process itself.
    #[serde(rename = "isSelf")]
    pub is_self: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<PageMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessInfo>,

    /// Epoch ms.
    #[serde(rename = "firstSeen")]
    pub first_seen: u64,
    #[serde(rename = "lastSeen")]
    pub last_seen: u64,
    #[serde(rename = "lastProbed")]
    pub last_probed: u64,
    /// How many consecutive scans produced an identical fingerprint.
    #[serde(rename = "consecutiveStable")]
    pub consecutive_stable: u32,
    /// Hash of the volatile fields, used to decide whether to re-enrich.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Wall time of the last successful probe, in ms.
    #[serde(rename = "probeMs", skip_serializing_if = "Option::is_none")]
    pub probe_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PortRecord {
    /// A fresh record for a port we just found and have not yet described.
    pub fn new(port: u16, tier: DiscoveryTier, address: &str, now: u64) -> Self {
        Self {
            id: port.to_string(),
            port,
            addresses: Vec::new(),
            probed_address: probe_address_for(address),
            alive: true,
            protocol: Protocol::Unknown,
            tier,
            stale: false,
            is_self: false,
            http: None,
            meta: None,
            tls: None,
            process: None,
            first_seen: now,
            last_seen: now,
            last_probed: 0,
            consecutive_stable: 0,
            fingerprint: None,
            probe_ms: None,
            error: None,
        }
    }

    /// Best human label: page title, else project, else process name.
    pub fn label(&self) -> &str {
        if let Some(title) = self.meta.as_ref().and_then(|m| m.title.as_deref()) {
            return title;
        }
        if let Some(project) = self
            .process
            .as_ref()
            .and_then(|p| p.project_name.as_deref())
        {
            return project;
        }
        if let Some(name) = self.process.as_ref().and_then(|p| p.name.as_deref()) {
            return name;
        }
        if self.protocol == Protocol::Tcp {
            "(non-http service)"
        } else {
            "(no title)"
        }
    }
}

/// Which phase a running scan is in, for the progress line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    Lsof,
    Common,
    Sweep,
    Probing,
    Done,
}

impl ScanPhase {
    pub fn label(self) -> &'static str {
        match self {
            ScanPhase::Lsof => "reading process table",
            ScanPhase::Common => "checking common ports",
            ScanPhase::Sweep => "sweeping all ports",
            ScanPhase::Probing => "probing services",
            ScanPhase::Done => "done",
        }
    }
}

/// Progress of an in-flight scan.
#[derive(Debug, Clone, Copy)]
pub struct ScanProgress {
    pub phase: ScanPhase,
    pub scanned: usize,
    pub total: usize,
    pub found: usize,
    pub done: bool,
}

/// Wildcard binds are reachable over loopback, which is where we probe.
pub fn probe_address_for(address: &str) -> String {
    match address {
        "0.0.0.0" | "*" => "127.0.0.1".to_string(),
        "::" => "::1".to_string(),
        other => other.to_string(),
    }
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
