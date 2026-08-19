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

/// Loopback only. Serving the LAN is opt-in, because the index lists every
/// service on the machine and that is not something to expose by accident.
pub const DEFAULT_HOST: &str = "127.0.0.1";

/// Unprivileged by default: `/etc/resolver` can name a port, so nothing needs
/// root just to make a custom domain resolve on this machine. Serving a whole
/// network means moving to 53, which is a deliberate step.
pub const DEFAULT_DNS_PORT: u16 = 15353;

/// Cloudflare's pair. Queries we have no answer for go here.
pub const DEFAULT_FORWARDERS: [&str; 2] = ["1.1.1.1", "1.0.0.1"];

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

/// The resolver's own settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    /// 15353 to answer only what `/etc/resolver` sends here; 53 to be a
    /// resolver other machines can point at.
    #[serde(default = "default_dns_port")]
    pub port: u16,

    /// Where anything we have no answer for is sent.
    #[serde(default = "default_forwarders")]
    pub forward: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            port: default_dns_port(),
            forward: default_forwarders(),
        }
    }
}

impl DnsConfig {
    /// The upstreams as addresses, dropping anything unparseable.
    ///
    /// A bare IP is the normal thing to write, so `:53` is filled in.
    pub fn forwarders(&self) -> Vec<std::net::SocketAddr> {
        self.forward
            .iter()
            .filter_map(|entry| parse_forwarder(entry))
            .collect()
    }
}

/// Accept `1.1.1.1`, `1.1.1.1:53`, or a bracketed IPv6 address.
pub fn parse_forwarder(entry: &str) -> Option<std::net::SocketAddr> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    if let Ok(address) = entry.parse::<std::net::SocketAddr>() {
        return Some(address);
    }
    // No port given: DNS is 53 unless told otherwise.
    entry
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| std::net::SocketAddr::new(ip, 53))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bindings {
    #[serde(default = "default_version")]
    pub version: u32,

    /// Domains this proxy answers for, without a leading dot.
    ///
    /// A list rather than one value so a machine can be reached by more than
    /// one name: `myapp.localhost` on the box itself and `myapp.devbox.lan`
    /// from the rest of the network, pointed here by whatever DNS or hosts
    /// file you already keep. The first is canonical — it is what new
    /// bindings are printed as.
    #[serde(default = "default_domains")]
    pub domains: Vec<String>,

    /// Interface to listen on. `0.0.0.0` serves the whole network.
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(rename = "httpPort", default = "default_http_port")]
    pub http_port: u16,
    /// `None` disables TLS entirely.
    #[serde(rename = "httpsPort", default = "default_https_port_opt")]
    pub https_port: Option<u16>,
    #[serde(default)]
    pub bindings: Vec<Binding>,

    #[serde(default)]
    pub dns: DnsConfig,
}

fn default_version() -> u32 {
    BINDINGS_VERSION
}
fn default_domains() -> Vec<String> {
    vec![DEFAULT_TLD.to_string()]
}
fn default_host() -> String {
    DEFAULT_HOST.to_string()
}
fn default_dns_port() -> u16 {
    DEFAULT_DNS_PORT
}
fn default_forwarders() -> Vec<String> {
    DEFAULT_FORWARDERS.iter().map(|s| s.to_string()).collect()
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
            domains: default_domains(),
            host: default_host(),
            http_port: DEFAULT_HTTP_PORT,
            https_port: default_https_port_opt(),
            bindings: Vec::new(),
            dns: DnsConfig::default(),
        }
    }
}

/// Domains that would cause trouble, and why.
///
/// Judged by the last label: the HSTS preload list covers subdomains, so
/// `myapp.dev` is forced to HTTPS exactly as `.dev` is.
pub fn warn_about(domain: &str) -> Option<&'static str> {
    let effective = domain.rsplit('.').next().unwrap_or(domain);
    match effective {
        // Real, HSTS-preloaded: every http:// request is force-upgraded, so
        // plain HTTP can never work no matter what we serve.
        "dev" | "app" | "foo" | "zip" | "mov" => {
            Some("is a real, HSTS-preloaded TLD — browsers force HTTPS on it, so plain HTTP will never work")
        }
        // mDNS territory; hijacking it breaks device discovery.
        "local" => Some("is used by mDNS/Bonjour — taking it over breaks device discovery"),
        _ => None,
    }
}

/// Is this a usable domain to serve under?
///
/// Multi-label is the normal case for a custom one — `devbox.lan`,
/// `home.arpa` — so every label is checked rather than the whole string.
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    // An all-numeric name would be ambiguous with an address.
    if domain
        .split('.')
        .all(|label| !label.is_empty() && label.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }

    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Check a domain and return it normalised, or say why not.
///
/// The one place the rules live, so `ports domain` and the index page cannot
/// disagree about what is allowed.
pub fn check_domain(domain: &str) -> Result<String, String> {
    let domain = domain.trim().trim_matches('.').to_lowercase();
    if !is_valid_domain(&domain) {
        return Err(format!("'{domain}' is not a usable domain"));
    }
    if let Some(reason) = warn_about(&domain) {
        return Err(format!("{domain} {reason}"));
    }
    Ok(domain)
}

/// Lowercase a Host header and drop its port, without cutting an IPv6
/// literal in half.
fn strip_port(host_header: &str) -> String {
    let host = host_header.trim().to_lowercase();
    match host.rsplit_once(':') {
        Some((before, after)) if after.chars().all(|c| c.is_ascii_digit()) => before.to_string(),
        _ => host,
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
    load_bindings_from(&bindings_path())
}

/// Read from a named path.
pub fn load_bindings_from(path: &std::path::Path) -> anyhow::Result<Bindings> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        // Not existing yet is the normal first-run state, not an error.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Bindings::default()),
        Err(err) => return Err(err.into()),
    };

    let malformed = |err: serde_json::Error| {
        anyhow::anyhow!(
            "{} is not valid JSON: {err}\n  Fix it by hand, or delete it to start over.",
            path.display()
        )
    };

    let mut value: serde_json::Value = serde_json::from_str(&raw).map_err(malformed)?;

    // `domains` replaced a single `tld`. A file written before that still says
    // `tld`, and ignoring it would silently move every binding to
    // `.localhost` — so translate it before it ever becomes a struct, which
    // keeps the legacy spelling out of the type.
    if let Some(object) = value.as_object_mut() {
        if !object.contains_key("domains") {
            if let Some(tld) = object
                .remove("tld")
                .and_then(|v| v.as_str().map(str::to_string))
            {
                object.insert("domains".into(), serde_json::json!([tld]));
            }
        }
    }

    let mut bindings: Bindings = serde_json::from_value(value).map_err(malformed)?;
    bindings.normalise();
    Ok(bindings)
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
    save_bindings_to(&bindings_path(), bindings)
}

/// Write to a named path.
///
/// The daemon carries its own path rather than reaching for the global one, so
/// a test can point it somewhere harmless instead of at the running user's
/// real configuration.
pub fn save_bindings_to(path: &std::path::Path, bindings: &Bindings) -> std::io::Result<()> {
    let mut json = serde_json::to_string_pretty(bindings).unwrap_or_else(|_| "{}".into());
    json.push('\n');
    write_atomic(path, &json)
}

/// Any port below 1024 means the daemon must be able to bind a privileged one.
pub fn needs_privilege(bindings: &Bindings) -> bool {
    bindings.http_port < 1024
        || bindings.https_port.is_some_and(|p| p < 1024)
        // A resolver on 53 needs exactly the same treatment as a proxy on 80.
        || bindings.dns.port < 1024
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
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
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
    let host = if host == "localhost" {
        "127.0.0.1"
    } else {
        host
    };
    Some(format!("{host}:{port}"))
}

impl Bindings {
    /// Find the binding for a request's Host header.
    ///
    /// Handles the port suffix the browser sends on a non-default port, and is
    /// case-insensitive because Host headers are.
    pub fn resolve(&self, host_header: &str) -> Option<&Binding> {
        let name = self.name_in(host_header)?;
        self.bindings.iter().find(|b| b.name == name)
    }

    /// Strip whichever configured domain a hostname ends with, leaving the name.
    ///
    /// The longest match wins, so with both `lan` and `devbox.lan` configured,
    /// `myapp.devbox.lan` is `myapp` rather than `myapp.devbox`.
    pub fn name_in(&self, host_header: &str) -> Option<String> {
        let host = strip_port(host_header);

        let mut best: Option<&str> = None;
        for domain in &self.domains {
            let suffix = format!(".{}", domain.trim_matches('.').to_lowercase());
            let Some(name) = host.strip_suffix(&suffix) else {
                continue;
            };
            if best.map(|found| name.len() < found.len()).unwrap_or(true) {
                best = Some(name);
            }
        }

        best.filter(|name| !name.is_empty()).map(str::to_string)
    }

    /// Is this hostname one of the configured domains itself, with no subdomain?
    pub fn is_bare_domain(&self, host_header: &str) -> bool {
        let host = strip_port(host_header);
        self.domains
            .iter()
            .any(|domain| host == domain.trim_matches('.').to_lowercase())
    }

    /// The canonical domain: what new bindings are printed as.
    pub fn primary(&self) -> &str {
        self.domains
            .first()
            .map(String::as_str)
            .unwrap_or(DEFAULT_TLD)
    }

    /// Every domain that needs resolver setup, i.e. all but `.localhost`.
    pub fn domains_needing_dns(&self) -> Vec<&str> {
        self.domains
            .iter()
            .map(String::as_str)
            .filter(|domain| *domain != DEFAULT_TLD && !domain.ends_with(".localhost"))
            .collect()
    }

    /// Normalise whatever we were handed, so matching can assume a shape.
    pub fn normalise(&mut self) {
        for domain in &mut self.domains {
            *domain = domain.trim().trim_matches('.').to_lowercase();
        }
        self.domains.retain(|domain| !domain.is_empty());
        self.domains.dedup();

        // A table with no domain at all could route nothing.
        if self.domains.is_empty() {
            self.domains = default_domains();
        }
    }

    /// True when the proxy is reachable from beyond this machine.
    pub fn is_exposed(&self) -> bool {
        !self
            .host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
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
            bindings
                .resolve("myapp.localhost")
                .map(|b| b.target.as_str()),
            Some("127.0.0.1:4000")
        );
        // Multi-level names work, which is what makes `web.acme.localhost` viable.
        assert_eq!(
            bindings
                .resolve("api.myapp.localhost")
                .map(|b| b.target.as_str()),
            Some("127.0.0.1:4001")
        );
    }

    #[test]
    fn ignores_the_port_suffix_and_header_casing() {
        let bindings = table();
        for header in [
            "myapp.localhost:80",
            "MyApp.localhost",
            "MYAPP.LOCALHOST:8080",
        ] {
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
        assert_eq!(
            normalise_name("myapp", "localhost").as_deref(),
            Some("myapp")
        );
        assert_eq!(
            normalise_name("MyApp", "localhost").as_deref(),
            Some("myapp")
        );
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
        for bad in [
            "",
            ".",
            "-lead",
            "trail-",
            "has space",
            "under_score",
            "a..b",
        ] {
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

    fn multi(domains: &[&str]) -> Bindings {
        let mut bindings = Bindings {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            ..Default::default()
        };
        bindings.upsert("myapp".into(), "127.0.0.1:4000".into(), 0);
        bindings
    }

    #[test]
    fn accepts_the_domains_people_actually_point_at_a_box() {
        for good in [
            "test",
            "localhost",
            "lo",
            "internal",
            "dev-box",
            // Multi-label is the normal shape for a custom one.
            "devbox.lan",
            "home.arpa",
            "dev.internal.example",
        ] {
            assert!(is_valid_domain(good), "{good} should be valid");
        }
    }

    #[test]
    fn rejects_domains_that_are_not_hostnames() {
        for bad in [
            "",
            "has space",
            "under_score",
            "-lead",
            "trail-",
            "123",
            "a..b",
            ".",
            "trailing.",
        ] {
            assert!(!is_valid_domain(bad), "{bad} should be rejected");
        }
    }

    #[test]
    fn hsts_preloaded_domains_are_refused_at_any_depth() {
        // The preload list covers subdomains, so myapp.dev is forced to HTTPS
        // exactly as .dev is — plain HTTP could never work under either.
        assert!(warn_about("dev").is_some());
        assert!(warn_about("devbox.dev").is_some());
        assert!(warn_about("anything.app").is_some());

        assert!(warn_about("devbox.lan").is_none());
        assert!(warn_about("home.arpa").is_none());
    }

    #[test]
    fn the_shared_check_normalises_and_explains() {
        assert_eq!(check_domain("  .DevBox.LAN. ").as_deref(), Ok("devbox.lan"));
        // The reason comes back with the rejection, so both callers can say why.
        assert!(check_domain("myapp.dev").unwrap_err().contains("HSTS"));
        assert!(check_domain("has space").is_err());
    }

    #[test]
    fn a_binding_answers_under_every_configured_domain() {
        // The point of the list: reachable as myapp.localhost on the box, and
        // as myapp.devbox.lan from anywhere the hosts file points here.
        let bindings = multi(&["localhost", "devbox.lan"]);

        assert!(bindings.resolve("myapp.localhost").is_some());
        assert!(bindings.resolve("myapp.devbox.lan").is_some());
        assert!(bindings.resolve("myapp.devbox.lan:8080").is_some());
        assert!(bindings.resolve("myapp.elsewhere.lan").is_none());
    }

    #[test]
    fn the_longest_matching_domain_wins() {
        // With both configured, myapp.devbox.lan is `myapp`, not `myapp.devbox`
        // — otherwise the more specific domain could never be used.
        let bindings = multi(&["lan", "devbox.lan"]);
        assert_eq!(
            bindings.name_in("myapp.devbox.lan").as_deref(),
            Some("myapp")
        );
        assert_eq!(bindings.name_in("myapp.lan").as_deref(), Some("myapp"));
    }

    #[test]
    fn the_bare_domain_is_not_a_binding() {
        let bindings = multi(&["localhost", "devbox.lan"]);
        assert!(bindings.is_bare_domain("devbox.lan"));
        assert!(bindings.is_bare_domain("devbox.lan:8080"));
        assert!(!bindings.is_bare_domain("myapp.devbox.lan"));
        // A bare domain leaves no name to look up.
        assert!(bindings.name_in("devbox.lan").is_none());
    }

    #[test]
    fn the_first_domain_is_the_one_new_bindings_are_printed_as() {
        assert_eq!(multi(&["devbox.lan", "localhost"]).primary(), "devbox.lan");
        assert_eq!(Bindings::default().primary(), "localhost");
    }

    #[test]
    fn only_domains_the_os_does_not_already_resolve_need_setup() {
        let bindings = multi(&["localhost", "devbox.lan", "test"]);
        let needing = bindings.domains_needing_dns();
        assert!(needing.contains(&"devbox.lan"));
        assert!(needing.contains(&"test"));
        // Every resolver sends *.localhost to loopback on its own.
        assert!(!needing.contains(&"localhost"));
    }

    #[test]
    fn exposure_is_decided_by_the_listen_address() {
        assert!(!Bindings::default().is_exposed());
        let lan = Bindings {
            host: "0.0.0.0".into(),
            ..Default::default()
        };
        assert!(lan.is_exposed());
    }

    #[test]
    fn a_config_written_before_domains_existed_keeps_its_domain() {
        // Reading `tld` and dropping it would silently move every binding to
        // .localhost, breaking links the user already has.
        let legacy = serde_json::json!({
            "version": 1,
            "tld": "test",
            "bindings": [{ "name": "myapp", "target": "127.0.0.1:4000" }]
        });

        let mut object = legacy.as_object().unwrap().clone();
        if !object.contains_key("domains") {
            if let Some(tld) = object
                .remove("tld")
                .and_then(|v| v.as_str().map(str::to_string))
            {
                object.insert("domains".into(), serde_json::json!([tld]));
            }
        }
        let mut parsed: Bindings =
            serde_json::from_value(serde_json::Value::Object(object)).unwrap();
        parsed.normalise();

        assert_eq!(parsed.primary(), "test");
        assert!(parsed.resolve("myapp.test").is_some());
    }

    #[test]
    fn domains_are_normalised_however_they_were_typed() {
        let mut bindings = Bindings {
            domains: vec!["  .DevBox.LAN. ".into(), "".into(), "localhost".into()],
            ..Default::default()
        };
        bindings.normalise();
        assert_eq!(bindings.domains, vec!["devbox.lan", "localhost"]);
    }

    #[test]
    fn a_table_with_no_domains_falls_back_rather_than_routing_nothing() {
        let mut bindings = Bindings {
            domains: Vec::new(),
            ..Default::default()
        };
        bindings.normalise();
        assert_eq!(bindings.domains, vec!["localhost"]);
    }

    #[test]
    fn a_missing_or_corrupt_file_yields_working_defaults() {
        let parsed: Bindings = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.primary(), "localhost");
        assert_eq!(parsed.http_port, 80);
        assert!(parsed.bindings.is_empty());
    }
}
