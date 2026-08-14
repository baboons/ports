//! Tell the operating system to send `*.<tld>` to our responder.
//!
//! Three mechanisms, because the platforms genuinely differ:
//!
//! - macOS reads `/etc/resolver/<tld>`, which is per-domain and supports a
//!   `port` keyword, so a wildcard costs one file and no privileged listener.
//! - systemd-resolved takes a drop-in with a routing domain, which is the
//!   equivalent on most modern Linux.
//! - Everywhere else, a managed block in `/etc/hosts`. No wildcards, so it has
//!   to be rewritten as bindings change — but it works on anything.
//!
//! None of this is needed for `.localhost`, which every resolver already sends
//! to loopback on its own.

use std::path::PathBuf;

use crate::config::bindings::Bindings;
use crate::dns::DNS_PORT;

/// Marks the region of /etc/hosts we own, so hand-written entries survive.
const HOSTS_BEGIN: &str = "# >>> ports begin";
const HOSTS_END: &str = "# <<< ports end";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// Nothing to do — the OS already resolves this TLD.
    None,
    MacResolver,
    SystemdResolved,
    HostsFile,
}

/// Which mechanism this machine needs for this TLD.
pub fn mechanism_for(tld: &str) -> Mechanism {
    // RFC 6761: every resolver that matters sends *.localhost to loopback.
    if tld == "localhost" {
        return Mechanism::None;
    }
    if cfg!(target_os = "macos") {
        return Mechanism::MacResolver;
    }
    if std::path::Path::new("/run/systemd/resolve").exists() {
        return Mechanism::SystemdResolved;
    }
    Mechanism::HostsFile
}

pub fn mac_resolver_path(tld: &str) -> PathBuf {
    PathBuf::from("/etc/resolver").join(tld)
}

pub fn systemd_dropin_path() -> PathBuf {
    PathBuf::from("/etc/systemd/resolved.conf.d/ports.conf")
}

/// The `/etc/resolver/<tld>` file contents.
pub fn mac_resolver_file(port: u16) -> String {
    format!("nameserver 127.0.0.1\nport {port}\n")
}

/// A systemd-resolved drop-in routing one domain at our responder.
///
/// The `~` prefix makes it a routing domain: only names under it are sent
/// here, and ordinary DNS is untouched.
pub fn systemd_dropin_file(tld: &str, port: u16) -> String {
    format!("[Resolve]\nDNS=127.0.0.1:{port}\nDomains=~{tld}\n")
}

/// Rewrite the managed block of an /etc/hosts file.
///
/// Everything outside the markers is preserved exactly, because this file is
/// full of things other tools and people put there.
pub fn rewrite_hosts(existing: &str, bindings: &Bindings) -> String {
    let mut kept = String::new();
    let mut inside = false;

    for line in existing.lines() {
        if line.trim() == HOSTS_BEGIN {
            inside = true;
            continue;
        }
        if line.trim() == HOSTS_END {
            inside = false;
            continue;
        }
        if !inside {
            kept.push_str(line);
            kept.push('\n');
        }
    }

    // Nothing of ours to write: leave the file without an empty marker block.
    if bindings.bindings.is_empty() || bindings.tld == "localhost" {
        return kept.trim_end().to_string() + "\n";
    }

    let mut out = kept.trim_end().to_string();
    out.push_str("\n\n");
    out.push_str(HOSTS_BEGIN);
    out.push_str("\n# Managed by `ports`. Edits between these markers are overwritten.\n");
    for binding in &bindings.bindings {
        let hostname = binding.hostname(&bindings.tld);
        out.push_str(&format!("127.0.0.1\t{hostname}\n::1\t\t{hostname}\n"));
    }
    out.push_str(HOSTS_END);
    out.push('\n');
    out
}

/// What has to happen for this TLD to resolve, as a shell command the user can
/// read before it runs.
pub struct Install {
    pub mechanism: Mechanism,
    pub path: PathBuf,
    pub contents: String,
    /// Run after writing, if anything.
    pub reload: Option<Vec<String>>,
}

pub fn plan_install(tld: &str) -> Option<Install> {
    match mechanism_for(tld) {
        Mechanism::None => None,
        Mechanism::MacResolver => Some(Install {
            mechanism: Mechanism::MacResolver,
            path: mac_resolver_path(tld),
            contents: mac_resolver_file(DNS_PORT),
            // macOS notices a new resolver file on its own, but flushing makes
            // it immediate rather than eventually.
            reload: Some(vec![
                "dscacheutil".into(),
                "-flushcache".into(),
            ]),
        }),
        Mechanism::SystemdResolved => Some(Install {
            mechanism: Mechanism::SystemdResolved,
            path: systemd_dropin_path(),
            contents: systemd_dropin_file(tld, DNS_PORT),
            reload: Some(vec![
                "systemctl".into(),
                "restart".into(),
                "systemd-resolved".into(),
            ]),
        }),
        Mechanism::HostsFile => Some(Install {
            mechanism: Mechanism::HostsFile,
            path: PathBuf::from("/etc/hosts"),
            contents: String::new(), // built from the bindings at write time
            reload: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bindings_with(tld: &str, names: &[(&str, u16)]) -> Bindings {
        let mut bindings = Bindings {
            tld: tld.to_string(),
            ..Default::default()
        };
        for (name, port) in names {
            bindings.upsert(name.to_string(), format!("127.0.0.1:{port}"), 0);
        }
        bindings
    }

    #[test]
    fn localhost_needs_no_resolver_setup() {
        assert_eq!(mechanism_for("localhost"), Mechanism::None);
        assert!(plan_install("localhost").is_none());
    }

    #[test]
    fn a_custom_tld_needs_setup() {
        assert_ne!(mechanism_for("test"), Mechanism::None);
        assert!(plan_install("test").is_some());
    }

    #[test]
    fn the_mac_resolver_file_points_at_the_unprivileged_port() {
        let contents = mac_resolver_file(15353);
        assert!(contents.contains("nameserver 127.0.0.1"));
        // The port keyword is what keeps the responder off port 53, and so
        // out of needing root.
        assert!(contents.contains("port 15353"));
    }

    #[test]
    fn the_systemd_dropin_routes_only_our_domain() {
        let contents = systemd_dropin_file("test", 15353);
        assert!(contents.contains("DNS=127.0.0.1:15353"));
        // The ~ makes it a routing domain; without it this would become the
        // machine's default resolver.
        assert!(contents.contains("Domains=~test"));
    }

    #[test]
    fn hosts_rewriting_preserves_everything_outside_the_markers() {
        let existing = "127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n\
                        # someone's own entry\n10.0.0.5\tstaging.internal\n";
        let result = rewrite_hosts(existing, &bindings_with("test", &[("myapp", 4000)]));

        assert!(result.contains("127.0.0.1\tlocalhost"));
        assert!(result.contains("broadcasthost"));
        assert!(result.contains("# someone's own entry"));
        assert!(result.contains("10.0.0.5\tstaging.internal"));
        assert!(result.contains("myapp.test"));
    }

    #[test]
    fn rewriting_twice_does_not_accumulate_blocks() {
        let existing = "127.0.0.1\tlocalhost\n";
        let once = rewrite_hosts(existing, &bindings_with("test", &[("myapp", 4000)]));
        let twice = rewrite_hosts(&once, &bindings_with("test", &[("myapp", 4000)]));

        assert_eq!(once, twice, "a second write should be a no-op");
        assert_eq!(twice.matches(HOSTS_BEGIN).count(), 1);
    }

    #[test]
    fn removing_the_last_binding_removes_the_block_entirely() {
        let existing = "127.0.0.1\tlocalhost\n";
        let with_binding = rewrite_hosts(existing, &bindings_with("test", &[("myapp", 4000)]));
        let emptied = rewrite_hosts(&with_binding, &bindings_with("test", &[]));

        assert!(!emptied.contains(HOSTS_BEGIN));
        assert!(!emptied.contains("myapp.test"));
        assert!(emptied.contains("127.0.0.1\tlocalhost"));
    }

    #[test]
    fn a_changed_binding_list_replaces_rather_than_appends() {
        let existing = "127.0.0.1\tlocalhost\n";
        let first = rewrite_hosts(existing, &bindings_with("test", &[("old", 4000)]));
        let second = rewrite_hosts(&first, &bindings_with("test", &[("new", 4001)]));

        assert!(second.contains("new.test"));
        assert!(!second.contains("old.test"), "stale entry was left behind");
    }

    #[test]
    fn every_hostname_gets_both_address_families() {
        let result = rewrite_hosts("", &bindings_with("test", &[("myapp", 4000)]));
        // A v4-only entry breaks clients that resolve AAAA first.
        assert!(result.contains("127.0.0.1\tmyapp.test"));
        assert!(result.contains("::1\t\tmyapp.test"));
    }
}
