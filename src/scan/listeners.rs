//! Tier 1: enumerate listening sockets from the kernel.
//!
//! `netstat2` reads them directly (libproc on macOS, /proc on Linux). When that
//! is unavailable we shell out to `lsof` and parse its field-mode output, which
//! is the path this tool used exclusively before and is kept because it is the
//! one that works on the widest range of machines.
//!
//! Either way the coverage limit is the same: unprivileged, you only see your
//! own processes. Root-owned listeners are found by the connect sweep in tiers
//! 2 and 3 instead, just without a pid attached.

use std::collections::HashSet;
use std::process::Command;

use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState,
};

use crate::types::{Family, Listener};

/// lsof emits records in field mode grouped by process: the `p`/`c`/`L` fields
/// appear once, then one `f`/`t`/`n` group per file descriptor. So we carry the
/// process fields forward and emit a listener each time we see an address.
pub fn parse_lsof(output: &str) -> Vec<Listener> {
    let mut listeners = Vec::new();
    let mut seen = HashSet::new();

    let mut pid: Option<u32> = None;
    let mut command: Option<String> = None;
    let mut user: Option<String> = None;
    let mut family: Option<Family> = None;

    for line in output.lines() {
        if line.len() < 2 {
            continue;
        }
        let (tag, value) = line.split_at(1);

        match tag {
            "p" => {
                pid = value.parse().ok();
                // A new process resets the per-descriptor state.
                family = None;
            }
            "c" => command = Some(value.to_string()),
            "L" => user = Some(value.to_string()),
            "t" => {
                family = Some(if value == "IPv6" {
                    Family::Ipv6
                } else {
                    Family::Ipv4
                })
            }
            "n" => {
                let Some((address, port)) = parse_address(value) else {
                    continue;
                };
                // A single process often holds the same address on many
                // descriptors (nginx workers, node cluster). Collapse them.
                if !seen.insert(format!("{address}:{port}")) {
                    continue;
                }
                listeners.push(Listener {
                    port,
                    family: family.unwrap_or(if address.contains(':') {
                        Family::Ipv6
                    } else {
                        Family::Ipv4
                    }),
                    address,
                    pid,
                    command: command.clone(),
                    user: user.clone(),
                });
            }
            _ => {}
        }
    }

    listeners
}

/// Handles the three shapes lsof produces for a listening socket:
///   127.0.0.1:8080   *:52259   [::1]:18789
fn parse_address(raw: &str) -> Option<(String, u16)> {
    // Strip a trailing state annotation if -s didn't already filter it.
    let value = raw.trim().strip_suffix("(LISTEN)").unwrap_or(raw).trim();

    let last_colon = value.rfind(':')?;
    let port: u32 = value[last_colon + 1..].parse().ok()?;
    if port < 1 || port > 65535 {
        return None;
    }

    let mut address = &value[..last_colon];
    if address.starts_with('[') && address.ends_with(']') {
        address = &address[1..address.len() - 1];
    }
    let address = if address.is_empty() || address == "*" {
        "0.0.0.0"
    } else {
        address
    };

    Some((address.to_string(), port as u16))
}

/// Read listening sockets straight from the kernel.
fn enumerate_via_netstat() -> Option<Vec<Listener>> {
    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP,
    )
    .ok()?;

    let mut listeners = Vec::new();
    let mut seen = HashSet::new();

    for socket in sockets {
        let ProtocolSocketInfo::Tcp(tcp) = socket.protocol_socket_info else {
            continue;
        };
        if tcp.state != TcpState::Listen {
            continue;
        }

        let address = tcp.local_addr.to_string();
        if !seen.insert(format!("{address}:{}", tcp.local_port)) {
            continue;
        }

        listeners.push(Listener {
            port: tcp.local_port,
            family: if tcp.local_addr.is_ipv6() {
                Family::Ipv6
            } else {
                Family::Ipv4
            },
            address,
            // A socket can be shared by forked workers; the first pid is the
            // one we can resolve to a command, and they share a command line.
            pid: socket.associated_pids.first().copied(),
            command: None,
            user: None,
        });
    }

    // An empty result is more likely "this platform is unsupported" than
    // "nothing is listening", so let the caller fall back rather than trusting
    // it. Even a bare machine has something bound.
    if listeners.is_empty() {
        None
    } else {
        Some(listeners)
    }
}

/// Shell out to lsof. Never fails loudly — no lsof just means zero listeners
/// from this tier, and the sweep still finds the ports.
fn enumerate_via_lsof() -> Vec<Listener> {
    let output = Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:LISTEN", "-FpcnLt"])
        .output();

    match output {
        // lsof exits non-zero when it has partial results (permission denied on
        // some descriptors) but still prints usable output on stdout.
        Ok(out) => parse_lsof(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => Vec::new(),
    }
}

/// Tier 1: every listening socket we are allowed to see.
pub fn enumerate_listeners() -> Vec<Listener> {
    match enumerate_via_netstat() {
        Some(listeners) => listeners,
        None => enumerate_via_lsof(),
    }
}

/// True when we can see other users' sockets, which widens tier 1 coverage.
pub fn is_privileged() -> bool {
    // Safety: geteuid is always safe to call and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_a_process_holding_one_address_on_many_descriptors() {
        let output = "p553\ncnginx\nLjohan\nf6\ntIPv4\nn127.0.0.1:80\n\
                      p554\ncnginx\nLjohan\nf6\ntIPv4\nn127.0.0.1:80\n\
                      p555\ncnginx\nLjohan\nf6\ntIPv4\nn127.0.0.1:80\n";

        let listeners = parse_lsof(output);
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].port, 80);
        assert_eq!(listeners[0].command.as_deref(), Some("nginx"));
        // First pid wins — they all share the same listening socket.
        assert_eq!(listeners[0].pid, Some(553));
    }

    #[test]
    fn keeps_ipv4_and_ipv6_binds_of_the_same_port_distinct() {
        let output = "p1234\ncnode\nLjohan\nf20\ntIPv4\nn127.0.0.1:18789\n\
                      f21\ntIPv6\nn[::1]:18789\n";

        let listeners = parse_lsof(output);
        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].address, "127.0.0.1");
        assert_eq!(listeners[0].family, Family::Ipv4);
        // The brackets are lsof's, not part of the address.
        assert_eq!(listeners[1].address, "::1");
        assert_eq!(listeners[1].family, Family::Ipv6);
    }

    #[test]
    fn normalises_a_wildcard_bind() {
        let listeners = parse_lsof("p999\ncrapportd\nLjohan\nf5\ntIPv4\nn*:52259\n");
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].address, "0.0.0.0");
        assert_eq!(listeners[0].port, 52259);
    }

    #[test]
    fn ignores_malformed_and_out_of_range_addresses() {
        let output = "p1\ncx\nLj\nf1\ntIPv4\nnnot-an-address\n\
                      f2\ntIPv4\nn127.0.0.1:99999\n\
                      f3\ntIPv4\nn127.0.0.1:0\n";
        assert!(parse_lsof(output).is_empty());
    }

    #[test]
    fn strips_a_trailing_listen_annotation() {
        let listeners = parse_lsof("p1\ncnode\nLj\nf1\ntIPv4\nn127.0.0.1:3000 (LISTEN)\n");
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].port, 3000);
        assert_eq!(listeners[0].address, "127.0.0.1");
    }
}
