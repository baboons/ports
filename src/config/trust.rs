//! Which addresses may change the bindings through the web interface.
//!
//! The default is loopback only. Off the machine, the Origin check that
//! protects a browser is worth nothing — any peer can set a header — so
//! trusting an address is trusting whatever holds it on your network, and the
//! only honest way to widen it is to name the addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A single address or a network in CIDR form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedNet {
    base: IpAddr,
    /// Significant leading bits. A bare address is a full-length prefix.
    prefix: u8,
}

impl TrustedNet {
    /// Parse `10.0.1.50`, `10.0.1.0/24`, `::1` or `fd00::/8`.
    pub fn parse(entry: &str) -> Option<Self> {
        let entry = entry.trim();
        if entry.is_empty() {
            return None;
        }

        let (address, prefix) = match entry.split_once('/') {
            Some((address, prefix)) => (address.trim(), Some(prefix.trim())),
            None => (entry, None),
        };

        let base: IpAddr = address.parse().ok()?;
        let full = if base.is_ipv4() { 32 } else { 128 };

        let prefix = match prefix {
            None => full,
            Some(prefix) => {
                let parsed: u8 = prefix.parse().ok()?;
                // A prefix longer than the address has no meaning, and
                // accepting it would silently match nothing.
                if parsed > full {
                    return None;
                }
                parsed
            }
        };

        Some(Self { base, prefix })
    }

    /// Is this address inside the network?
    pub fn contains(&self, candidate: IpAddr) -> bool {
        match (self.base, candidate) {
            (IpAddr::V4(base), IpAddr::V4(candidate)) => {
                same_prefix(&base.octets(), &candidate.octets(), self.prefix)
            }
            (IpAddr::V6(base), IpAddr::V6(candidate)) => {
                same_prefix(&base.octets(), &candidate.octets(), self.prefix)
            }
            // A v4 client is not inside a v6 network, or the reverse. Mapped
            // addresses are unwrapped before they ever reach here.
            _ => false,
        }
    }
}

/// Do two addresses agree on their first `prefix` bits?
fn same_prefix(left: &[u8], right: &[u8], prefix: u8) -> bool {
    let whole = (prefix / 8) as usize;
    if left[..whole] != right[..whole] {
        return false;
    }

    let remainder = prefix % 8;
    if remainder == 0 {
        return true;
    }
    // The high `remainder` bits of the next byte.
    let mask = 0xffu8 << (8 - remainder);
    (left[whole] & mask) == (right[whole] & mask)
}

/// Normalise a client address before comparing it.
///
/// A v4 client arriving on a dual-stack socket shows up as `::ffff:10.0.1.5`,
/// which would not match a v4 rule written the obvious way.
pub fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// May this address change the bindings?
///
/// Loopback always may — that is the machine itself. Anything else has to be
/// named in the trusted list.
pub fn is_trusted(address: IpAddr, trusted: &[String]) -> bool {
    let address = canonical(address);
    if address.is_loopback() {
        return true;
    }
    trusted
        .iter()
        .filter_map(|entry| TrustedNet::parse(entry))
        .any(|net| net.contains(address))
}

/// Check a list, reporting the first entry that is not an address or network.
pub fn check_entries(entries: &[String]) -> Result<Vec<String>, String> {
    let mut checked = Vec::with_capacity(entries.len());
    for entry in entries {
        for part in entry.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if TrustedNet::parse(part).is_none() {
                return Err(format!(
                    "'{part}' is not an address or network — try 10.0.1.50, \
                     or 10.0.1.0/24"
                ));
            }
            checked.push(part.to_string());
        }
    }
    Ok(checked)
}

/// Networks broad enough that naming them is almost certainly a mistake.
pub fn is_dangerously_broad(entry: &str) -> bool {
    match TrustedNet::parse(entry) {
        Some(net) => match net.base {
            // Anything with almost no fixed bits is "the internet".
            IpAddr::V4(Ipv4Addr::UNSPECIFIED) => net.prefix <= 8,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED) => net.prefix <= 8,
            _ => net.prefix == 0,
        },
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_bare_address_matches_only_itself() {
        let net = TrustedNet::parse("10.0.1.50").unwrap();
        assert!(net.contains(ip("10.0.1.50")));
        assert!(!net.contains(ip("10.0.1.51")));
        assert!(!net.contains(ip("10.0.2.50")));
    }

    #[test]
    fn a_cidr_matches_its_whole_network() {
        let net = TrustedNet::parse("10.0.1.0/24").unwrap();
        assert!(net.contains(ip("10.0.1.1")));
        assert!(net.contains(ip("10.0.1.255")));
        assert!(!net.contains(ip("10.0.2.1")));
    }

    #[test]
    fn a_prefix_that_is_not_a_whole_byte_still_masks_correctly() {
        // /20 splits inside the third octet, which is where a naive
        // byte-at-a-time comparison goes wrong.
        let net = TrustedNet::parse("10.0.16.0/20").unwrap();
        assert!(net.contains(ip("10.0.16.1")));
        assert!(net.contains(ip("10.0.31.254")));
        assert!(!net.contains(ip("10.0.32.1")));
        assert!(!net.contains(ip("10.0.15.1")));
    }

    #[test]
    fn ipv6_networks_work_the_same_way() {
        let net = TrustedNet::parse("fd00::/8").unwrap();
        assert!(net.contains(ip("fd00::1")));
        assert!(net.contains(ip("fdff::abcd")));
        assert!(!net.contains(ip("fe80::1")));

        let single = TrustedNet::parse("fd00::1").unwrap();
        assert!(single.contains(ip("fd00::1")));
        assert!(!single.contains(ip("fd00::2")));
    }

    #[test]
    fn address_families_do_not_match_across() {
        let v4 = TrustedNet::parse("10.0.1.0/24").unwrap();
        assert!(!v4.contains(ip("fd00::1")));

        let v6 = TrustedNet::parse("fd00::/8").unwrap();
        assert!(!v6.contains(ip("10.0.1.1")));
    }

    #[test]
    fn a_v4_client_on_a_dual_stack_socket_matches_a_v4_rule() {
        // Arrives as ::ffff:10.0.1.5, which would otherwise never match.
        assert!(is_trusted(ip("::ffff:10.0.1.5"), &["10.0.1.0/24".into()]));
        assert_eq!(canonical(ip("::ffff:10.0.1.5")), ip("10.0.1.5"));
    }

    #[test]
    fn loopback_is_always_trusted_whatever_the_list_says() {
        assert!(is_trusted(ip("127.0.0.1"), &[]));
        assert!(is_trusted(ip("::1"), &[]));
        // Even a v4-mapped loopback.
        assert!(is_trusted(ip("::ffff:127.0.0.1"), &[]));
    }

    #[test]
    fn nothing_else_is_trusted_by_default() {
        for address in ["10.0.1.5", "192.168.1.2", "8.8.8.8", "fd00::1"] {
            assert!(!is_trusted(ip(address), &[]), "{address}");
        }
    }

    #[test]
    fn an_unparseable_entry_grants_nothing_rather_than_everything() {
        // A typo must fail closed.
        assert!(!is_trusted(ip("10.0.1.5"), &["not-an-address".into()]));
        assert!(!is_trusted(ip("10.0.1.5"), &["10.0.1.0/99".into()]));
    }

    #[test]
    fn rejects_entries_that_are_not_addresses() {
        assert!(check_entries(&["nas.lan".into()]).is_err());
        assert!(check_entries(&["10.0.1.0/33".into()]).is_err());
        assert!(check_entries(&["".into()]).unwrap().is_empty());

        // Comma-separated in one argument is the obvious thing to type.
        assert_eq!(
            check_entries(&["10.0.1.5, 10.0.2.0/24".into()]).unwrap(),
            vec!["10.0.1.5", "10.0.2.0/24"]
        );
    }

    #[test]
    fn recognises_a_rule_that_trusts_everything() {
        assert!(is_dangerously_broad("0.0.0.0/0"));
        assert!(is_dangerously_broad("::/0"));
        assert!(!is_dangerously_broad("10.0.0.0/8"));
        assert!(!is_dangerously_broad("10.0.1.50"));
    }
}
