//! When to re-probe a port, and how to fold a new observation into what we
//! already knew.
//!
//! The whole point is that a repeat run should be cheap: a port whose
//! description has not changed in a while backs off exponentially, and the
//! expensive full sweep is trusted for five minutes.

use std::collections::{HashMap, HashSet};

use sha1::{Digest, Sha1};

use crate::types::{PortRecord, Protocol};

/// How long a completed tier-3 sweep is trusted before another is due.
pub const FULL_SWEEP_TTL: u64 = 5 * 60_000;

/// Floor for a live HTTP port: re-probe at most this often.
const LIVE_MIN_TTL: u64 = 2_000;
/// Ceiling for a port that has looked identical for several passes.
const LIVE_MAX_TTL: u64 = 60_000;
/// Non-HTTP listeners rarely change what they are.
const TCP_TTL: u64 = 120_000;
/// A port known to be down is worth checking, but not often.
const DEAD_TTL: u64 = 300_000;

/// Hash of the fields that describe what a port is serving.
///
/// Deliberately excludes timestamps and timings: those change on every pass,
/// and a fingerprint that changed every pass would never let the backoff grow.
pub fn fingerprint_of(record: &PortRecord) -> String {
    let parts = [
        record.protocol.as_str().to_string(),
        if record.alive { "1" } else { "0" }.to_string(),
        record
            .http
            .as_ref()
            .map(|h| h.status.to_string())
            .unwrap_or_default(),
        record
            .http
            .as_ref()
            .and_then(|h| h.server.clone())
            .unwrap_or_default(),
        record
            .http
            .as_ref()
            .and_then(|h| h.redirect_to.clone())
            .unwrap_or_default(),
        record
            .meta
            .as_ref()
            .and_then(|m| m.title.clone())
            .unwrap_or_default(),
        record
            .process
            .as_ref()
            .map(|p| p.pid.to_string())
            .unwrap_or_default(),
    ];

    let mut hasher = Sha1::new();
    hasher.update(parts.join(" ").as_bytes());
    let digest = hasher.finalize();

    // Sixteen hex chars is plenty to tell two descriptions apart, and keeps the
    // cache file readable.
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// How long this record's description stays trustworthy.
pub fn probe_ttl(record: &PortRecord) -> u64 {
    if !record.alive {
        return DEAD_TTL;
    }
    if record.protocol == Protocol::Tcp {
        return TCP_TTL;
    }
    // Exponential backoff, capped. A dev server that has looked the same for
    // five passes is not worth re-probing every two seconds.
    let exponent = record.consecutive_stable.min(10);
    LIVE_MIN_TTL
        .saturating_mul(1u64 << exponent)
        .min(LIVE_MAX_TTL)
}

/// Is this record's description stale enough to re-probe?
pub fn needs_probe(record: &PortRecord, now: u64) -> bool {
    if record.last_probed == 0 {
        return true;
    }
    if record.protocol == Protocol::Unknown {
        return true;
    }
    now.saturating_sub(record.last_probed) >= probe_ttl(record)
}

/// Has the full 1-65535 sweep gone stale?
pub fn is_sweep_due(last_full_sweep: u64, now: u64) -> bool {
    if last_full_sweep == 0 {
        return true;
    }
    now.saturating_sub(last_full_sweep) >= FULL_SWEEP_TTL
}

/// Fold a fresh observation into what we already knew about a port.
///
/// Enrichment is sticky: a pass that only re-probed HTTP must not erase the
/// process detail a different step gathered. The stability counter compares
/// the newly merged fingerprint against the previous one, which is what makes
/// the backoff in `probe_ttl` grow.
pub fn merge_record(prev: Option<&PortRecord>, next: PortRecord, now: u64) -> PortRecord {
    let Some(prev) = prev else {
        let mut fresh = next;
        fresh.consecutive_stable = 0;
        fresh.stale = false;
        fresh.fingerprint = Some(fingerprint_of(&fresh));
        return fresh;
    };

    let mut merged = next;

    merged.first_seen = {
        let a = if prev.first_seen == 0 {
            now
        } else {
            prev.first_seen
        };
        let b = if merged.first_seen == 0 {
            now
        } else {
            merged.first_seen
        };
        a.min(b)
    };

    // Union, previous order first, so a long-lived record keeps a stable
    // address ordering across passes.
    let mut addresses = prev.addresses.clone();
    for address in &merged.addresses {
        if !addresses.contains(address) {
            addresses.push(address.clone());
        }
    }
    merged.addresses = addresses;

    if merged.http.is_none() {
        merged.http = prev.http.clone();
    }
    if merged.meta.is_none() {
        merged.meta = prev.meta.clone();
    }
    if merged.tls.is_none() {
        merged.tls = prev.tls.clone();
    }
    if merged.process.is_none() {
        merged.process = prev.process.clone();
    }

    merged.stale = false;

    let fingerprint = fingerprint_of(&merged);
    merged.consecutive_stable = if prev.fingerprint.as_deref() == Some(fingerprint.as_str()) {
        prev.consecutive_stable + 1
    } else {
        0
    };
    merged.fingerprint = Some(fingerprint);

    merged
}

/// Retire ports we looked for and did not find.
///
/// Only ports actually searched this pass are eligible: skipping the sweep must
/// make the answer cheaper, never smaller. Records are mutated in place and the
/// changed ones returned, so callers can stream just the difference.
pub fn mark_missing(
    known: &mut HashMap<u16, PortRecord>,
    seen_ports: &HashSet<u16>,
    searched_ports: &HashSet<u16>,
    now: u64,
) -> Vec<PortRecord> {
    let mut changed = Vec::new();

    for (port, record) in known.iter_mut() {
        if seen_ports.contains(port) || !searched_ports.contains(port) || !record.alive {
            continue;
        }
        record.alive = false;
        record.last_probed = now;
        record.consecutive_stable = 0;
        record.fingerprint = Some(fingerprint_of(record));
        changed.push(record.clone());
    }

    changed.sort_by_key(|r| r.port);
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DiscoveryTier, HttpInfo, PageMeta, ProcessInfo};

    fn record() -> PortRecord {
        let mut r = PortRecord::new(3000, DiscoveryTier::Lsof, "127.0.0.1", 1000);
        r.addresses = vec!["127.0.0.1".into()];
        r.protocol = Protocol::Http;
        r.last_seen = 1000;
        r.last_probed = 1000;
        r
    }

    fn with_status(status: u16, title: &str) -> PortRecord {
        let mut r = record();
        r.http = Some(HttpInfo {
            status,
            ..Default::default()
        });
        r.meta = Some(PageMeta {
            title: Some(title.into()),
            ..Default::default()
        });
        r
    }

    #[test]
    fn fingerprint_ignores_timestamps_but_reacts_to_what_is_served() {
        let a = with_status(200, "Acme");
        let mut b = with_status(200, "Acme");
        b.last_seen = 99_999;
        b.last_probed = 99_999;
        b.probe_ms = Some(412);

        assert_eq!(fingerprint_of(&a), fingerprint_of(&b));
        assert_ne!(
            fingerprint_of(&a),
            fingerprint_of(&with_status(500, "Acme"))
        );
    }

    #[test]
    fn probe_ttl_backs_off_and_is_capped() {
        let mut stable_4 = record();
        stable_4.consecutive_stable = 4;
        let mut stable_0 = record();
        stable_0.consecutive_stable = 0;
        assert!(probe_ttl(&stable_4) > probe_ttl(&stable_0));

        let mut stable_500 = record();
        stable_500.consecutive_stable = 500;
        let mut stable_50 = record();
        stable_50.consecutive_stable = 50;
        assert!(probe_ttl(&stable_500) <= LIVE_MAX_TTL);
        assert_eq!(probe_ttl(&stable_500), probe_ttl(&stable_50));
    }

    #[test]
    fn non_http_and_dead_ports_get_long_ttls() {
        let mut tcp = record();
        tcp.protocol = Protocol::Tcp;
        assert!(probe_ttl(&tcp) >= TCP_TTL);

        let mut dead = record();
        dead.alive = false;
        assert!(probe_ttl(&dead) >= DEAD_TTL);
    }

    #[test]
    fn needs_probe_always_fires_for_never_probed_or_unclassified_ports() {
        let mut never = record();
        never.last_probed = 0;
        assert!(needs_probe(&never, 1000));

        let mut unknown = record();
        unknown.protocol = Protocol::Unknown;
        assert!(needs_probe(&unknown, 1000));

        assert!(!needs_probe(&record(), 1500));
        assert!(needs_probe(&record(), 100_000));
    }

    #[test]
    fn sweep_ttl_gates_the_expensive_tier() {
        let t = 1_700_000_000_000u64;
        assert!(is_sweep_due(0, t));
        assert!(!is_sweep_due(t, t + FULL_SWEEP_TTL - 1));
        assert!(is_sweep_due(t, t + FULL_SWEEP_TTL));
    }

    #[test]
    fn merge_preserves_first_seen_history_and_unions_addresses() {
        let mut prev = record();
        prev.first_seen = 500;
        prev.addresses = vec!["127.0.0.1".into()];

        let mut next = record();
        next.first_seen = 9000;
        next.addresses = vec!["::1".into()];

        let merged = merge_record(Some(&prev), next, 9000);
        assert_eq!(merged.first_seen, 500);
        let mut addresses = merged.addresses.clone();
        addresses.sort();
        assert_eq!(addresses, vec!["127.0.0.1".to_string(), "::1".to_string()]);
    }

    #[test]
    fn merge_counts_consecutive_identical_observations() {
        let first = merge_record(None, with_status(200, "Acme"), 1000);
        assert_eq!(first.consecutive_stable, 0);

        let second = merge_record(Some(&first), with_status(200, "Acme"), 2000);
        assert_eq!(second.consecutive_stable, 1);

        let third = merge_record(Some(&second), with_status(200, "Acme"), 3000);
        assert_eq!(third.consecutive_stable, 2);

        let changed = merge_record(Some(&third), with_status(503, "Acme"), 4000);
        assert_eq!(changed.consecutive_stable, 0);
    }

    #[test]
    fn merge_keeps_process_detail_a_probe_only_pass_did_not_collect() {
        let mut prev = record();
        prev.process = Some(ProcessInfo {
            pid: 42,
            project_name: Some("acme".into()),
            ..Default::default()
        });

        let mut next = record();
        next.process = None;

        let merged = merge_record(Some(&prev), next, 2000);
        assert_eq!(
            merged.process.and_then(|p| p.project_name),
            Some("acme".to_string())
        );
    }

    #[test]
    fn mark_missing_retires_only_ports_that_were_actually_searched() {
        let mut known = HashMap::new();
        known.insert(3000, record());
        let mut other = record();
        other.port = 8021;
        other.id = "8021".into();
        known.insert(8021, other);

        let changed = mark_missing(&mut known, &HashSet::new(), &HashSet::from([3000]), 5000);

        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].port, 3000);
        // The caller's collection is updated, not just the returned copies.
        assert!(!known[&3000].alive);
        assert!(known[&8021].alive);
    }

    #[test]
    fn mark_missing_leaves_ports_that_were_seen_alone() {
        let mut known = HashMap::new();
        known.insert(3000, record());

        let changed = mark_missing(
            &mut known,
            &HashSet::from([3000]),
            &HashSet::from([3000]),
            5000,
        );

        assert!(changed.is_empty());
        assert!(known[&3000].alive);
    }
}
