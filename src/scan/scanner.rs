//! Run the discovery tiers in order of how fast they produce answers.
//!
//! Each port found is queued for probing the moment it is known, rather than
//! after discovery finishes. That is what makes the common case feel instant:
//! the dev servers you care about are fully described while the full sweep is
//! still grinding through the empty ranges.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::scan::common_ports::common_ports;
use crate::scan::listeners::enumerate_listeners;
use crate::scan::probe::probe_port;
use crate::scan::process::enrich_processes;
use crate::scan::scheduler::{mark_missing, merge_record, needs_probe};
use crate::scan::sweep::{full_range, sweep_ports, SweepOptions};
use crate::types::{
    now_ms, probe_address_for, DiscoveryTier, PortRecord, ProcessInfo, ScanPhase, ScanProgress,
};

/// Parallel HTTP probes. Loopback probes are latency-bound, not CPU-bound, so
/// this can be generous without starving anything.
const PROBE_CONCURRENCY: usize = 24;

pub struct ScanOptions {
    /// Run tier 3, the full 1-65535 sweep.
    pub deep: bool,
    /// Ignore cached TTLs and re-probe everything found.
    pub force: bool,
    /// What we already knew, from the cache.
    pub prior: Vec<PortRecord>,
    /// Port this process is serving on, so we can flag it rather than hide it.
    pub self_port: Option<u16>,
    pub cancel: Arc<AtomicBool>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            deep: true,
            force: false,
            prior: Vec::new(),
            self_port: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub struct ScanResult {
    /// Everything observed this pass, plus ports confirmed to have gone away.
    pub records: Vec<PortRecord>,
    /// Whether tier 3 ran to completion, which decides if the sweep TTL resets.
    pub swept_fully: bool,
}

pub async fn scan<P>(options: ScanOptions, mut on_progress: P) -> ScanResult
where
    P: FnMut(ScanProgress),
{
    let loopback = IpAddr::from([127, 0, 0, 1]);
    let now = now_ms();

    // Everything we knew coming in, used both to skip probes that are still
    // fresh and to preserve first-seen history through the merge.
    let prior: HashMap<u16, PortRecord> = options.prior.into_iter().map(|r| (r.port, r)).collect();

    let mut records: HashMap<u16, PortRecord> = HashMap::new();
    // Ports we actually looked for, so we only mark those absent as dead.
    let mut searched: HashSet<u16> = HashSet::new();

    let mut report = |phase: ScanPhase, scanned: usize, total: usize, found: usize| {
        on_progress(ScanProgress {
            phase,
            scanned,
            total,
            found,
            done: phase == ScanPhase::Done,
        });
    };

    // --- Tier 1: the process table. Fast, and the only source of pids. ---
    report(ScanPhase::Lsof, 0, 0, 0);

    for listener in enumerate_listeners() {
        let record = records.entry(listener.port).or_insert_with(|| {
            match prior.get(&listener.port) {
                // Carry the cached description forward so this port is already
                // described if its TTL says it needs no re-probing.
                Some(cached) => PortRecord {
                    tier: DiscoveryTier::Lsof,
                    alive: true,
                    stale: true,
                    last_seen: now,
                    ..cached.clone()
                },
                None => PortRecord::new(listener.port, DiscoveryTier::Lsof, &listener.address, now),
            }
        });

        if !record.addresses.contains(&listener.address) {
            record.addresses.push(listener.address.clone());
        }
        record.probed_address = probe_address_for(&listener.address);
        record.last_seen = now;
        record.is_self = options.self_port == Some(listener.port);

        if let Some(pid) = listener.pid {
            if record.process.is_none() {
                record.process = Some(ProcessInfo {
                    pid,
                    name: listener.command.clone(),
                    user: listener.user.clone(),
                    ..Default::default()
                });
            }
        }
    }
    report(ScanPhase::Lsof, 0, 0, records.len());

    // --- Tier 2: the common dev-port list, for anything tier 1 could not see. ---
    let known: HashSet<u16> = records.keys().copied().collect();
    let tier2: Vec<u16> = common_ports()
        .into_iter()
        .filter(|p| !known.contains(p))
        .collect();

    let found_tier2 = sweep_tier(
        tier2,
        loopback,
        256,
        Arc::clone(&options.cancel),
        ScanPhase::Common,
        &mut report,
        records.len(),
        &mut searched,
    )
    .await;

    for port in found_tier2 {
        records.entry(port).or_insert_with(|| {
            adopt_cached(&prior, port, DiscoveryTier::Common, now, options.self_port)
        });
    }

    // --- Tier 3: everything else. Slowest, so it runs last. ---
    let mut swept_fully = false;
    if options.deep && !options.cancel.load(Ordering::Relaxed) {
        let known: HashSet<u16> = records.keys().copied().collect();
        let tier3 = full_range(&known);

        let found_tier3 = sweep_tier(
            tier3,
            loopback,
            512,
            Arc::clone(&options.cancel),
            ScanPhase::Sweep,
            &mut report,
            records.len(),
            &mut searched,
        )
        .await;

        for port in found_tier3 {
            records.entry(port).or_insert_with(|| {
                adopt_cached(&prior, port, DiscoveryTier::Sweep, now, options.self_port)
            });
        }
        swept_fully = !options.cancel.load(Ordering::Relaxed);
    }

    // --- Probe everything whose description is stale. ---
    report(ScanPhase::Probing, 0, 0, records.len());

    let to_probe: Vec<u16> = records
        .values()
        .filter(|record| options.force || needs_probe(record, now))
        .map(|record| record.port)
        .collect();

    // Ports still inside their TTL keep the description they arrived with;
    // they are simply no longer flagged as unverified.
    for record in records.values_mut() {
        if !to_probe.contains(&record.port) {
            record.stale = false;
        }
    }

    let probed = probe_all(&records, &to_probe, Arc::clone(&options.cancel)).await;

    for (port, result) in probed {
        let Some(existing) = records.get(&port) else {
            continue;
        };
        let mut next = existing.clone();
        next.protocol = result.protocol;
        next.last_probed = now_ms();
        next.probe_ms = Some(result.probe_ms);
        next.stale = false;

        let mut merged = merge_record(prior.get(&port), next, now);

        // `merge_record` keeps previous values where the new pass saw nothing,
        // which is right for process data gathered by a different step. Probe
        // output is different: it is a complete observation, so a server that
        // stopped serving HTML must lose last run's title rather than keep
        // advertising it. Assign these unconditionally, None included.
        merged.http = result.http;
        merged.meta = result.meta;
        merged.tls = result.tls;
        merged.error = result.error;

        records.insert(port, merged);
    }

    // --- Process enrichment, batched across every pid at once. ---
    let pids: Vec<u32> = records
        .values()
        .filter_map(|r| r.process.as_ref().map(|p| p.pid))
        .collect();

    if !pids.is_empty() && !options.cancel.load(Ordering::Relaxed) {
        let enriched = enrich_processes(&pids);
        for record in records.values_mut() {
            let Some(pid) = record.process.as_ref().map(|p| p.pid) else {
                continue;
            };
            let Some(info) = enriched.get(&pid) else {
                continue;
            };
            // Keep the short command name from tier 1 if the fuller lookup
            // came back without one.
            let fallback_name = record.process.as_ref().and_then(|p| p.name.clone());
            let mut info = info.clone();
            if info.name.is_none() {
                info.name = fallback_name;
            }
            record.process = Some(info);
        }
    }

    // --- Retire ports we looked for and did not find. ---
    let mut carried: HashMap<u16, PortRecord> = prior
        .iter()
        .filter(|(port, _)| !records.contains_key(port))
        .map(|(port, record)| (*port, record.clone()))
        .collect();
    let seen: HashSet<u16> = records.keys().copied().collect();
    let dead = mark_missing(&mut carried, &seen, &searched, now_ms());

    report(ScanPhase::Done, 0, 0, records.len());

    let mut all: Vec<PortRecord> = records.into_values().chain(dead).collect();
    all.sort_by_key(|r| r.port);

    ScanResult {
        records: all,
        swept_fully,
    }
}

/// Create a record for a newly-swept port, reusing any cached description.
fn adopt_cached(
    prior: &HashMap<u16, PortRecord>,
    port: u16,
    tier: DiscoveryTier,
    now: u64,
    self_port: Option<u16>,
) -> PortRecord {
    let mut record = match prior.get(&port) {
        Some(cached) => PortRecord {
            tier,
            alive: true,
            stale: true,
            last_seen: now,
            ..cached.clone()
        },
        None => PortRecord::new(port, tier, "127.0.0.1", now),
    };
    if record.addresses.is_empty() {
        record.addresses.push("127.0.0.1".into());
    }
    record.is_self = self_port == Some(port);
    record
}

/// Run one connect-scan tier, reporting progress as it goes.
#[allow(clippy::too_many_arguments)]
async fn sweep_tier<P>(
    ports: Vec<u16>,
    host: IpAddr,
    concurrency: usize,
    cancel: Arc<AtomicBool>,
    phase: ScanPhase,
    report: &mut P,
    found_so_far: usize,
    searched: &mut HashSet<u16>,
) -> Vec<u16>
where
    P: FnMut(ScanPhase, usize, usize, usize),
{
    let total = ports.len();
    if total == 0 {
        return Vec::new();
    }

    report(phase, 0, total, found_so_far);

    // Every port here is genuinely tested, so a closed one is evidence that it
    // is closed — which is what lets `mark_missing` retire it.
    let tested = Arc::new(Mutex::new(Vec::with_capacity(total)));
    let sink = Arc::clone(&tested);

    let progress = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&progress);

    let open = sweep_ports(
        ports,
        SweepOptions {
            host,
            concurrency,
            cancel,
            ..Default::default()
        },
        move |port, _open| {
            sink.lock().unwrap().push(port);
            counter.fetch_add(1, Ordering::Relaxed);
        },
    )
    .await;

    for port in tested.lock().unwrap().iter() {
        searched.insert(*port);
    }
    report(phase, total, total, found_so_far + open.len());

    open
}

/// Probe a batch of ports with a bounded number in flight.
async fn probe_all(
    records: &HashMap<u16, PortRecord>,
    ports: &[u16],
    cancel: Arc<AtomicBool>,
) -> Vec<(u16, crate::scan::probe::ProbeResult)> {
    let mut results = Vec::with_capacity(ports.len());

    for chunk in ports.chunks(PROBE_CONCURRENCY) {
        if cancel.load(Ordering::Relaxed) {
            break;
        }

        let mut handles = Vec::with_capacity(chunk.len());
        for port in chunk {
            let Some(record) = records.get(port) else {
                continue;
            };
            let address: IpAddr = record
                .probed_address
                .parse()
                .unwrap_or(IpAddr::from([127, 0, 0, 1]));
            let port = *port;
            handles.push(tokio::spawn(async move {
                (port, probe_port(port, address).await)
            }));
        }

        for handle in handles {
            if let Ok(result) = handle.await {
                results.push(result);
            }
        }
    }

    results
}

/// A scan that only revisits what we already know about, skipping discovery.
///
/// Used by the proxy daemon, which needs upstream liveness far more often than
/// it needs to find new ports.
pub async fn refresh_known(known: Vec<PortRecord>) -> Vec<PortRecord> {
    let cancel = Arc::new(AtomicBool::new(false));
    let records: HashMap<u16, PortRecord> = known.into_iter().map(|r| (r.port, r)).collect();
    let ports: Vec<u16> = records.keys().copied().collect();

    let probed = probe_all(&records, &ports, cancel).await;
    let now = now_ms();

    let mut out: Vec<PortRecord> = Vec::with_capacity(records.len());
    let mut probed_map: HashMap<u16, crate::scan::probe::ProbeResult> =
        probed.into_iter().collect();

    for (port, record) in records {
        let Some(result) = probed_map.remove(&port) else {
            out.push(record);
            continue;
        };
        let mut next = record.clone();
        next.protocol = result.protocol;
        next.last_probed = now;
        next.probe_ms = Some(result.probe_ms);
        next.stale = false;
        next.http = result.http;
        next.meta = result.meta;
        next.tls = result.tls;
        next.error = result.error;
        out.push(merge_record(Some(&record), next, now));
    }

    out.sort_by_key(|r| r.port);
    out
}

/// Ports that answered HTTP or HTTPS, in port order.
pub fn web_servers(records: &[PortRecord]) -> Vec<&PortRecord> {
    records
        .iter()
        .filter(|r| r.alive && r.protocol.is_web())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Protocol;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn finds_and_describes_a_server_it_was_not_told_about() {
        let body = "<html><head><title>Fixture</title></head></html>";
        let payload: &'static str = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n{body}",
                body.len()
            )
            .into_boxed_str(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut scratch = [0u8; 1024];
                    let _ = socket.read(&mut scratch).await;
                    let _ = socket.write_all(payload.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        // Skip the full sweep: this asserts the pipeline works, and tier 1
        // already sees a socket owned by this very process.
        let result = scan(
            ScanOptions {
                deep: false,
                ..Default::default()
            },
            |_| {},
        )
        .await;

        let found = result
            .records
            .iter()
            .find(|r| r.port == port)
            .expect("the fixture server should be discovered");

        assert!(found.alive);
        assert_eq!(found.protocol, Protocol::Http);
        assert_eq!(
            found.meta.as_ref().and_then(|m| m.title.as_deref()),
            Some("Fixture")
        );
        // Tier 1 saw the socket, so it should carry our own pid.
        assert_eq!(
            found.process.as_ref().map(|p| p.pid),
            Some(std::process::id())
        );
    }

    #[tokio::test]
    async fn reports_progress_through_the_tiers() {
        let phases = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&phases);

        scan(
            ScanOptions {
                deep: false,
                ..Default::default()
            },
            move |progress| sink.lock().unwrap().push(progress.phase),
        )
        .await;

        let phases = phases.lock().unwrap();
        assert!(phases.contains(&ScanPhase::Lsof));
        assert!(phases.contains(&ScanPhase::Probing));
        assert_eq!(phases.last(), Some(&ScanPhase::Done));
    }
}
