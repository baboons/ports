//! Tiers 2 and 3: find open ports by trying to connect to them.
//!
//! A closed loopback port refuses immediately rather than timing out, which is
//! the only reason sweeping all 65535 of them is affordable at all.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;

/// Errors that mean "the machine ran out of something", not "the port is shut".
///
/// Treating these as closed would silently drop real servers from the results
/// whenever the box is under pressure, which is the worst kind of bug for an
/// inventory tool: a quiet false negative. We retry them instead.
fn is_exhaustion(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EMFILE)        // process fd limit
            | Some(libc::ENFILE)  // system-wide fd limit
            | Some(libc::ENOBUFS) // kernel buffer pressure
            | Some(libc::EADDRNOTAVAIL) // ephemeral port range exhausted
            | Some(libc::EADDRINUSE)
    )
}

enum Outcome {
    Open,
    Closed,
    Exhausted,
}

async fn attempt_connect(port: u16, host: IpAddr, timeout: Duration) -> Outcome {
    match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(_stream)) => Outcome::Open,
        Ok(Err(err)) if is_exhaustion(&err) => Outcome::Exhausted,
        Ok(Err(_)) => Outcome::Closed,
        // A filtered port, which on loopback is rare.
        Err(_elapsed) => Outcome::Closed,
    }
}

/// Is something accepting TCP connections on this port?
pub async fn check_port(port: u16, host: IpAddr, timeout: Duration) -> bool {
    for attempt in 0..3u32 {
        match attempt_connect(port, host, timeout).await {
            Outcome::Open => return true,
            Outcome::Closed => return false,
            Outcome::Exhausted => {
                // Back off to let descriptors and ephemeral ports drain.
                tokio::time::sleep(Duration::from_millis(50 * (attempt as u64 + 1))).await;
            }
        }
    }
    false
}

pub struct SweepOptions {
    pub host: IpAddr,
    /// Max sockets in flight. Loopback tolerates a lot; the fd limit is the ceiling.
    pub concurrency: usize,
    /// Per-connection budget. Loopback answers or refuses almost instantly.
    pub timeout: Duration,
    pub cancel: Arc<AtomicBool>,
}

impl Default for SweepOptions {
    fn default() -> Self {
        Self {
            host: IpAddr::from([127, 0, 0, 1]),
            concurrency: 512,
            timeout: Duration::from_millis(300),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Connect-scan a list of ports with a bounded number of sockets in flight.
///
/// Implemented as N long-lived workers pulling from a shared cursor rather than
/// chunked batches: a batch would stall on its slowest port before starting the
/// next one, which over a 65535-port sweep adds up badly.
pub async fn sweep_ports<F>(ports: Vec<u16>, options: SweepOptions, on_result: F) -> Vec<u16>
where
    F: Fn(u16, bool) + Send + Sync + 'static,
{
    let total = ports.len();
    if total == 0 {
        return Vec::new();
    }

    let ports = Arc::new(ports);
    let cursor = Arc::new(AtomicUsize::new(0));
    let on_result = Arc::new(on_result);
    let open = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let workers = options.concurrency.min(total).max(1);
    let mut handles = Vec::with_capacity(workers);

    for _ in 0..workers {
        let ports = Arc::clone(&ports);
        let cursor = Arc::clone(&cursor);
        let on_result = Arc::clone(&on_result);
        let open = Arc::clone(&open);
        let cancel = Arc::clone(&options.cancel);
        let host = options.host;
        let timeout = options.timeout;

        handles.push(tokio::spawn(async move {
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                let index = cursor.fetch_add(1, Ordering::Relaxed);
                let Some(&port) = ports.get(index) else {
                    return;
                };

                let is_open = check_port(port, host, timeout).await;
                if is_open {
                    open.lock().await.push(port);
                }
                on_result(port, is_open);
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }

    let mut open = Arc::try_unwrap(open)
        .map(|m| m.into_inner())
        .unwrap_or_default();
    open.sort_unstable();
    open
}

/// Every port in 1-65535, minus any we already know about.
pub fn full_range(exclude: &std::collections::HashSet<u16>) -> Vec<u16> {
    (1..=65535u16).filter(|p| !exclude.contains(p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tokio::net::TcpListener;

    #[test]
    fn full_range_covers_everything_not_excluded() {
        let exclude = HashSet::from([1u16, 80, 65535]);
        let range = full_range(&exclude);
        assert_eq!(range.len(), 65535 - 3);
        assert!(!range.contains(&80));
        assert!(range.contains(&81));
    }

    #[tokio::test]
    async fn finds_a_port_that_is_listening_and_not_one_that_is_not() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let host = IpAddr::from([127, 0, 0, 1]);

        assert!(check_port(port, host, Duration::from_millis(300)).await);

        // Dropping the listener closes the socket, so the same port now refuses.
        drop(listener);
        assert!(!check_port(port, host, Duration::from_millis(300)).await);
    }

    #[tokio::test]
    async fn sweep_reports_every_port_it_was_given() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = listener.local_addr().unwrap().port();

        // A std mutex, not a tokio one: the callback is synchronous and runs
        // inside the worker tasks, where an async lock would deadlock.
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);

        let ports = vec![open_port, 1, 2];
        let found = sweep_ports(ports.clone(), SweepOptions::default(), move |port, open| {
            sink.lock().unwrap().push((port, open));
        })
        .await;

        assert_eq!(found, vec![open_port]);
        assert_eq!(seen.lock().unwrap().len(), 3);
    }
}
