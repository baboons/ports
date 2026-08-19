//! `ports doctor` — find out which layer is broken.
//!
//! A local domain not working can fail at five different places, and the
//! browser reports almost all of them as the same blank error. Checking each
//! layer separately turns "it doesn't work" into one specific thing to fix.

use std::time::Duration;

use crate::cli::bind::{is_ports_proxy, is_reachable};
use crate::cli::format::{bold, dim, gray, green, red, yellow};
use crate::config::bindings::{load_bindings_strict, Bindings};
use crate::dns::resolver::{mechanism_for, plan_install, Mechanism};
use crate::proxy::tls;

#[derive(Debug, PartialEq, Eq)]
pub enum Health {
    Ok(String),
    Warn(String),
    Fail(String),
    Skip(String),
}

impl Health {
    fn mark(&self) -> String {
        match self {
            Health::Ok(_) => green("✓"),
            Health::Warn(_) => yellow("!"),
            Health::Fail(_) => red("✗"),
            Health::Skip(_) => gray("–"),
        }
    }

    fn text(&self) -> &str {
        match self {
            Health::Ok(t) | Health::Warn(t) | Health::Fail(t) | Health::Skip(t) => t,
        }
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, Health::Fail(_))
    }
}

/// Does the OS resolve a name under this TLD to loopback?
///
/// Asked through the real resolver rather than our own DNS server, because the
/// question is whether *the machine* resolves it, not whether we would answer.
pub async fn check_resolution(tld: &str) -> Health {
    let probe = format!("ports-doctor-probe.{tld}");
    let lookup = tokio::net::lookup_host(format!("{probe}:80")).await;

    match lookup {
        Ok(addresses) => {
            let addresses: Vec<_> = addresses.collect();
            if addresses.iter().all(|a| a.ip().is_loopback()) && !addresses.is_empty() {
                Health::Ok(format!("*.{tld} resolves to loopback"))
            } else {
                Health::Fail(format!(
                    "*.{tld} resolves to {} — something else owns this domain",
                    addresses
                        .first()
                        .map(|a| a.ip().to_string())
                        .unwrap_or_else(|| "nothing".into())
                ))
            }
        }
        Err(_) => match mechanism_for(tld) {
            Mechanism::None => Health::Fail(format!(
                "*.{tld} does not resolve, which is unexpected — the OS should handle it"
            )),
            _ => {
                let path = plan_install(tld)
                    .map(|i| i.path.display().to_string())
                    .unwrap_or_default();
                Health::Fail(format!(
                    "*.{tld} does not resolve — run `sudo ports domain {tld} --install` to write {path}"
                ))
            }
        },
    }
}

/// Ask our own resolver a question and read the reply code.
async fn ask_resolver(port: u16, name: &str) -> Option<(usize, u16)> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    socket.connect(("127.0.0.1", port)).await.ok()?;

    let mut query = vec![0x42, 0x42, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&[0, 1, 0, 1]);

    socket.send(&query).await.ok()?;

    let mut buffer = [0u8; 1024];
    // Generous: a forwarded query is a round trip to the internet.
    let size = tokio::time::timeout(Duration::from_secs(4), socket.recv(&mut buffer))
        .await
        .ok()?
        .ok()?;
    if size < 12 {
        return None;
    }

    let answers = u16::from_be_bytes([buffer[6], buffer[7]]);
    let rcode = u16::from_be_bytes([buffer[2], buffer[3]]) & 0x000F;
    Some((answers as usize, rcode))
}

/// Is our resolver running, and does it both answer and forward?
pub async fn check_dns_responder(bindings: &Bindings) -> Health {
    let needing = bindings.domains_needing_dns();
    if needing.is_empty() {
        return Health::Skip("every domain resolves without a DNS server".into());
    }

    let port = bindings.dns.port;
    let local = format!("probe.{}", needing[0]);

    let Some((answers, _)) = ask_resolver(port, &local).await else {
        return Health::Fail(format!(
            "nothing answering DNS on 127.0.0.1:{port} — `ports service install`"
        ));
    };
    if answers == 0 {
        return Health::Fail(format!(
            "the resolver on {port} did not answer for *.{}",
            needing[0]
        ));
    }

    // Forwarding is half of what this resolver is for, and it fails
    // separately — a wrong upstream answers our domains perfectly and
    // nothing else.
    match ask_resolver(port, "example.com").await {
        Some((answers, 0)) if answers > 0 => Health::Ok(format!(
            "resolver on {}:{port}, forwarding to {}",
            bindings.host,
            bindings.dns.forward.join(", ")
        )),
        Some((_, rcode)) => Health::Warn(format!(
            "answering for your domains, but forwarding failed (rcode {rcode}) — \
             check `ports dns` upstreams"
        )),
        None => Health::Warn(
            "answering for your domains, but a forwarded query timed out — \
             check `ports dns` upstreams"
                .into(),
        ),
    }
}

/// Is the proxy listening, and is it ours?
pub async fn check_proxy(bindings: &Bindings) -> Health {
    let port = bindings.http_port;

    if !is_reachable(&format!("127.0.0.1:{port}")).await {
        return Health::Fail(format!(
            "nothing listening on port {port} — `ports serve`, or `ports service install`"
        ));
    }
    if !is_ports_proxy(port).await {
        return Health::Fail(format!(
            "port {port} is held by something else — `ports` will show you what"
        ));
    }

    // Naming the interface here is the difference between "it works" and
    // spending an evening wondering why the LAN gets connection refused.
    if bindings.is_exposed() {
        Health::Ok(format!(
            "proxy answering on {}:{port}, reachable from the network",
            bindings.host
        ))
    } else {
        Health::Ok(format!(
            "proxy answering on {}:{port} — this machine only, \
             `ports expose all` to widen it",
            bindings.host
        ))
    }
}

/// Are the upstreams behind the bindings actually up?
pub async fn check_upstreams(bindings: &Bindings) -> Health {
    if bindings.bindings.is_empty() {
        return Health::Skip("nothing bound yet — `ports adopt` in a project".into());
    }

    let mut down = Vec::new();
    for binding in &bindings.bindings {
        if !is_reachable(&binding.target).await {
            down.push(binding.hostname(bindings.primary()));
        }
    }

    let total = bindings.bindings.len();
    if down.is_empty() {
        Health::Ok(format!("all {total} upstream{} up", plural(total)))
    } else {
        // Not a failure: a dev server you have not started yet is the normal
        // state, and the binding is still correct.
        Health::Warn(format!(
            "{} of {total} upstream{} down: {}",
            down.len(),
            plural(total),
            down.join(", ")
        ))
    }
}

/// Have we got a CA to issue certificates from?
pub fn check_ca(bindings: &Bindings) -> Health {
    if bindings.https_port.is_none() {
        return Health::Skip("HTTPS disabled".into());
    }

    match tls::find_ca() {
        Some(ca) if ca.is_mkcert => Health::Ok(format!(
            "issuing from the mkcert root at {}",
            ca.source.display()
        )),
        Some(ca) => Health::Ok(format!(
            "issuing from our own CA at {}",
            ca.source.display()
        )),
        None => Health::Warn(
            "no local CA found — HTTPS will not work until you install mkcert, \
             or run `ports ca install`"
                .into(),
        ),
    }
}

/// Does a bound name reach its upstream through the proxy?
pub async fn check_end_to_end(bindings: &Bindings) -> Health {
    let Some(binding) = bindings.bindings.first() else {
        return Health::Skip("nothing bound to try".into());
    };
    let hostname = binding.hostname(bindings.primary());

    if !is_reachable(&binding.target).await {
        return Health::Skip(format!("{hostname} is not running, so nothing to try"));
    }

    match crate::cli::bind::check_through_proxy(&hostname, bindings.http_port).await {
        Some(warning) => Health::Warn(format!(
            "{hostname} reaches its server, but it is refusing the hostname\n{warning}"
        )),
        None => Health::Ok(format!("{hostname} reaches its server")),
    }
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

pub async fn doctor() -> anyhow::Result<()> {
    let bindings = load_bindings_strict()?;

    println!(
        "\n  {}  ·  {} binding{}",
        bold(&format!("*.{}", bindings.primary())),
        bindings.bindings.len(),
        plural(bindings.bindings.len())
    );
    println!();

    let checks = vec![
        ("resolution", check_resolution(bindings.primary()).await),
        ("dns", check_dns_responder(&bindings).await),
        ("proxy", check_proxy(&bindings).await),
        ("upstreams", check_upstreams(&bindings).await),
        ("certificates", check_ca(&bindings)),
        ("end to end", check_end_to_end(&bindings).await),
    ];

    let width = checks.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    let mut failed = 0;

    for (name, health) in &checks {
        println!(
            "  {} {}  {}",
            health.mark(),
            dim(&format!("{name:<width$}")),
            health.text()
        );
        if health.is_fail() {
            failed += 1;
        }
    }

    println!();
    if failed == 0 {
        println!("{}\n", dim("  nothing broken"));
    } else {
        println!(
            "{}\n",
            yellow(&format!("  {failed} thing{} to fix", plural(failed)))
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn localhost_resolution_passes_with_no_setup() {
        // The whole reason .localhost is the default.
        let health = check_resolution("localhost").await;
        assert!(
            matches!(health, Health::Ok(_)),
            "expected .localhost to resolve, got {health:?}"
        );
    }

    #[tokio::test]
    async fn a_tld_nothing_serves_reports_a_fix_rather_than_just_failing() {
        let health = check_resolution("definitely-not-a-real-tld-xyzzy").await;
        match health {
            Health::Fail(message) => {
                assert!(
                    message.contains("ports domain"),
                    "a failure should say what to run: {message}"
                );
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_dns_check_is_skipped_when_no_domain_needs_one() {
        // Only .localhost configured: nothing to resolve, nothing to check.
        assert!(matches!(
            check_dns_responder(&Bindings::default()).await,
            Health::Skip(_)
        ));
    }

    #[tokio::test]
    async fn a_resolver_that_is_not_running_is_a_failure_naming_the_fix() {
        let bindings = Bindings {
            domains: vec!["nas.lan".into()],
            // Nothing will be listening here.
            dns: crate::config::bindings::DnsConfig {
                port: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        match check_dns_responder(&bindings).await {
            Health::Fail(message) => assert!(message.contains("service install"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_proxy_that_is_not_running_is_a_failure_naming_the_fix() {
        let bindings = Bindings {
            // Nothing will be listening here.
            http_port: 1,
            ..Default::default()
        };
        match check_proxy(&bindings).await {
            Health::Fail(message) => assert!(message.contains("ports serve")),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unstarted_dev_server_is_a_warning_not_a_failure() {
        // A binding you have not started yet is normal, and the binding is
        // still correct — failing here would cry wolf every morning.
        let mut bindings = Bindings::default();
        bindings.upsert("nothing".into(), "127.0.0.1:1".into(), 0);

        let health = check_upstreams(&bindings).await;
        assert!(matches!(health, Health::Warn(_)), "got {health:?}");
        assert!(!health.is_fail());
    }

    #[tokio::test]
    async fn an_empty_binding_table_is_skipped_rather_than_failed() {
        assert!(matches!(
            check_upstreams(&Bindings::default()).await,
            Health::Skip(_)
        ));
    }

    #[test]
    fn the_ca_check_is_skipped_when_https_is_off() {
        let bindings = Bindings {
            https_port: None,
            ..Default::default()
        };
        assert!(matches!(check_ca(&bindings), Health::Skip(_)));
    }
}
