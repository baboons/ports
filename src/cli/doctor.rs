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

/// Is our DNS responder running, when this TLD needs one?
pub async fn check_dns_responder(tld: &str) -> Health {
    if mechanism_for(tld) == Mechanism::None {
        return Health::Skip(format!("*.{tld} needs no DNS server"));
    }

    let socket = match tokio::net::UdpSocket::bind("127.0.0.1:0").await {
        Ok(socket) => socket,
        Err(err) => return Health::Fail(format!("could not open a socket: {err}")),
    };
    if socket
        .connect(("127.0.0.1", crate::dns::DNS_PORT))
        .await
        .is_err()
    {
        return Health::Fail("DNS responder is not running — `ports service install`".into());
    }

    // A real query: a bound socket proves nothing for UDP.
    let mut query = vec![0x42, 0x42, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in format!("probe.{tld}").split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);

    if socket.send(&query).await.is_err() {
        return Health::Fail("DNS responder is not answering".into());
    }

    let mut buffer = [0u8; 512];
    match tokio::time::timeout(Duration::from_millis(700), socket.recv(&mut buffer)).await {
        Ok(Ok(size)) if size > 12 => Health::Ok(format!(
            "DNS responder answering on 127.0.0.1:{}",
            crate::dns::DNS_PORT
        )),
        _ => Health::Fail(format!(
            "nothing answering DNS on 127.0.0.1:{} — `ports service install`",
            crate::dns::DNS_PORT
        )),
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
    Health::Ok(format!("proxy answering on port {port}"))
}

/// Are the upstreams behind the bindings actually up?
pub async fn check_upstreams(bindings: &Bindings) -> Health {
    if bindings.bindings.is_empty() {
        return Health::Skip("nothing bound yet — `ports adopt` in a project".into());
    }

    let mut down = Vec::new();
    for binding in &bindings.bindings {
        if !is_reachable(&binding.target).await {
            down.push(binding.hostname(&bindings.tld));
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
        Some(ca) => Health::Ok(format!("issuing from our own CA at {}", ca.source.display())),
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
    let hostname = binding.hostname(&bindings.tld);

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
        bold(&format!("*.{}", bindings.tld)),
        bindings.bindings.len(),
        plural(bindings.bindings.len())
    );
    println!();

    let checks = vec![
        ("resolution", check_resolution(&bindings.tld).await),
        ("dns", check_dns_responder(&bindings.tld).await),
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
    async fn the_dns_check_is_skipped_for_localhost() {
        assert!(matches!(
            check_dns_responder("localhost").await,
            Health::Skip(_)
        ));
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
