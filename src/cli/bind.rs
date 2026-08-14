//! `ports bind`, `ports unbind`, `ports links`.

use std::net::SocketAddr;
use std::time::Duration;

use crate::cli::format::{bold, dim, gray, green, red, yellow};
use crate::config::bindings::{
    load_bindings_strict, normalise_name, normalise_target, save_bindings, Bindings,
};
use crate::proxy::blocked;
use crate::types::now_ms;

/// Turn a package name into something that works as a subdomain.
///
/// Scopes go first: `@acme/web` is `web` to everyone who works on it, and
/// `acme-web` would be a worse name for the same thing.
pub fn slugify(input: &str) -> Option<String> {
    let without_scope = input.rsplit('/').next().unwrap_or(input);

    let mut slug = String::with_capacity(without_scope.len());
    let mut last_was_dash = false;
    for ch in without_scope.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash && !slug.is_empty() {
            slug.push('-');
            last_was_dash = true;
        }
    }

    let slug = slug.trim_end_matches('-').to_string();
    (!slug.is_empty()).then_some(slug)
}

/// Is anything listening on this target right now?
pub async fn is_reachable(target: &str) -> bool {
    let Ok(addr) = target.parse::<SocketAddr>() else {
        return false;
    };
    tokio::time::timeout(
        Duration::from_millis(400),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

/// Probe a bound hostname through the proxy and report a host-check rejection.
///
/// Returns None when the proxy is not running, which is the common case right
/// after a first `bind` and not worth complaining about.
pub async fn check_through_proxy(hostname: &str, http_port: u16) -> Option<String> {
    let stream = tokio::time::timeout(
        Duration::from_millis(600),
        tokio::net::TcpStream::connect(("127.0.0.1", http_port)),
    )
    .await
    .ok()?
    .ok()?;

    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .ok()?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = hyper::Request::builder()
        .uri("/")
        .header("host", hostname)
        .body(String::new())
        .ok()?;

    let response = tokio::time::timeout(Duration::from_secs(3), sender.send_request(request))
        .await
        .ok()?
        .ok()?;

    let status = response.status().as_u16();
    let body = {
        use http_body_util::BodyExt;
        let collected = response.into_body().collect().await.ok()?;
        String::from_utf8_lossy(&collected.to_bytes()).into_owned()
    };

    let detected = blocked::detect(status, &body)?;
    Some(format!(
        "  {} {} is refusing the new hostname — that is its DNS-rebinding guard, not a proxy fault.\n{}\n{}",
        yellow("!"),
        detected.stack,
        dim(&format!("    add to {}:", detected.file)),
        bold(&format!("      {}", detected.fix)),
    ))
}

/// Is a ports proxy what is listening on this port?
///
/// Asked by probing with a hostname that cannot be bound, so the proxy answers
/// with its own "not bound" page rather than forwarding, and looking for the
/// marker header it stamps on pages it generates.
pub async fn is_ports_proxy(port: u16) -> bool {
    let Ok(Ok(stream)) = tokio::time::timeout(
        Duration::from_millis(400),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    else {
        return false;
    };

    let Ok((mut sender, connection)) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await
    else {
        return false;
    };
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let Ok(request) = hyper::Request::builder()
        .uri("/")
        // A label that `normalise_name` rejects, so it can never be bound.
        .header("host", "ports-self-check--.invalid")
        .body(String::new())
    else {
        return false;
    };

    match tokio::time::timeout(Duration::from_secs(2), sender.send_request(request)).await {
        Ok(Ok(response)) => response.headers().contains_key(crate::proxy::SELF_MARKER),
        _ => false,
    }
}

/// Resolve the subdomain name for a port, from the project running on it.
async fn infer_name(port: u16) -> Option<String> {
    let cache = crate::cache::load_cache();
    let record = cache.records.iter().find(|r| r.port == port)?;
    let project = record.process.as_ref()?.project_name.as_deref()?;
    slugify(project)
}

pub async fn bind(name: Option<String>, target: String) -> anyhow::Result<()> {
    let mut bindings = load_bindings_strict()?;

    let Some(target) = normalise_target(&target) else {
        anyhow::bail!("'{target}' is not a port or host:port");
    };

    // Binding the proxy to itself is an infinite loop, and the resulting hang
    // is a genuinely confusing thing to debug. Check the configured ports and
    // then ask the port itself, since `ports serve --http-port` can put the
    // running proxy somewhere the config does not mention.
    let target_port: u16 = target.rsplit(':').next().unwrap_or("").parse().unwrap_or(0);
    let is_loopback_target = target.starts_with("127.0.0.1:") || target.starts_with("[::1]:");
    if is_loopback_target
        && (bindings.own_ports().contains(&target_port) || is_ports_proxy(target_port).await)
    {
        anyhow::bail!("port {target_port} is the proxy itself — that would loop forever");
    }

    let name = match name {
        Some(name) => name,
        None => match infer_name(target_port).await {
            Some(inferred) => inferred,
            None => anyhow::bail!(
                "could not work out a name for port {target_port} — run `ports` first, \
                 or give one: `ports bind <name> {target_port}`"
            ),
        },
    };

    let Some(name) = normalise_name(&name, &bindings.tld) else {
        anyhow::bail!("'{name}' is not a valid hostname label");
    };

    bindings.upsert(name.clone(), target.clone(), now_ms());
    save_bindings(&bindings)?;

    let hostname = format!("{name}.{}", bindings.tld);
    let url = if bindings.http_port == 80 {
        format!("http://{hostname}/")
    } else {
        format!("http://{hostname}:{}/", bindings.http_port)
    };

    println!("\n  {} → {}", bold(&url), dim(&target));

    if !is_reachable(&target).await {
        println!(
            "{}",
            gray(&format!(
                "  nothing listening on {target} yet — the binding is saved regardless"
            ))
        );
    } else if let Some(warning) = check_through_proxy(&hostname, bindings.http_port).await {
        println!("\n{warning}");
    }

    println!();
    Ok(())
}

pub fn unbind(name: String) -> anyhow::Result<()> {
    let mut bindings = load_bindings_strict()?;
    let Some(name) = normalise_name(&name, &bindings.tld) else {
        anyhow::bail!("'{name}' is not a valid hostname label");
    };

    if !bindings.remove(&name) {
        anyhow::bail!("'{name}.{}' is not bound", bindings.tld);
    }
    save_bindings(&bindings)?;

    println!(
        "\n  unbound {}\n",
        bold(&format!("{name}.{}", bindings.tld))
    );
    Ok(())
}

pub async fn links() -> anyhow::Result<()> {
    let bindings = load_bindings_strict()?;

    if bindings.bindings.is_empty() {
        println!("\n{}", dim("  nothing bound"));
        println!(
            "{}\n",
            gray("  `ports adopt` in a project, or `ports bind myapp 3000`")
        );
        return Ok(());
    }

    // Check every upstream at once; serially this would cost the dead-port
    // timeout for each one in turn.
    let mut checks = Vec::with_capacity(bindings.bindings.len());
    for binding in &bindings.bindings {
        let name = binding.name.clone();
        let target = binding.target.clone();
        checks.push(tokio::spawn(
            async move { (name, is_reachable(&target).await) },
        ));
    }

    let mut health: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    for check in checks {
        if let Ok((name, up)) = check.await {
            health.insert(name, up);
        }
    }

    println!();
    let widest = bindings
        .bindings
        .iter()
        .map(|b| b.hostname(&bindings.tld).len())
        .max()
        .unwrap_or(0);

    for binding in &bindings.bindings {
        let hostname = binding.hostname(&bindings.tld);
        let up = health.get(&binding.name).copied().unwrap_or(false);
        println!(
            "  {}  {}  {}",
            bold(&format!("{hostname:<widest$}")),
            dim(&binding.target),
            if up { green("up") } else { red("down") },
        );
    }

    println!(
        "\n{}\n",
        dim(&format!("  {} bound", bindings.bindings.len()))
    );
    Ok(())
}

/// Print the table the way `ports adopt` previews it.
pub fn describe(bindings: &Bindings) -> String {
    bindings
        .bindings
        .iter()
        .map(|b| format!("{} → {}", b.hostname(&bindings.tld), b.target))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_drops_the_scope_and_normalises_the_rest() {
        assert_eq!(slugify("@acme/web").as_deref(), Some("web"));
        assert_eq!(slugify("acme-web").as_deref(), Some("acme-web"));
        assert_eq!(slugify("Acme Web").as_deref(), Some("acme-web"));
        assert_eq!(slugify("my_app.v2").as_deref(), Some("my-app-v2"));
        assert_eq!(slugify("@scope/").as_deref(), None);
        assert_eq!(slugify("").as_deref(), None);
    }

    #[test]
    fn slugify_output_is_always_a_legal_hostname_label() {
        for input in ["@acme/web", "Weird  Name!!", "trailing---", "123"] {
            if let Some(slug) = slugify(input) {
                assert!(
                    normalise_name(&slug, "localhost").is_some(),
                    "{input:?} produced {slug:?}, which is not a valid label"
                );
            }
        }
    }

    #[tokio::test]
    async fn reachability_reflects_whether_anything_is_listening() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = format!("127.0.0.1:{port}");

        assert!(is_reachable(&target).await);
        drop(listener);
        assert!(!is_reachable(&target).await);
    }
}
