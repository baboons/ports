//! `ports dns` — the resolver's port and where it forwards.

use crate::cli::format::{bold, dim, gray, yellow};
use crate::config::bindings::{
    load_bindings_strict, parse_forwarder, save_bindings, Bindings, DEFAULT_FORWARDERS,
};

/// Validate a list of upstreams, keeping what the user wrote.
///
/// The written form is preserved rather than normalised, so a bare `1.1.1.1`
/// stays readable in a file people edit by hand.
pub fn check_forwarders(entries: &[String]) -> Result<Vec<String>, String> {
    let mut checked = Vec::with_capacity(entries.len());
    for entry in entries {
        for part in entry.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if parse_forwarder(part).is_none() {
                return Err(format!(
                    "'{part}' is not a resolver address — try 1.1.1.1, or 9.9.9.9:53"
                ));
            }
            checked.push(part.to_string());
        }
    }

    if checked.is_empty() {
        return Err("at least one forwarder is needed".into());
    }
    Ok(checked)
}

pub fn dns(port: Option<u16>, forward: Vec<String>, reset: bool) -> anyhow::Result<()> {
    let mut bindings = load_bindings_strict()?;

    if port.is_none() && forward.is_empty() && !reset {
        return show(&bindings);
    }

    if reset {
        bindings.dns.forward = DEFAULT_FORWARDERS.iter().map(|s| s.to_string()).collect();
    }
    if !forward.is_empty() {
        bindings.dns.forward = check_forwarders(&forward).map_err(|err| anyhow::anyhow!(err))?;
    }
    if let Some(port) = port {
        if port == 0 {
            anyhow::bail!("0 is not a port to listen on");
        }
        bindings.dns.port = port;
    }

    save_bindings(&bindings)?;
    show(&bindings)?;
    println!(
        "{}\n",
        dim("  restart the proxy to apply:  sudo systemctl restart ports")
    );
    Ok(())
}

fn show(bindings: &Bindings) -> anyhow::Result<()> {
    println!(
        "\n  listening on {}",
        bold(&format!("{}:{}", bindings.host, bindings.dns.port))
    );
    println!("  forwarding to {}", bold(&bindings.dns.forward.join(", ")));

    println!("\n  answered here:");
    for domain in &bindings.domains {
        println!("    {}", dim(&format!("*.{domain}")));
    }

    if bindings.dns.port == 53 {
        if bindings.is_exposed() {
            println!(
                "\n{}",
                gray("  other machines can use this as their DNS server")
            );
            println!(
                "{}",
                gray(
                    "  arbitrary names are resolved only for private clients, so this \
                      cannot become an open resolver"
                )
            );
        } else {
            println!(
                "\n{}",
                yellow("  on port 53 but loopback only — `ports expose all` to serve the network")
            );
        }
    } else {
        println!(
            "\n{}",
            gray(
                "  a high port answers only what /etc/resolver sends here; \
                  `ports dns --port 53` to serve other machines"
            )
        );
    }
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_forms_a_resolver_is_written_in() {
        let checked = check_forwarders(&["1.1.1.1".into(), "9.9.9.9:53".into()]).unwrap();
        assert_eq!(checked, vec!["1.1.1.1", "9.9.9.9:53"]);

        // A comma-separated list in one argument is the obvious thing to type.
        assert_eq!(
            check_forwarders(&["1.1.1.1, 1.0.0.1".into()]).unwrap(),
            vec!["1.1.1.1", "1.0.0.1"]
        );
    }

    #[test]
    fn refuses_what_cannot_be_a_resolver() {
        assert!(check_forwarders(&["not-an-address".into()]).is_err());
        // A hostname would need resolving to be resolved through, which is
        // a chicken and egg.
        assert!(check_forwarders(&["dns.google".into()]).is_err());
        assert!(check_forwarders(&[]).is_err());
        assert!(check_forwarders(&["".into()]).is_err());
    }

    #[test]
    fn the_written_form_is_kept_rather_than_normalised() {
        // The file is hand-edited, so `1.1.1.1` should stay `1.1.1.1`.
        assert_eq!(
            check_forwarders(&["1.1.1.1".into()]).unwrap(),
            vec!["1.1.1.1"]
        );
    }
}
