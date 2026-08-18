//! `ports expose` — which interface the proxy listens on.
//!
//! A named command rather than a JSON field to hand-edit, because it is the
//! setting that decides whether the rest of the network can see this machine's
//! services, and that deserves to be said out loud.

use std::net::IpAddr;

use crate::cli::format::{bold, dim, gray, green, yellow};
use crate::config::bindings::{load_bindings_strict, save_bindings, DEFAULT_HOST};

/// Resolve what the user typed into an address to bind.
pub fn parse_address(input: &str) -> Result<String, String> {
    let input = input.trim();
    let resolved = match input.to_lowercase().as_str() {
        // Words for the two cases anyone actually wants.
        "local" | "localhost" | "loopback" | "off" => DEFAULT_HOST,
        "all" | "any" | "lan" | "network" | "on" => "0.0.0.0",
        _ => input,
    };

    resolved
        .parse::<IpAddr>()
        .map(|address| address.to_string())
        .map_err(|_| {
            format!(
                "'{input}' is not an address to listen on — try `local`, `all`, \
                 or an address of this machine"
            )
        })
}

pub fn expose(address: Option<String>) -> anyhow::Result<()> {
    let mut bindings = load_bindings_strict()?;

    let Some(address) = address else {
        return show(&bindings);
    };

    let address = parse_address(&address).map_err(|err| anyhow::anyhow!(err))?;
    if address == bindings.host {
        println!("\n  already listening on {}\n", bold(&address));
        return Ok(());
    }

    let was_exposed = bindings.is_exposed();
    bindings.host = address.clone();
    save_bindings(&bindings)?;

    println!("\n  listening on {}", bold(&address));

    if bindings.is_exposed() {
        // Worth stating plainly: the index is an inventory of everything
        // running here, and this is what publishes it.
        println!(
            "{}",
            yellow("  reachable from the network — the index lists every service on this machine")
        );
        println!(
            "{}",
            gray("  bind and unbind stay refused from off this machine")
        );
    } else if was_exposed {
        println!("{}", green("  no longer reachable from the network"));
    }

    println!(
        "\n{}\n",
        dim("  restart the proxy to apply:  sudo systemctl restart ports")
    );
    Ok(())
}

fn show(bindings: &crate::config::bindings::Bindings) -> anyhow::Result<()> {
    println!("\n  {}", bold(&bindings.host));
    if bindings.is_exposed() {
        println!("{}", gray("  reachable from the network"));
        println!(
            "{}\n",
            dim("  `ports expose local` to restrict it to this machine")
        );
    } else {
        println!("{}", gray("  this machine only"));
        println!(
            "{}\n",
            dim("  `ports expose all` to reach it from the network")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_words_for_the_two_cases_anyone_wants() {
        for word in ["local", "localhost", "loopback", "off"] {
            assert_eq!(parse_address(word).as_deref(), Ok("127.0.0.1"), "{word}");
        }
        for word in ["all", "any", "lan", "network", "on"] {
            assert_eq!(parse_address(word).as_deref(), Ok("0.0.0.0"), "{word}");
        }
    }

    #[test]
    fn accepts_an_explicit_address() {
        assert_eq!(parse_address("10.0.1.2").as_deref(), Ok("10.0.1.2"));
        assert_eq!(parse_address("::1").as_deref(), Ok("::1"));
        assert_eq!(parse_address("  0.0.0.0 ").as_deref(), Ok("0.0.0.0"));
    }

    #[test]
    fn rejects_what_cannot_be_bound() {
        // A hostname is not an interface, and neither is a port.
        for bad in ["nas.lan", "0.0.0.0:80", "", "everything"] {
            assert!(parse_address(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn the_words_agree_with_the_default() {
        // If the default moved, `local` must move with it.
        assert_eq!(parse_address("local").as_deref(), Ok(DEFAULT_HOST));
    }
}
