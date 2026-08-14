//! `ports domain` — change the local TLD.

use std::process::Command;

use crate::cli::format::{bold, dim, gray, green, yellow};
use crate::config::bindings::{load_bindings_strict, save_bindings};
use crate::dns::resolver::{mechanism_for, plan_install, rewrite_hosts, Mechanism};

/// TLDs that would cause trouble, and why.
fn warn_about(tld: &str) -> Option<&'static str> {
    match tld {
        // Real, HSTS-preloaded: every http:// request is force-upgraded, so
        // plain HTTP can never work no matter what we serve.
        "dev" | "app" | "foo" | "zip" | "mov" => {
            Some("is a real, HSTS-preloaded TLD — browsers force HTTPS on it, so plain HTTP will never work")
        }
        // mDNS territory; hijacking it breaks device discovery.
        "local" => Some("is used by mDNS/Bonjour — taking it over breaks device discovery"),
        _ => None,
    }
}

fn is_valid_tld(tld: &str) -> bool {
    !tld.is_empty()
        && tld.len() <= 63
        && tld.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !tld.starts_with('-')
        && !tld.ends_with('-')
        // An all-numeric TLD would be ambiguous with an address.
        && !tld.chars().all(|c| c.is_ascii_digit())
}

pub fn domain(new_tld: Option<String>) -> anyhow::Result<()> {
    let mut bindings = load_bindings_strict()?;

    let Some(new_tld) = new_tld else {
        return show(&bindings.tld);
    };

    let new_tld = new_tld.trim().trim_matches('.').to_lowercase();
    if !is_valid_tld(&new_tld) {
        anyhow::bail!("'{new_tld}' is not a usable top-level domain");
    }

    if let Some(reason) = warn_about(&new_tld) {
        anyhow::bail!(
            ".{new_tld} {reason}.\n  \
             Consider .localhost (no setup at all) or .test (reserved for exactly this)."
        );
    }

    let old_tld = std::mem::replace(&mut bindings.tld, new_tld.clone());
    if old_tld == new_tld {
        println!("\n  already {}\n", bold(&format!("*.{new_tld}")));
        return Ok(());
    }

    save_bindings(&bindings)?;

    println!(
        "\n  {} → {}",
        dim(&format!("*.{old_tld}")),
        bold(&format!("*.{new_tld}"))
    );
    for binding in &bindings.bindings {
        println!("    {}", green(&binding.hostname(&new_tld)));
    }
    println!();

    // Leaving the old resolver file behind would keep sending a TLD we no
    // longer serve at a responder that will now NXDOMAIN it.
    if mechanism_for(&old_tld) == Mechanism::MacResolver {
        let old_path = crate::dns::resolver::mac_resolver_path(&old_tld);
        if old_path.exists() {
            println!(
                "{}",
                gray(&format!("  no longer needed:  sudo rm {}", old_path.display()))
            );
        }
    }

    print_setup(&new_tld, &bindings)?;
    Ok(())
}

fn show(tld: &str) -> anyhow::Result<()> {
    println!("\n  {}", bold(&format!("*.{tld}")));
    match mechanism_for(tld) {
        Mechanism::None => println!(
            "{}\n",
            gray("  resolved by the OS with no setup — nothing to install")
        ),
        _ => {
            let bindings = load_bindings_strict()?;
            print_setup(tld, &bindings)?;
        }
    }
    Ok(())
}

/// Explain what still has to happen for this TLD to resolve.
fn print_setup(tld: &str, bindings: &crate::config::bindings::Bindings) -> anyhow::Result<()> {
    let Some(install) = plan_install(tld) else {
        println!(
            "{}\n",
            gray("  every resolver sends *.localhost to loopback already — nothing to install")
        );
        return Ok(());
    };

    match install.mechanism {
        Mechanism::HostsFile => {
            println!("  {}", yellow("this TLD needs /etc/hosts entries:"));
            let existing = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
            let updated = rewrite_hosts(&existing, bindings);
            println!(
                "{}",
                dim("    ports writes these itself when run with sudo; the block is marked")
            );
            for line in updated.lines().skip_while(|l| !l.contains(">>> ports")) {
                println!("    {}", dim(line));
            }
        }
        _ => {
            println!("  {}", yellow("this TLD needs a resolver entry:"));
            println!(
                "{}",
                dim(&format!(
                    "    sudo mkdir -p {}",
                    install
                        .path
                        .parent()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                ))
            );
            println!(
                "{}",
                dim(&format!(
                    "    printf '{}' | sudo tee {} >/dev/null",
                    install.contents.replace('\n', "\\n"),
                    install.path.display()
                ))
            );
            if let Some(reload) = &install.reload {
                println!("{}", dim(&format!("    sudo {}", reload.join(" "))));
            }
            println!(
                "\n{}",
                gray("  then `ports service install` so the DNS responder is running")
            );
        }
    }
    println!();
    Ok(())
}

/// Write the resolver entry. Requires root; used by `ports domain --install`.
pub fn install_resolver(tld: &str) -> anyhow::Result<()> {
    let Some(install) = plan_install(tld) else {
        println!("\n{}\n", dim("  nothing to install for *.localhost"));
        return Ok(());
    };

    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!(
            "writing {} needs root — try `sudo ports domain {tld} --install`",
            install.path.display()
        );
    }

    match install.mechanism {
        Mechanism::HostsFile => {
            let bindings = load_bindings_strict()?;
            let existing = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
            std::fs::write("/etc/hosts", rewrite_hosts(&existing, &bindings))?;
            println!("\n  updated {}\n", bold("/etc/hosts"));
        }
        _ => {
            if let Some(parent) = install.path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&install.path, &install.contents)?;
            println!("\n  wrote {}", bold(&install.path.display().to_string()));

            if let Some(reload) = &install.reload {
                let _ = Command::new(&reload[0]).args(&reload[1..]).status();
            }
            println!();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_tlds_that_cannot_work() {
        // HSTS-preloaded: the browser upgrades to HTTPS before we see it.
        assert!(warn_about("dev").is_some());
        assert!(warn_about("app").is_some());
        // mDNS.
        assert!(warn_about("local").is_some());

        assert!(warn_about("test").is_none());
        assert!(warn_about("localhost").is_none());
        assert!(warn_about("lo").is_none());
    }

    #[test]
    fn validates_the_shape_of_a_tld() {
        for good in ["test", "localhost", "lo", "internal", "dev-box"] {
            assert!(is_valid_tld(good), "{good} should be valid");
        }
        for bad in ["", "has space", "under_score", "-lead", "trail-", "123", "a.b"] {
            assert!(!is_valid_tld(bad), "{bad} should be rejected");
        }
    }
}
