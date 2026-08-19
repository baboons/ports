//! `ports domain` — change the local TLD.

use std::process::Command;

use crate::cli::format::{bold, dim, gray, green, yellow};
use crate::config::bindings::{load_bindings_strict, save_bindings};
use crate::dns::resolver::{mechanism_for, plan_install_on, rewrite_hosts, Mechanism};

/// What `ports domain` was asked to do.
pub enum DomainAction {
    Show,
    /// Make this the canonical domain, adding it if new.
    SetPrimary(String),
    /// Serve this as well, without changing which is canonical.
    Add(String),
    Remove(String),
}

fn check(domain: &str) -> anyhow::Result<String> {
    crate::config::bindings::check_domain(domain).map_err(|err| {
        anyhow::anyhow!(
            "{err}.\n  \
             Consider .localhost (no setup at all) or .test (reserved for exactly this)."
        )
    })
}

pub fn domain(action: DomainAction) -> anyhow::Result<()> {
    let mut bindings = load_bindings_strict()?;

    match action {
        DomainAction::Show => return show(&bindings),

        DomainAction::SetPrimary(domain) => {
            let domain = check(&domain)?;
            if bindings.primary() == domain {
                println!("\n  already {}\n", bold(&format!("*.{domain}")));
                return Ok(());
            }
            let previous = bindings.primary().to_string();

            // The old one keeps serving: links people already have should not
            // break because the canonical name changed.
            bindings.domains.retain(|d| *d != domain);
            bindings.domains.insert(0, domain.clone());
            save_bindings(&bindings)?;

            println!(
                "\n  {} → {}",
                dim(&format!("*.{previous}")),
                bold(&format!("*.{domain}"))
            );
            println!(
                "{}",
                gray(&format!(
                    "  *.{previous} still works — `ports domain --remove {previous}` to stop"
                ))
            );
        }

        DomainAction::Add(domain) => {
            let domain = check(&domain)?;
            if bindings.domains.contains(&domain) {
                println!("\n  {} is already served\n", bold(&format!("*.{domain}")));
                return Ok(());
            }
            bindings.domains.push(domain.clone());
            save_bindings(&bindings)?;
            println!("\n  also serving {}", bold(&format!("*.{domain}")));
        }

        DomainAction::Remove(domain) => {
            let domain = domain.trim().trim_matches('.').to_lowercase();
            if bindings.domains.len() == 1 && bindings.domains[0] == domain {
                anyhow::bail!(
                    "{domain} is the only domain — the proxy would answer for nothing.\n  \
                     Add another first: ports domain <other>"
                );
            }
            if !bindings.domains.contains(&domain) {
                anyhow::bail!("{domain} is not one of the domains served");
            }
            bindings.domains.retain(|d| *d != domain);
            save_bindings(&bindings)?;

            println!("\n  no longer serving {}", bold(&format!("*.{domain}")));
            if mechanism_for(&domain) == Mechanism::MacResolver {
                let path = crate::dns::resolver::mac_resolver_path(&domain);
                if path.exists() {
                    println!(
                        "{}",
                        gray(&format!("  no longer needed:  sudo rm {}", path.display()))
                    );
                }
            }
            println!();
            return Ok(());
        }
    }

    for binding in &bindings.bindings {
        println!("    {}", green(&binding.hostname(bindings.primary())));
    }
    println!();

    print_setup_all(&bindings)?;
    Ok(())
}

fn show(bindings: &crate::config::bindings::Bindings) -> anyhow::Result<()> {
    println!();
    for (index, domain) in bindings.domains.iter().enumerate() {
        let note = if index == 0 { " (canonical)" } else { "" };
        println!("  {}{}", bold(&format!("*.{domain}")), dim(note));
    }

    if bindings.is_exposed() {
        println!(
            "\n{}",
            gray(&format!(
                "  listening on {} — point these at this machine in your DNS or hosts file",
                bindings.host
            ))
        );
    }

    print_setup_all(bindings)?;
    Ok(())
}

/// Explain what still has to happen for every domain that needs it.
fn print_setup_all(bindings: &crate::config::bindings::Bindings) -> anyhow::Result<()> {
    let needing = bindings.domains_needing_dns();
    if needing.is_empty() {
        println!(
            "{}\n",
            gray("  every resolver sends these to loopback already — nothing to install")
        );
        return Ok(());
    }

    // A domain pointed here by a hosts file or a LAN DNS server needs nothing
    // from us; the resolver entry is only for making it resolve on this box.
    println!();
    for domain in needing {
        print_setup(domain, bindings)?;
    }
    Ok(())
}

/// Explain what still has to happen for this TLD to resolve.
fn print_setup(tld: &str, bindings: &crate::config::bindings::Bindings) -> anyhow::Result<()> {
    let bindings_now = load_bindings_strict().unwrap_or_default();
    let Some(install) = plan_install_on(tld, bindings_now.dns.port) else {
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
            // A domain on a LAN is usually already pointed at the machine by
            // the user's own DNS or hosts file, in which case there is nothing
            // for us to install — say so before printing commands.
            println!(
                "  {}",
                yellow(&format!("*.{tld} has to resolve to this machine somehow:"))
            );
            println!(
                "{}",
                dim("    already handled if your DNS or hosts file points it here")
            );
            println!("{}", dim("    otherwise, to resolve it on this box only:"));
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

/// Write resolver entries for every domain that needs one, or just the named
/// one. Requires root; used by `ports domain --install`.
pub fn install_resolvers(only: Option<&str>) -> anyhow::Result<()> {
    let bindings = load_bindings_strict()?;

    let wanted: Vec<String> = match only {
        Some(domain) => vec![domain.trim().trim_matches('.').to_lowercase()],
        None => bindings
            .domains_needing_dns()
            .into_iter()
            .map(str::to_string)
            .collect(),
    };

    if wanted.is_empty() {
        println!(
            "\n{}\n",
            dim("  nothing to install — every configured domain resolves on its own")
        );
        return Ok(());
    }

    for domain in wanted {
        install_resolver(&domain)?;
    }
    Ok(())
}

/// Write the resolver entry for one domain. Requires root.
pub fn install_resolver(tld: &str) -> anyhow::Result<()> {
    let bindings_now = load_bindings_strict().unwrap_or_default();
    let Some(install) = plan_install_on(tld, bindings_now.dns.port) else {
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
    use crate::config::bindings::warn_about;

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
}
