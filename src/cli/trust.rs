//! `ports trust` — which addresses may change bindings from the web interface.

use crate::cli::format::{bold, dim, gray, green, yellow};
use crate::config::bindings::{load_bindings_strict, save_bindings, Bindings};
use crate::config::trust::{check_entries, is_dangerously_broad};

pub fn trust(add: Vec<String>, remove: Vec<String>, clear: bool) -> anyhow::Result<()> {
    let mut bindings = load_bindings_strict()?;

    if add.is_empty() && remove.is_empty() && !clear {
        return show(&bindings);
    }

    if clear {
        bindings.trusted.clear();
    }

    for entry in check_entries(&remove).map_err(|err| anyhow::anyhow!(err))? {
        if !bindings.trusted.contains(&entry) {
            anyhow::bail!("{entry} is not trusted");
        }
        bindings.trusted.retain(|existing| *existing != entry);
    }

    for entry in check_entries(&add).map_err(|err| anyhow::anyhow!(err))? {
        if is_dangerously_broad(&entry) {
            anyhow::bail!(
                "{entry} is every address there is — anything that can reach the proxy \
                 could rebind your domains.\n  Name the machines instead, or a single \
                 network like 10.0.1.0/24."
            );
        }
        if !bindings.trusted.contains(&entry) {
            bindings.trusted.push(entry);
        }
    }

    save_bindings(&bindings)?;
    show(&bindings)?;
    println!(
        "{}\n",
        dim("  takes effect immediately — no restart needed")
    );
    Ok(())
}

fn show(bindings: &Bindings) -> anyhow::Result<()> {
    println!("\n  {}", bold("allowed to bind and unbind from the page"));
    println!("    {} {}", green("✓"), dim("this machine (always)"));

    if bindings.trusted.is_empty() {
        println!(
            "\n{}",
            gray("  nothing else — `ports trust --add 10.0.1.50`")
        );
    } else {
        for entry in &bindings.trusted {
            println!("    {} {}", green("✓"), entry);
        }
        println!(
            "\n{}",
            yellow("  these are trusted without a password — anything holding one of")
        );
        println!("{}", yellow("  those addresses can repoint your domains"));
    }

    if !bindings.is_exposed() && !bindings.trusted.is_empty() {
        println!(
            "\n{}",
            gray("  the proxy is loopback-only, so nothing else can reach it anyway")
        );
    }
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_that_trusts_the_whole_internet_is_refused() {
        // Everything else here is a judgement call; this one is a mistake.
        assert!(is_dangerously_broad("0.0.0.0/0"));
        assert!(is_dangerously_broad("::/0"));
        // A real network is not.
        assert!(!is_dangerously_broad("10.0.1.0/24"));
        assert!(!is_dangerously_broad("10.0.0.0/8"));
    }
}
