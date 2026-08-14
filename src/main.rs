mod cache;
mod cli;
mod config;
mod scan;
mod types;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};

use crate::cache::{load_cache, save_cache, CacheState};
use crate::cli::format::{dim, gray, render_table, TableOptions};
use crate::config::curation::{
    curation_path, hide_reason_for, load_curation, save_curation, with_hidden, without_hidden,
};
use crate::scan::listeners::is_privileged;
use crate::scan::scanner::{scan, ScanOptions};
use crate::scan::scheduler::is_sweep_due;
use crate::types::{now_ms, PortRecord, ScanProgress};

#[derive(Parser)]
#[command(
    name = "ports",
    version,
    about = "Find the HTTP servers running on this machine",
    // Subcommands are the exception, not the rule: bare `ports` lists.
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    list: ListArgs,
}

#[derive(clap::Args, Default)]
struct ListArgs {
    /// Include listeners that do not speak HTTP
    #[arg(short, long)]
    all: bool,

    /// Skip the full 1-65535 sweep
    #[arg(long)]
    fast: bool,

    /// Ignore cached descriptions and re-probe everything
    #[arg(short, long)]
    refresh: bool,

    /// Do not read or write the cache at all
    #[arg(long)]
    no_cache: bool,

    /// Emit JSON instead of a table
    #[arg(long)]
    json: bool,

    /// Suppress the progress line
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Command {
    /// List the HTTP servers running on this machine (the default)
    Ls(ListArgs),

    /// Hide ports from the listing
    Hide {
        /// Port numbers to hide
        #[arg(required = true)]
        ports: Vec<u16>,
    },

    /// Bring hidden ports back
    Unhide {
        #[arg(required = true)]
        ports: Vec<u16>,
    },

    /// Show the current hide rules and where they live
    Hidden,
}

#[tokio::main]
async fn main() {
    // rustls needs a process-wide crypto provider before any TLS happens.
    // Installing it once here beats discovering the panic mid-probe.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    let result = match cli.command {
        None => list(cli.list).await,
        Some(Command::Ls(args)) => list(args).await,
        Some(Command::Hide { ports }) => curate(&ports, true),
        Some(Command::Unhide { ports }) => curate(&ports, false),
        Some(Command::Hidden) => show_hidden(),
    };

    if let Err(err) = result {
        eprintln!("\n{} {err}", cli::format::red("ports failed:"));
        std::process::exit(1);
    }
}

/// A single rewritten status line, so progress does not scroll the terminal.
fn progress_line(progress: &ScanProgress, last_paint: &mut Instant) {
    use std::io::IsTerminal;
    if !std::io::stderr().is_terminal() || progress.done {
        return;
    }
    // The sweep fires thousands of updates; repaint at most every 80ms.
    if last_paint.elapsed().as_millis() < 80 {
        return;
    }
    *last_paint = Instant::now();

    let pct = if progress.total > 0 {
        format!(" {}%", progress.scanned * 100 / progress.total)
    } else {
        String::new()
    };
    eprint!(
        "\r{}\x1b[K",
        dim(&format!(
            "  {}{pct} — {} found",
            progress.phase.label(),
            progress.found
        ))
    );
}

async fn list(args: ListArgs) -> anyhow::Result<()> {
    let started = Instant::now();

    let cancel = Arc::new(AtomicBool::new(false));
    {
        let cancel = Arc::clone(&cancel);
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                cancel.store(true, Ordering::Relaxed);
                eprintln!();
                std::process::exit(130);
            }
        });
    }

    let cache = if args.no_cache {
        CacheState::default()
    } else {
        load_cache()
    };

    // The full sweep is the expensive tier by an order of magnitude. If one
    // completed recently, tiers 1 and 2 keep the picture current, which is what
    // makes a repeat run return in well under a second.
    let sweep_due = args.refresh || is_sweep_due(cache.last_full_sweep, now_ms());
    let deep = !args.fast && sweep_due;

    let show_progress = !args.quiet && !args.json;
    let mut last_paint = Instant::now() - std::time::Duration::from_secs(1);

    let result = scan(
        ScanOptions {
            deep,
            force: args.refresh,
            prior: cache.records.clone(),
            self_port: None,
            cancel: Arc::clone(&cancel),
        },
        |progress| {
            if show_progress {
                progress_line(&progress, &mut last_paint);
            }
        },
    )
    .await;

    if show_progress {
        eprint!("\r\x1b[K");
    }

    // Fold this pass into the index. Ports we did not look at keep their last
    // known state: skipping the sweep must make the answer cheaper, never
    // smaller. Anything carried over is flagged stale so it reads as
    // remembered rather than observed.
    let observed: std::collections::HashSet<u16> =
        result.records.iter().map(|r| r.port).collect();
    let mut merged: Vec<PortRecord> = cache
        .records
        .iter()
        .filter(|r| !observed.contains(&r.port))
        .map(|r| PortRecord {
            stale: true,
            ..r.clone()
        })
        .chain(result.records.iter().cloned())
        .collect();
    merged.sort_by_key(|r| r.port);

    if !args.no_cache {
        save_cache(&CacheState {
            last_full_sweep: if result.swept_fully {
                now_ms()
            } else {
                cache.last_full_sweep
            },
            records: merged.clone(),
            ..Default::default()
        });
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&merged)?);
        return Ok(());
    }

    // Dead entries stay in the cache as history, but the listing is a view of
    // what is running right now.
    let curation = load_curation();
    let curated = merged
        .iter()
        .filter(|r| hide_reason_for(r, &curation).is_some())
        .count();
    let live: Vec<PortRecord> = merged
        .into_iter()
        .filter(|r| r.alive)
        .filter(|r| args.all || hide_reason_for(r, &curation).is_none())
        .collect();

    let web = live.iter().filter(|r| r.protocol.is_web()).count();
    let elapsed = started.elapsed().as_secs_f64();

    println!();
    println!(
        "{}",
        render_table(
            &live,
            &TableOptions {
                include_tcp: args.all,
                ..Default::default()
            }
        )
    );
    println!();

    let mut parts = vec![
        format!("{web} web server{}", if web == 1 { "" } else { "s" }),
        format!("{} listener{}", live.len(), if live.len() == 1 { "" } else { "s" }),
        format!("{elapsed:.1}s"),
    ];
    if !deep && !args.fast {
        // Be explicit that coverage was narrowed, rather than quietly showing less.
        parts.push("cached sweep".into());
    }
    println!("{}", dim(&format!("  {}", parts.join(" · "))));

    if curated > 0 && !args.all {
        println!(
            "{}",
            gray(&format!(
                "  {curated} hidden by curation — 'ports hidden' to review, -a to include."
            ))
        );
    }
    if !deep && !args.fast {
        println!(
            "{}",
            gray("  Full port sweep skipped; still fresh. Use --refresh to force one.")
        );
    }
    if !is_privileged() {
        println!("{}", gray("  Run with sudo to see other users' processes."));
    }
    println!();

    Ok(())
}

fn curate(ports: &[u16], hide: bool) -> anyhow::Result<()> {
    let mut curation = load_curation();
    for port in ports {
        curation = if hide {
            with_hidden(curation, *port)
        } else {
            without_hidden(curation, *port)
        };
    }
    save_curation(&curation)?;

    let list = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    println!("\n  {list} {}", if hide { "hidden" } else { "shown" });
    println!("{}\n", dim(&format!("  {}", curation_path().display())));
    Ok(())
}

fn show_hidden() -> anyhow::Result<()> {
    let curation = load_curation();

    println!();
    if curation.is_empty() {
        println!("{}", dim("  nothing hidden"));
    } else {
        if !curation.hidden_ports.is_empty() {
            let list: Vec<String> = curation.hidden_ports.iter().map(u16::to_string).collect();
            println!("  ports     {}", list.join(", "));
        }
        if !curation.hidden_ranges.is_empty() {
            println!("  ranges    {}", curation.hidden_ranges.join(", "));
        }
        if !curation.hidden_commands.is_empty() {
            println!("  commands  {}", curation.hidden_commands.join(", "));
        }
    }
    println!("{}\n", dim(&format!("  {}", curation_path().display())));
    Ok(())
}
