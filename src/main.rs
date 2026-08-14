
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};

use ports::cache::{load_cache, save_cache, CacheState};
use ports::cli::format::{bold, dim, gray, render_table, TableOptions};
use ports::config::curation::{
    curation_path, hide_reason_for, load_curation, save_curation, with_hidden, without_hidden,
};
use ports::scan::listeners::is_privileged;
use ports::scan::scanner::{scan, ScanOptions};
use ports::scan::scheduler::is_sweep_due;
use ports::types::{now_ms, PortRecord, ScanProgress};

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

    /// Bind a local domain to a port
    ///
    /// With one argument the name is inferred from the project running there.
    #[command(after_help = "EXAMPLES:\n  ports bind myapp 4000\n  ports bind 4000\n  ports bind api.myapp 4001")]
    Bind {
        /// Subdomain, or the port when given alone
        first: String,
        /// Port, or host:port
        second: Option<String>,
    },

    /// Bind every server in the current project
    ///
    /// Finds the repo's workspaces, matches running servers to them by working
    /// directory, and falls back to declared config for anything not up yet.
    Adopt {
        /// Project directory (defaults to the current one)
        path: Option<std::path::PathBuf>,

        /// Show what would be bound, and write nothing
        #[arg(long)]
        dry_run: bool,

        /// Bind without confirming
        #[arg(short, long)]
        yes: bool,

        /// Qualify every name with the repo, e.g. web.acme.localhost
        #[arg(long)]
        prefix: bool,
    },

    /// Remove a local domain binding
    Unbind {
        /// The subdomain to remove
        name: String,
    },

    /// List bound domains and whether their upstreams are answering
    Links,

    /// Run the proxy in the foreground
    Serve {
        /// Port to serve HTTP on, overriding the saved setting
        #[arg(long)]
        http_port: Option<u16>,
    },
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
        Some(Command::Bind { first, second }) => {
            // `ports bind 4000` infers the name; `ports bind myapp 4000` does not.
            match second {
                Some(target) => ports::cli::bind::bind(Some(first), target).await,
                None => ports::cli::bind::bind(None, first).await,
            }
        }
        Some(Command::Adopt {
            path,
            dry_run,
            yes,
            prefix,
        }) => {
            ports::adopt::adopt(ports::adopt::AdoptArgs {
                path,
                dry_run,
                yes,
                prefix,
            })
            .await
        }
        Some(Command::Unbind { name }) => ports::cli::bind::unbind(name),
        Some(Command::Links) => ports::cli::bind::links().await,
        Some(Command::Serve { http_port }) => serve(http_port).await,
    };

    if let Err(err) = result {
        eprintln!("\n{} {err}", ports::cli::format::red("ports failed:"));
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

/// Run the proxy in the foreground.
async fn serve(http_port_override: Option<u16>) -> anyhow::Result<()> {
    let mut bindings = ports::config::bindings::load_bindings_strict()?;
    if let Some(port) = http_port_override {
        bindings.http_port = port;
    }

    let http_port = bindings.http_port;
    let tld = bindings.tld.clone();
    let count = bindings.bindings.len();

    let state = Arc::new(ports::proxy::ProxyState::new(bindings));
    tokio::spawn(ports::proxy::watch_bindings(Arc::clone(&state)));

    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", http_port)).await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            anyhow::bail!(
                "port {http_port} needs root. Either run `sudo ports serve`, or pick an \
                 unprivileged port with `ports serve --http-port 8080`"
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
            let holder = ports::scan::listeners::enumerate_listeners()
                .into_iter()
                .find(|l| l.port == http_port)
                .and_then(|l| l.command)
                .unwrap_or_else(|| "another process".into());
            anyhow::bail!("port {http_port} is already held by {holder}");
        }
        Err(err) => return Err(err.into()),
    };
    drop(listener);

    println!(
        "\n  {} on port {http_port}, serving {count} binding{} under {}",
        bold("ports proxy"),
        if count == 1 { "" } else { "s" },
        bold(&format!("*.{tld}"))
    );
    println!("{}\n", dim("  Ctrl-C to stop"));

    ports::proxy::serve_http(state, http_port).await
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
