use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};

use ports::cache::{load_cache, save_cache, CacheState};
use ports::cli::format::{bold, dim, gray, green, render_table, yellow, TableOptions};
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

    /// Stop whatever is listening on a port
    ///
    /// Sends SIGTERM and waits, so a dev server can exit tidily, then SIGKILL
    /// if it ignores that.
    #[command(
        after_help = "EXAMPLES:\n  ports kill 8080\n  ports kill 3000 5173\n  \
                            ports kill 8080 --force"
    )]
    Kill {
        /// Ports to free
        #[arg(required = true)]
        ports: Vec<u16>,

        /// Do not ask first
        #[arg(short, long)]
        yes: bool,

        /// SIGKILL straight away, with no chance to shut down cleanly
        #[arg(short, long)]
        force: bool,
    },

    /// Bind a local domain to a port
    ///
    /// With one argument the name is inferred from the project running there.
    #[command(
        after_help = "EXAMPLES:\n  ports bind myapp 4000\n  ports bind 4000\n  ports bind api.myapp 4001"
    )]
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

        /// Port to serve HTTPS on, overriding the saved setting
        #[arg(long)]
        https_port: Option<u16>,

        /// Do not serve HTTPS at all
        #[arg(long, conflicts_with = "https_port")]
        no_https: bool,
    },

    /// Show or change the local top-level domain
    ///
    /// Defaults to .localhost, which every resolver already sends to loopback.
    /// Any other TLD needs a one-time resolver entry, which --install writes.
    #[command(after_help = "EXAMPLES:\n  ports domain\n  ports domain test\n  \
                      ports domain --add devbox.lan\n  sudo ports domain --install")]
    Domain {
        /// Make this the canonical domain, adding it if new
        tld: Option<String>,

        /// Serve this domain as well, leaving the canonical one alone
        #[arg(long, value_name = "DOMAIN", conflicts_with_all = ["tld", "remove"])]
        add: Option<String>,

        /// Stop serving this domain
        #[arg(long, value_name = "DOMAIN", conflicts_with_all = ["tld", "add"])]
        remove: Option<String>,

        /// Write the resolver entries (needs root)
        #[arg(long)]
        install: bool,
    },

    /// Show or change which interface the proxy listens on
    ///
    /// Loopback by default. `all` reaches it from the rest of the network.
    #[command(after_help = "EXAMPLES:\n  ports expose\n  ports expose all\n  ports expose local")]
    Expose {
        /// `local`, `all`, or an address of this machine
        address: Option<String>,
    },

    /// Show or change the DNS resolver's port and forwarders
    ///
    /// Names under your domains are answered here; everything else is
    /// forwarded, to Cloudflare unless you say otherwise.
    #[command(after_help = "EXAMPLES:\n  ports dns\n  ports dns --port 53\n  \
                            ports dns --forward 9.9.9.9 --forward 149.112.112.112")]
    Dns {
        /// Port to listen on — 53 to serve other machines
        #[arg(long)]
        port: Option<u16>,

        /// Upstream resolver, repeatable or comma-separated
        #[arg(long, value_name = "ADDRESS")]
        forward: Vec<String>,

        /// Restore the default forwarders
        #[arg(long, conflicts_with = "forward")]
        reset: bool,
    },

    /// Show or change which addresses may bind from the web interface
    ///
    /// This machine always may. Anything else has to be named, and is then
    /// trusted without a password.
    #[command(
        after_help = "EXAMPLES:\n  ports trust\n  ports trust --add 10.0.1.50\n  \
                            ports trust --add 10.0.1.0/24\n  ports trust --clear"
    )]
    Trust {
        /// Address or network to allow, repeatable or comma-separated
        #[arg(long, value_name = "ADDRESS")]
        add: Vec<String>,

        /// Stop allowing one
        #[arg(long, value_name = "ADDRESS")]
        remove: Vec<String>,

        /// Allow nothing but this machine again
        #[arg(long)]
        clear: bool,
    },

    /// Check every layer and report which one is broken
    Doctor,

    /// Install the newest release
    Update {
        /// Only report whether one is available
        #[arg(long)]
        check: bool,
    },

    /// Manage the certificate authority used for HTTPS
    Ca {
        #[arg(value_enum, default_value = "status")]
        action: CaActionArg,
    },

    /// Install, remove or inspect the proxy service
    Service {
        #[arg(value_enum, default_value = "status")]
        action: ServiceActionArg,

        /// Install for the current user rather than system-wide
        #[arg(long)]
        user: bool,
    },
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum CaActionArg {
    /// Show which CA certificates are issued from
    Status,
    /// Generate our own CA, when no mkcert root exists
    Install,
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum ServiceActionArg {
    Install,
    Uninstall,
    Status,
    /// Print the unit file without installing anything
    Print,
}

impl From<ServiceActionArg> for ports::cli::service::ServiceAction {
    fn from(value: ServiceActionArg) -> Self {
        use ports::cli::service::ServiceAction;
        match value {
            ServiceActionArg::Install => ServiceAction::Install,
            ServiceActionArg::Uninstall => ServiceAction::Uninstall,
            ServiceActionArg::Status => ServiceAction::Status,
            ServiceActionArg::Print => ServiceAction::Print,
        }
    }
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
        Some(Command::Kill { ports, yes, force }) => {
            ports::cli::kill::kill(ports, yes, force).await
        }
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
        Some(Command::Serve {
            http_port,
            https_port,
            no_https,
        }) => serve(http_port, https_port, no_https).await,
        Some(Command::Domain {
            tld,
            add,
            remove,
            install,
        }) => {
            use ports::cli::domain::DomainAction;
            if install {
                ports::cli::domain::install_resolvers(tld.as_deref())
            } else {
                ports::cli::domain::domain(match (tld, add, remove) {
                    (Some(domain), _, _) => DomainAction::SetPrimary(domain),
                    (_, Some(domain), _) => DomainAction::Add(domain),
                    (_, _, Some(domain)) => DomainAction::Remove(domain),
                    _ => DomainAction::Show,
                })
            }
        }
        Some(Command::Expose { address }) => ports::cli::expose::expose(address),
        Some(Command::Dns {
            port,
            forward,
            reset,
        }) => ports::cli::dns::dns(port, forward, reset),
        Some(Command::Trust { add, remove, clear }) => ports::cli::trust::trust(add, remove, clear),
        Some(Command::Doctor) => ports::cli::doctor::doctor().await,
        Some(Command::Update { check }) => update(check),
        Some(Command::Ca { action }) => ca(action),
        Some(Command::Service { action, user }) => {
            ports::cli::service::service(ports::cli::service::ServiceArgs {
                action: action.into(),
                user,
            })
        }
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

    // checked_div rather than a guard: a tier with nothing to scan has no
    // percentage to show, which is the same case as a division by zero.
    let pct = match (progress.scanned * 100).checked_div(progress.total) {
        Some(percent) => format!(" {percent}%"),
        None => String::new(),
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
            fetch_favicons: false,
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
    let observed: std::collections::HashSet<u16> = result.records.iter().map(|r| r.port).collect();
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
        format!(
            "{} listener{}",
            live.len(),
            if live.len() == 1 { "" } else { "s" }
        ),
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

    // Read from cache only, so the listing never waits on the network.
    let cache = ports::update::read_cache();
    if let Some(version) = ports::update::pending_update(cache.as_ref()) {
        println!(
            "{}",
            gray(&format!("  v{version} available — run `ports update`"))
        );
    }
    println!();

    // Refresh afterwards, at most daily, so the next run knows. Deliberately
    // last: everything above is already printed by the time this can block.
    if !args.json && ports::update::check_is_due(cache.as_ref(), now_ms() / 1000) {
        ports::update::refresh_in_background();
    }

    Ok(())
}

fn update(check_only: bool) -> anyhow::Result<()> {
    use ports::update::{self, Origin, Version};

    let current = Version::current();
    println!("\n  installed  {}", dim(&format!("v{current}")));

    let latest = update::check_now()?;
    if latest <= current {
        println!("  latest     {}\n", bold(&format!("v{latest}")));
        println!("{}\n", dim("  already up to date"));
        return Ok(());
    }
    println!("  available  {}", bold(&format!("v{latest}")));

    if check_only {
        println!("\n{}\n", dim("  run `ports update` to install it"));
        return Ok(());
    }

    // Replacing a binary a package manager owns leaves it convinced one
    // version is installed while another is on disk.
    let exe = std::env::current_exe()?;
    if let Origin::PackageManager(name) = update::origin_of(&exe) {
        let how = match name {
            "Homebrew" => "brew upgrade ports",
            "cargo" => "cargo install ports --force",
            "npm" => "npm install -g @baboons/ports@latest",
            _ => "your package manager",
        };
        println!("\n  {}", yellow(&format!("this copy is managed by {name}")));
        println!("{}\n", dim(&format!("  update it with:  {how}")));
        return Ok(());
    }

    println!("{}", dim("  downloading and verifying…"));
    let download = update::download(latest)?;
    update::replace_binary(&exe, &download.bytes)?;

    println!(
        "\n  {} {}\n",
        green("✓"),
        bold(&format!("v{latest} installed to {}", exe.display()))
    );

    // A running daemon is still the old binary until it is restarted.
    if ports::config::bindings::load_bindings().bindings.is_empty() {
        return Ok(());
    }
    println!(
        "{}\n",
        dim("  restart a running proxy to pick it up:  ports service install")
    );
    Ok(())
}

fn ca(action: CaActionArg) -> anyhow::Result<()> {
    use ports::proxy::tls;

    match action {
        CaActionArg::Status => {
            match tls::find_ca() {
                Some(found) if found.is_mkcert => {
                    println!("\n  {}", bold("mkcert root"));
                    println!("  {}", dim(&found.source.display().to_string()));
                    println!(
                        "{}\n",
                        gray("  already trusted by this machine — nothing to install")
                    );
                }
                Some(found) => {
                    println!("\n  {}", bold("ports CA"));
                    println!("  {}", dim(&found.source.display().to_string()));
                    println!(
                        "{}\n",
                        gray("  must be trusted by the system for HTTPS to work without warnings")
                    );
                }
                None => {
                    println!("\n  {}", ports::cli::format::yellow("no local CA found"));
                    println!(
                        "{}",
                        gray("  install mkcert (brew install mkcert && mkcert -install),")
                    );
                    println!("{}\n", gray("  or run `ports ca install` to generate one"));
                }
            }
            Ok(())
        }
        CaActionArg::Install => {
            if let Some(found) = tls::find_ca() {
                if found.is_mkcert {
                    println!(
                        "\n  {}\n",
                        dim(&format!(
                            "an mkcert root already exists at {} — using that instead",
                            found.source.display()
                        ))
                    );
                    return Ok(());
                }
            }

            let generated = tls::generate_ca()?;
            println!(
                "\n  generated {}",
                bold(&generated.source.display().to_string())
            );
            println!("\n  {}", ports::cli::format::yellow("trust it:"));
            if cfg!(target_os = "macos") {
                println!(
                    "{}",
                    dim(&format!(
                        "    sudo security add-trusted-cert -d -r trustRoot \\\n      \
                         -k /Library/Keychains/System.keychain {}/rootCA.pem",
                        generated.source.display()
                    ))
                );
            } else {
                println!(
                    "{}",
                    dim(&format!(
                        "    sudo cp {}/rootCA.pem /usr/local/share/ca-certificates/ports.crt\n    \
                         sudo update-ca-certificates",
                        generated.source.display()
                    ))
                );
            }
            println!(
                "\n{}\n",
                gray("  Firefox keeps its own trust store; add it under Settings → Certificates")
            );
            Ok(())
        }
    }
}

/// Explain a DNS bind failure in terms of what to do about it.
fn dns_bind_error(err: std::io::Error, host: &str, port: u16) -> anyhow::Error {
    match err.kind() {
        std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
            "dns port {port} needs root — `sudo ports serve`, or `ports dns --port 15353`"
        ),
        std::io::ErrorKind::AddrInUse => anyhow::anyhow!(
            "dns port {port} on {host} is already in use — systemd-resolved and \
             dnsmasq both take 53; stop one, or `ports dns --port 15353`"
        ),
        _ => anyhow::anyhow!("could not bind dns on {host}:{port}: {err}"),
    }
}

/// Run the proxy in the foreground.
async fn serve(
    http_port_override: Option<u16>,
    https_port_override: Option<u16>,
    no_https: bool,
) -> anyhow::Result<()> {
    let mut bindings = ports::config::bindings::load_bindings_strict()?;
    if let Some(port) = http_port_override {
        bindings.http_port = port;
    }
    if no_https {
        bindings.https_port = None;
    } else if let Some(port) = https_port_override {
        bindings.https_port = Some(port);
    }

    let http_port = bindings.http_port;
    let https_port = bindings.https_port;
    let host = bindings.host.clone();
    let exposed = bindings.is_exposed();
    let tld = bindings.primary().to_string();
    let count = bindings.bindings.len();

    let needs_dns =
        ports::dns::resolver::mechanism_for(&tld) != ports::dns::resolver::Mechanism::None;

    // Claim the ports first, while we may still have the rights to.
    let listener = match ports::proxy::bind_listener(&host, http_port).await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            anyhow::bail!(
                "port {http_port} needs root. Either `sudo ports serve`, or pick an \
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

    // HTTPS only if a CA exists to issue from; a certificate nothing trusts
    // is worse than no HTTPS, because the failure is an interstitial rather
    // than a clean fallback.
    let ca = ports::proxy::tls::find_ca();
    let mut https_note: Option<String> = None;
    let https = match (https_port, &ca) {
        (Some(port), Some(_)) => match ports::proxy::bind_listener(&host, port).await {
            Ok(listener) => Some((port, listener)),
            // Losing TLS is a degradation; losing the proxy is an outage. Say
            // what happened and carry on serving HTTP, which is the half
            // everything actually depends on.
            Err(err) => {
                https_note = Some(match err.kind() {
                    std::io::ErrorKind::PermissionDenied => format!(
                        "https off: port {port} needs root — `sudo ports serve`, \
                         or set httpsPort above 1024"
                    ),
                    std::io::ErrorKind::AddrInUse => {
                        format!("https off: port {port} is already in use")
                    }
                    _ => format!("https off: could not bind port {port}: {err}"),
                });
                None
            }
        },
        (Some(_), None) => {
            https_note =
                Some("https off: no local CA — install mkcert, or run `ports ca install`".into());
            None
        }
        _ => None,
    };

    // The resolver listens wherever the proxy does, so pointing a LAN client
    // at this machine reaches both. Bound now, while privileges still allow
    // port 53.
    let dns_port = bindings.dns.port;
    let forwarders = bindings.dns.forwarders();
    let dns = if needs_dns {
        let udp = tokio::net::UdpSocket::bind((host.as_str(), dns_port))
            .await
            .map_err(|err| dns_bind_error(err, &host, dns_port))?;
        let tcp = tokio::net::TcpListener::bind((host.as_str(), dns_port))
            .await
            .map_err(|err| dns_bind_error(err, &host, dns_port))?;
        Some((udp, tcp))
    } else {
        None
    };

    // Everything privileged is done. Give root back before handling a single
    // request, so a bug in the proxy is a bug in an ordinary user process.
    ports::cli::service::drop_privileges()?;

    let state = Arc::new(ports::proxy::ProxyState::new(bindings));
    tokio::spawn(ports::proxy::watch_bindings(Arc::clone(&state)));
    // Populates the index with what is running, and caches their icons.
    tokio::spawn(ports::proxy::watch_ports(Arc::clone(&state)));

    if let Some((udp, tcp)) = dns {
        // Shares the proxy's binding table, so a domain added from the index
        // resolves without a restart.
        let resolver = Arc::new(ports::dns::Resolver::new(Arc::clone(&state.bindings)));
        let for_tcp = Arc::clone(&resolver);
        tokio::spawn(async move {
            let _ = ports::dns::serve_udp(udp, resolver).await;
        });
        tokio::spawn(async move {
            let _ = ports::dns::serve_tcp(tcp, for_tcp).await;
        });
    }

    let mut https_listening: Option<(u16, String)> = None;
    if let (Some((port, listener)), Some(ca)) = (https, ca) {
        https_listening = Some((port, ca.source.display().to_string()));
        let certs = Arc::new(ports::proxy::tls::CertStore::new(ca));
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = ports::proxy::serve_tls_on(listener, state, port, certs).await;
        });
    }

    println!(
        "\n  {} on port {http_port}, serving {count} binding{} under {}",
        bold("ports proxy"),
        if count == 1 { "" } else { "s" },
        bold(&format!("*.{tld}"))
    );
    match (&https_note, https_listening) {
        (Some(note), _) => println!("{}", gray(&format!("  {note}"))),
        (None, Some((port, source))) => println!(
            "{}",
            dim(&format!("  https on port {port}, issuing from {source}"))
        ),
        _ => {}
    }
    if needs_dns {
        let upstreams = forwarders
            .iter()
            .map(|address| address.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{}",
            dim(&format!(
                "  dns on {host}:{dns_port}, forwarding the rest to {upstreams}"
            ))
        );
        if exposed && dns_port == 53 {
            println!(
                "{}",
                gray(
                    "  other machines can use this as their DNS server — arbitrary \
                     names are resolved only for private clients"
                )
            );
        }
    }
    let index_suffix = if http_port == 80 {
        String::new()
    } else {
        format!(":{http_port}")
    };
    println!(
        "{}",
        dim(&format!(
            "  index at http://{}.{tld}{index_suffix}/",
            ports::proxy::index::INDEX_NAME
        ))
    );
    if exposed {
        println!(
            "{}",
            gray(&format!(
                "  listening on {host} — reachable from the network, and the index \
                 lists every service on this machine"
            ))
        );
        println!(
            "{}",
            gray("  bind and unbind are refused from off this machine")
        );
    }
    println!("{}\n", dim("  Ctrl-C to stop"));

    ports::proxy::serve_on(listener, state, http_port).await
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
