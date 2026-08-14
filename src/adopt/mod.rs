//! `ports adopt` — bind everything in a project you already have.

pub mod infer;
pub mod workspace;

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::bind::slugify;
use crate::cli::format::{bold, dim, gray, green, yellow};
use crate::config::bindings::{load_bindings_strict, normalise_name, save_bindings};
use crate::scan::scanner::{scan, ScanOptions};
use crate::types::{now_ms, PortRecord};

use self::infer::{infer_port, PortSource};
use self::workspace::{Repo, Workspace};

/// One workspace and what we worked out about it.
pub struct Candidate {
    pub rel: String,
    pub name: String,
    pub port: Option<u16>,
    pub source: Option<PortSource>,
}

/// Find the port a running server is using for this workspace.
///
/// Matches on the process's working directory: the most reliable signal there
/// is, because it is observed rather than inferred. A server started in a
/// subdirectory of the workspace still counts.
fn running_port(workspace: &Path, records: &[PortRecord], repo_root: &Path) -> Option<u16> {
    let mut best: Option<(usize, u16)> = None;

    for record in records {
        if !record.alive || !record.protocol.is_web() {
            continue;
        }
        let Some(cwd) = record.process.as_ref().and_then(|p| p.cwd.as_deref()) else {
            continue;
        };
        let cwd = Path::new(cwd);
        if !cwd.starts_with(workspace) {
            continue;
        }
        // The repo root "contains" every workspace, so without this the root
        // would claim whichever app happens to be listed first.
        if workspace == repo_root && cwd != repo_root {
            continue;
        }

        // Prefer the deepest match, so apps/web wins over the repo root for a
        // server actually started in apps/web.
        let depth = cwd.components().count();
        if best.map(|(d, _)| depth > d).unwrap_or(true) {
            best = Some((depth, record.port));
        }
    }

    best.map(|(_, port)| port)
}

/// Build the list of things we could bind.
pub fn candidates(repo: &Repo, records: &[PortRecord], prefix: bool) -> Vec<Candidate> {
    // Name each workspace, then qualify only the ones that collide.
    let mut proposed: Vec<(usize, String)> = Vec::new();
    for (index, workspace) in repo.workspaces.iter().enumerate() {
        proposed.push((index, base_name(workspace, repo)));
    }

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for (_, name) in &proposed {
        *counts.entry(name.as_str()).or_default() += 1;
    }

    let repo_slug = slugify(&repo.name);

    proposed
        .iter()
        .map(|(index, name)| {
            let workspace = &repo.workspaces[*index];

            // Qualify with the repo when asked, or when two workspaces in this
            // repo would otherwise claim the same hostname.
            let collides = counts.get(name.as_str()).copied().unwrap_or(0) > 1;
            let name = match (&repo_slug, prefix || collides) {
                (Some(repo_slug), true) if repo_slug != name => format!("{name}.{repo_slug}"),
                _ => name.clone(),
            };

            let (port, source) = match running_port(&workspace.dir, records, &repo.root) {
                Some(port) => (Some(port), Some(PortSource::Running)),
                None => match infer_port(&workspace.dir) {
                    Some((port, source)) => (Some(port), Some(source)),
                    None => (None, None),
                },
            };

            Candidate {
                rel: workspace.rel.clone(),
                name,
                port,
                source,
            }
        })
        .collect()
}

/// The unqualified name for a workspace: its package name, else its directory.
fn base_name(workspace: &Workspace, repo: &Repo) -> String {
    workspace
        .package_name
        .as_deref()
        .and_then(slugify)
        .or_else(|| {
            // "." is the repo root, whose directory name is the repo's.
            if workspace.rel == "." {
                slugify(&repo.name)
            } else {
                workspace
                    .dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(slugify)
            }
        })
        .unwrap_or_else(|| "app".to_string())
}

pub struct AdoptArgs {
    pub path: Option<PathBuf>,
    pub dry_run: bool,
    pub yes: bool,
    /// Qualify every name with the repo, e.g. `web.acme`.
    pub prefix: bool,
}

pub async fn adopt(args: AdoptArgs) -> anyhow::Result<()> {
    let start = match &args.path {
        Some(path) => path.clone(),
        None => std::env::current_dir()?,
    };

    let Some(repo) = workspace::discover(&start) else {
        anyhow::bail!(
            "{} does not look like a project — no package.json, Cargo.toml, go.mod or .git above it",
            start.display()
        );
    };

    // Tiers 1 and 2 only: this needs process cwds, which come from the process
    // table, and a full sweep would add seconds for ports nobody started.
    let result = scan(
        ScanOptions {
            deep: false,
            ..Default::default()
        },
        |_| {},
    )
    .await;

    let candidates = candidates(&repo, &result.records, args.prefix);
    let mut bindings = load_bindings_strict()?;

    println!(
        "\n  {}  ·  {}  ·  {} workspace{}",
        bold(&repo.name),
        dim(repo.kind.label()),
        repo.workspaces.len(),
        if repo.workspaces.len() == 1 { "" } else { "s" }
    );
    println!();

    let widest_rel = candidates.iter().map(|c| c.rel.len()).max().unwrap_or(9).max(9);
    let widest_source = candidates
        .iter()
        .map(|c| c.source.map(|s| s.label().len()).unwrap_or(9))
        .max()
        .unwrap_or(6);

    println!(
        "  {}  {}  {}  {}",
        dim(&format!("{:<widest_rel$}", "workspace")),
        dim(&format!("{:>5}", "port")),
        dim(&format!("{:<widest_source$}", "source")),
        dim("domain"),
    );

    let mut to_bind = Vec::new();
    for candidate in &candidates {
        let Some(port) = candidate.port else {
            println!(
                "  {}  {}  {}  {}",
                format!("{:<widest_rel$}", candidate.rel),
                gray(&format!("{:>5}", "—")),
                gray(&format!("{:<widest_source$}", "no server")),
                gray("skipped"),
            );
            continue;
        };

        let hostname = format!("{}.{}", candidate.name, bindings.tld);
        let existing = bindings.get(&candidate.name);
        let unchanged = existing.is_some_and(|b| {
            b.target == format!("127.0.0.1:{port}")
        });

        println!(
            "  {}  {}  {}  {} {}",
            format!("{:<widest_rel$}", candidate.rel),
            bold(&format!("{port:>5}")),
            dim(&format!(
                "{:<widest_source$}",
                candidate.source.map(|s| s.label()).unwrap_or("")
            )),
            green(&hostname),
            if unchanged {
                dim("(already bound)")
            } else if existing.is_some() {
                yellow("(re-pointed)")
            } else {
                String::new()
            },
        );

        if !unchanged {
            to_bind.push((candidate.name.clone(), format!("127.0.0.1:{port}")));
        }
    }

    println!();

    if to_bind.is_empty() {
        println!("{}\n", dim("  nothing to change"));
        return Ok(());
    }

    if args.dry_run {
        println!(
            "{}\n",
            dim(&format!("  {} would be bound — drop --dry-run to apply", to_bind.len()))
        );
        return Ok(());
    }

    if !args.yes && !confirm(to_bind.len())? {
        println!("{}\n", dim("  nothing bound"));
        return Ok(());
    }

    for (name, target) in &to_bind {
        // Already normalised on the way in, but a package name can produce
        // something a hostname cannot hold.
        let Some(name) = normalise_name(name, &bindings.tld) else {
            continue;
        };
        bindings.upsert(name, target.clone(), now_ms());
    }
    save_bindings(&bindings)?;

    println!(
        "  {} {} bound\n",
        green("✓"),
        to_bind.len()
    );
    Ok(())
}

fn confirm(count: usize) -> anyhow::Result<bool> {
    use std::io::IsTerminal;
    // Piped into something with no one to answer: do nothing rather than
    // assume yes.
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("not a terminal — pass --yes to bind without confirming");
    }

    print!("  bind {count}? [Y/n] ");
    std::io::stdout().flush()?;

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_lowercase();

    Ok(answer.is_empty() || answer == "y" || answer == "yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DiscoveryTier, HttpInfo, ProcessInfo, Protocol};

    fn write(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn record_at(port: u16, cwd: &Path) -> PortRecord {
        let mut record = PortRecord::new(port, DiscoveryTier::Lsof, "127.0.0.1", 0);
        record.protocol = Protocol::Http;
        record.http = Some(HttpInfo {
            status: 200,
            ..Default::default()
        });
        record.process = Some(ProcessInfo {
            pid: 1,
            cwd: Some(cwd.to_string_lossy().into_owned()),
            ..Default::default()
        });
        record
    }

    fn turborepo() -> tempfile::TempDir {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        write(&root.join("turbo.json"), "{}");
        write(
            &root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'apps/*'\n  - 'packages/*'\n",
        );
        write(&root.join("apps/web/package.json"), r#"{"name":"@acme/web"}"#);
        write(
            &root.join("apps/api/package.json"),
            r#"{"name":"@acme/api"}"#,
        );
        write(&root.join("apps/api/.env"), "PORT=4000\n");
        write(&root.join("packages/ui/package.json"), r#"{"name":"@acme/ui"}"#);
        repo
    }

    #[test]
    fn matches_a_running_server_to_the_workspace_it_was_started_in() {
        let repo_dir = turborepo();
        let repo = workspace::discover(repo_dir.path()).unwrap();
        let web = repo.root.join("apps/web");

        let records = vec![record_at(3000, &web)];
        let found = candidates(&repo, &records, false);

        let web_candidate = found.iter().find(|c| c.rel == "apps/web").unwrap();
        assert_eq!(web_candidate.port, Some(3000));
        assert_eq!(web_candidate.source, Some(PortSource::Running));
        assert_eq!(web_candidate.name, "web");
    }

    #[test]
    fn a_server_started_in_a_subdirectory_still_counts() {
        let repo_dir = turborepo();
        let repo = workspace::discover(repo_dir.path()).unwrap();
        let deep = repo.root.join("apps/web/src");
        std::fs::create_dir_all(&deep).unwrap();

        let records = vec![record_at(3000, &deep)];
        let found = candidates(&repo, &records, false);

        assert_eq!(
            found.iter().find(|c| c.rel == "apps/web").unwrap().port,
            Some(3000)
        );
    }

    #[test]
    fn the_repo_root_does_not_claim_a_workspaces_server() {
        let repo_dir = turborepo();
        let repo = workspace::discover(repo_dir.path()).unwrap();
        let web = repo.root.join("apps/web");

        let records = vec![record_at(3000, &web)];
        let found = candidates(&repo, &records, false);

        // Every workspace lives under the root, so without a guard the root
        // would claim the first server it saw.
        if let Some(root) = found.iter().find(|c| c.rel == ".") {
            assert_ne!(root.port, Some(3000));
        }
    }

    #[test]
    fn falls_back_to_declared_config_when_nothing_is_running() {
        let repo_dir = turborepo();
        let repo = workspace::discover(repo_dir.path()).unwrap();

        let found = candidates(&repo, &[], false);
        let api = found.iter().find(|c| c.rel == "apps/api").unwrap();

        assert_eq!(api.port, Some(4000));
        assert_eq!(api.source, Some(PortSource::DotEnv));
    }

    #[test]
    fn a_library_workspace_is_skipped_rather_than_guessed_at() {
        let repo_dir = turborepo();
        let repo = workspace::discover(repo_dir.path()).unwrap();

        let found = candidates(&repo, &[], false);
        let ui = found.iter().find(|c| c.rel == "packages/ui").unwrap();

        assert_eq!(ui.port, None, "a package with no dev server must not get one");
    }

    #[test]
    fn colliding_names_are_qualified_with_the_repo() {
        let repo_dir = tempfile::tempdir().unwrap();
        let root = repo_dir.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        write(&root.join("package.json"), r#"{"workspaces":["apps/*"]}"#);
        // Two workspaces whose package names slugify to the same thing.
        write(&root.join("apps/web/package.json"), r#"{"name":"@one/web"}"#);
        write(&root.join("apps/web2/package.json"), r#"{"name":"@two/web"}"#);

        let repo = workspace::discover(root).unwrap();
        let found = candidates(&repo, &[], false);

        let names: Vec<&str> = found.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.iter().filter(|n| **n == "web").count() <= 1,
            "collision was not resolved: {names:?}"
        );
    }

    #[test]
    fn prefix_qualifies_every_name() {
        let repo_dir = turborepo();
        let repo = workspace::discover(repo_dir.path()).unwrap();
        let found = candidates(&repo, &[], true);

        let web = found.iter().find(|c| c.rel == "apps/web").unwrap();
        assert!(
            web.name.ends_with(&format!(".{}", slugify(&repo.name).unwrap())),
            "expected a repo-qualified name, got {}",
            web.name
        );
    }

    #[test]
    fn every_proposed_name_is_a_legal_hostname() {
        let repo_dir = turborepo();
        let repo = workspace::discover(repo_dir.path()).unwrap();

        for candidate in candidates(&repo, &[], true) {
            assert!(
                normalise_name(&candidate.name, "localhost").is_some(),
                "{:?} is not a usable hostname label",
                candidate.name
            );
        }
    }
}
