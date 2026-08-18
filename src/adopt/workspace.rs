//! Work out what kind of repo this is and which directories in it are apps.
//!
//! Deliberately reads the package manager's own manifest rather than
//! special-casing any one tool: turborepo, Nx and Lerna all delegate the
//! workspace list to pnpm/npm/yarn, so following the same file makes this work
//! for all of them at once.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoKind {
    Turborepo,
    PnpmWorkspaces,
    NpmWorkspaces,
    CargoWorkspace,
    GoWorkspace,
    Nx,
    /// A plain project with no workspace layout.
    Single,
}

impl RepoKind {
    pub fn label(self) -> &'static str {
        match self {
            RepoKind::Turborepo => "turborepo",
            RepoKind::PnpmWorkspaces => "pnpm workspaces",
            RepoKind::NpmWorkspaces => "npm/yarn workspaces",
            RepoKind::CargoWorkspace => "cargo workspace",
            RepoKind::GoWorkspace => "go workspace",
            RepoKind::Nx => "nx",
            RepoKind::Single => "single project",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    /// Absolute path to the workspace directory.
    pub dir: PathBuf,
    /// Path relative to the repo root, e.g. "apps/web". "." for the root itself.
    pub rel: String,
    /// The name its manifest declares, if any.
    pub package_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Repo {
    pub root: PathBuf,
    /// Directory basename, used to qualify colliding workspace names.
    pub name: String,
    pub kind: RepoKind,
    pub workspaces: Vec<Workspace>,
}

/// Find the repo containing `start` and enumerate its workspaces.
pub fn discover(start: &Path) -> Option<Repo> {
    let root = find_root(start)?;
    let name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("repo")
        .to_string();

    let (kind, patterns) = layout(&root);

    let mut workspaces = Vec::new();
    for pattern in &patterns {
        for dir in expand(&root, pattern) {
            // Only directories that are actually packages; a glob like
            // `packages/*` happily matches `packages/.DS_Store`'s parent junk.
            let Some(package_name) = manifest_name(&dir) else {
                continue;
            };
            let rel = dir
                .strip_prefix(&root)
                .ok()
                .and_then(|p| p.to_str())
                .unwrap_or(".")
                .to_string();
            workspaces.push(Workspace {
                dir,
                rel,
                package_name,
            });
        }
    }

    // A workspace repo's root often runs something too (a docs site, a gateway),
    // and a single-project repo is nothing but its root.
    if (patterns.is_empty() || manifest_name(&root).is_some())
        && !workspaces.iter().any(|w| w.dir == root)
    {
        workspaces.insert(
            0,
            Workspace {
                dir: root.clone(),
                rel: ".".to_string(),
                package_name: manifest_name(&root).flatten(),
            },
        );
    }

    workspaces.sort_by(|a, b| a.rel.cmp(&b.rel));
    workspaces.dedup_by(|a, b| a.dir == b.dir);

    Some(Repo {
        root,
        name,
        kind,
        workspaces,
    })
}

/// Walk up looking for the outermost thing that looks like a repo root.
///
/// `.git` wins when present: in a monorepo the nearest package.json is a
/// workspace, not the repo, and adopting from `apps/web` should still find its
/// siblings.
fn find_root(start: &Path) -> Option<PathBuf> {
    let start = start.canonicalize().ok()?;
    let mut dir = Some(start.as_path());

    // The nearest package.json, used only if nothing better turns up. In a
    // monorepo that is a workspace rather than the repo, which is why it
    // loses to both of the checks below.
    let mut nearest_manifest: Option<PathBuf> = None;

    while let Some(current) = dir {
        if current.join(".git").exists() {
            return Some(current.to_path_buf());
        }
        // A workspace manifest is a repo root even without git.
        if !layout(current).1.is_empty() {
            return Some(current.to_path_buf());
        }
        if nearest_manifest.is_none() && has_manifest(current) {
            nearest_manifest = Some(current.to_path_buf());
        }
        dir = current.parent();
    }

    nearest_manifest
}

fn has_manifest(dir: &Path) -> bool {
    ["package.json", "Cargo.toml", "go.mod", "pyproject.toml"]
        .iter()
        .any(|f| dir.join(f).exists())
}

/// Which workspace layout this directory declares, and where its members are.
fn layout(root: &Path) -> (RepoKind, Vec<String>) {
    let read = |file: &str| std::fs::read_to_string(root.join(file)).ok();

    // pnpm's file is the most explicit, and turborepo sits on top of it.
    if let Some(raw) = read("pnpm-workspace.yaml") {
        let kind = if root.join("turbo.json").exists() {
            RepoKind::Turborepo
        } else {
            RepoKind::PnpmWorkspaces
        };
        return (kind, parse_pnpm_workspaces(&raw));
    }

    if let Some(raw) = read("package.json") {
        let patterns = parse_package_json_workspaces(&raw);
        if !patterns.is_empty() {
            let kind = if root.join("turbo.json").exists() {
                RepoKind::Turborepo
            } else if root.join("nx.json").exists() {
                RepoKind::Nx
            } else {
                RepoKind::NpmWorkspaces
            };
            return (kind, patterns);
        }
    }

    if let Some(raw) = read("Cargo.toml") {
        let patterns = parse_cargo_members(&raw);
        if !patterns.is_empty() {
            return (RepoKind::CargoWorkspace, patterns);
        }
    }

    if let Some(raw) = read("go.work") {
        let patterns = parse_go_work(&raw);
        if !patterns.is_empty() {
            return (RepoKind::GoWorkspace, patterns);
        }
    }

    (RepoKind::Single, Vec::new())
}

/// `packages:` followed by a YAML list. The file is essentially always this
/// shape, which is why it does not justify a YAML parser.
fn parse_pnpm_workspaces(raw: &str) -> Vec<String> {
    let mut patterns = Vec::new();
    let mut in_packages = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("packages:") {
            in_packages = true;
            continue;
        }
        if !in_packages {
            continue;
        }

        // A new top-level key ends the list.
        if !line.starts_with([' ', '\t', '-']) {
            break;
        }
        if let Some(item) = trimmed.strip_prefix('-') {
            let value = item.trim().trim_matches(['"', '\''].as_ref()).trim();
            if !value.is_empty() {
                patterns.push(value.to_string());
            }
        }
    }

    patterns
}

/// `"workspaces": [...]` or `"workspaces": { "packages": [...] }` (yarn v1).
fn parse_package_json_workspaces(raw: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let Some(workspaces) = value.get("workspaces") else {
        return Vec::new();
    };

    let array = workspaces
        .as_array()
        .or_else(|| workspaces.get("packages").and_then(|p| p.as_array()));

    array
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_cargo_members(raw: &str) -> Vec<String> {
    extract_toml_array(raw, "members")
}

/// `use ./a` or a `use ( ... )` block.
fn parse_go_work(raw: &str) -> Vec<String> {
    let mut patterns = Vec::new();
    let mut in_block = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("use (") {
            in_block = true;
            continue;
        }
        if in_block {
            if trimmed == ")" {
                in_block = false;
                continue;
            }
            if !trimmed.is_empty() && !trimmed.starts_with("//") {
                patterns.push(normalise_relative(trimmed));
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("use ") {
            patterns.push(normalise_relative(rest.trim()));
        }
    }

    patterns
}

fn normalise_relative(value: &str) -> String {
    value
        .trim_matches(['"', '\''].as_ref())
        .trim_start_matches("./")
        .to_string()
}

/// Pull a string array out of TOML without a TOML parser.
fn extract_toml_array(raw: &str, key: &str) -> Vec<String> {
    let Some(start) = raw
        .find(&format!("{key} "))
        .or_else(|| raw.find(&format!("{key}=")))
    else {
        return Vec::new();
    };
    let after = &raw[start..];
    let Some(open) = after.find('[') else {
        return Vec::new();
    };
    let Some(close) = after[open..].find(']') else {
        return Vec::new();
    };

    after[open + 1..open + close]
        .split(',')
        .map(|item| item.trim().trim_matches(['"', '\''].as_ref()).trim())
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// Expand a workspace glob into directories.
///
/// Supports the two forms workspace manifests actually use: a literal path, and
/// `*` / `**` as whole path segments.
fn expand(root: &Path, pattern: &str) -> Vec<PathBuf> {
    // Negations are rare and only ever subtract; ignoring them can include a
    // directory the user excluded, which the manifest check below usually
    // catches anyway.
    if pattern.starts_with('!') {
        return Vec::new();
    }

    let segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = vec![root.to_path_buf()];

    for segment in segments {
        let mut next = Vec::new();
        for dir in &current {
            match segment {
                "*" => next.extend(child_dirs(dir)),
                "**" => {
                    // Everything underneath, the directory itself included.
                    next.push(dir.clone());
                    collect_recursive(dir, &mut next, 0);
                }
                literal => {
                    let candidate = dir.join(literal);
                    if candidate.is_dir() {
                        next.push(candidate);
                    }
                }
            }
        }
        current = next;
    }

    current
}

fn child_dirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .filter(|p| {
            // node_modules under a glob would be thousands of pointless stats.
            !matches!(
                p.file_name().and_then(|n| n.to_str()),
                Some("node_modules") | Some(".git") | Some("target") | Some("dist")
            )
        })
        .collect()
}

fn collect_recursive(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    // `**` in a workspace manifest never means "the whole disk".
    if depth >= 4 {
        return;
    }
    for child in child_dirs(dir) {
        collect_recursive(&child, out, depth + 1);
        out.push(child);
    }
}

/// The name a directory's manifest declares.
///
/// `Some(None)` means "this is a package but it has no name", which is still a
/// package; `None` means "not a package at all".
fn manifest_name(dir: &Path) -> Option<Option<String>> {
    if let Ok(raw) = std::fs::read_to_string(dir.join("package.json")) {
        let name = serde_json::from_str::<serde_json::Value>(&raw)
            .ok()
            .and_then(|v| v.get("name")?.as_str().map(str::to_string));
        return Some(name);
    }
    for file in ["Cargo.toml", "pyproject.toml", "go.mod"] {
        if dir.join(file).exists() {
            return Some(None);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    /// A turborepo the way one actually looks on disk.
    fn turborepo() -> tempfile::TempDir {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path();

        std::fs::create_dir_all(root.join(".git")).unwrap();
        write(&root.join("turbo.json"), r#"{"tasks":{"dev":{}}}"#);
        write(
            &root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'apps/*'\n  - 'packages/*'\n",
        );
        write(
            &root.join("package.json"),
            r#"{"name":"acme","private":true}"#,
        );

        write(
            &root.join("apps/web/package.json"),
            r#"{"name":"@acme/web"}"#,
        );
        write(
            &root.join("apps/docs/package.json"),
            r#"{"name":"@acme/docs"}"#,
        );
        write(
            &root.join("packages/ui/package.json"),
            r#"{"name":"@acme/ui"}"#,
        );
        repo
    }

    #[test]
    fn finds_turborepo_workspaces_through_pnpm() {
        let repo = turborepo();
        let found = discover(repo.path()).expect("should discover the repo");

        assert_eq!(found.kind, RepoKind::Turborepo);
        let names: Vec<&str> = found.workspaces.iter().map(|w| w.rel.as_str()).collect();
        assert!(names.contains(&"apps/web"));
        assert!(names.contains(&"apps/docs"));
        assert!(names.contains(&"packages/ui"));
    }

    #[test]
    fn adopting_from_inside_a_workspace_still_finds_its_siblings() {
        let repo = turborepo();
        // Running `ports adopt` from apps/web must not treat apps/web as the
        // whole repo — that is what the .git check is for.
        let found = discover(&repo.path().join("apps/web")).expect("should walk up to the repo");

        assert_eq!(found.kind, RepoKind::Turborepo);
        assert!(found.workspaces.iter().any(|w| w.rel == "apps/docs"));
    }

    #[test]
    fn reads_npm_and_yarn_workspace_declarations() {
        assert_eq!(
            parse_package_json_workspaces(r#"{"workspaces":["apps/*"]}"#),
            vec!["apps/*"]
        );
        // yarn v1's nested form.
        assert_eq!(
            parse_package_json_workspaces(r#"{"workspaces":{"packages":["packages/*"]}}"#),
            vec!["packages/*"]
        );
        assert!(parse_package_json_workspaces(r#"{"name":"x"}"#).is_empty());
    }

    #[test]
    fn reads_a_pnpm_workspace_file() {
        let raw = "packages:\n  - 'apps/*'\n  # a comment\n  - \"packages/*\"\n";
        assert_eq!(parse_pnpm_workspaces(raw), vec!["apps/*", "packages/*"]);

        // A following top-level key ends the list rather than being swallowed.
        let with_more = "packages:\n  - 'apps/*'\nonlyBuiltDependencies:\n  - esbuild\n";
        assert_eq!(parse_pnpm_workspaces(with_more), vec!["apps/*"]);
    }

    #[test]
    fn reads_cargo_and_go_workspaces() {
        assert_eq!(
            parse_cargo_members("[workspace]\nmembers = [\"crates/*\", \"tools/cli\"]"),
            vec!["crates/*", "tools/cli"]
        );
        assert_eq!(
            parse_go_work("go 1.22\n\nuse (\n\t./api\n\t./worker\n)\n"),
            vec!["api", "worker"]
        );
        assert_eq!(parse_go_work("use ./single\n"), vec!["single"]);
    }

    #[test]
    fn a_plain_project_is_its_own_single_workspace() {
        let repo = tempfile::tempdir().unwrap();
        write(&repo.path().join("package.json"), r#"{"name":"solo"}"#);

        let found = discover(repo.path()).unwrap();
        assert_eq!(found.kind, RepoKind::Single);
        assert_eq!(found.workspaces.len(), 1);
        assert_eq!(found.workspaces[0].rel, ".");
        assert_eq!(found.workspaces[0].package_name.as_deref(), Some("solo"));
    }

    #[test]
    fn glob_expansion_skips_directories_that_are_not_packages() {
        let repo = tempfile::tempdir().unwrap();
        write(
            &repo.path().join("package.json"),
            r#"{"workspaces":["apps/*"]}"#,
        );
        write(
            &repo.path().join("apps/real/package.json"),
            r#"{"name":"real"}"#,
        );
        // A stray directory with no manifest is not a workspace.
        std::fs::create_dir_all(repo.path().join("apps/not-a-package")).unwrap();

        let found = discover(repo.path()).unwrap();
        let names: Vec<&str> = found.workspaces.iter().map(|w| w.rel.as_str()).collect();
        assert!(names.contains(&"apps/real"));
        assert!(!names.contains(&"apps/not-a-package"));
    }

    #[test]
    fn node_modules_is_never_walked() {
        let repo = tempfile::tempdir().unwrap();
        write(&repo.path().join("package.json"), r#"{"workspaces":["*"]}"#);
        write(
            &repo.path().join("node_modules/some-dep/package.json"),
            r#"{"name":"some-dep"}"#,
        );

        let found = discover(repo.path()).unwrap();
        assert!(
            !found
                .workspaces
                .iter()
                .any(|w| w.rel.contains("node_modules")),
            "node_modules must not be treated as a workspace"
        );
    }
}
