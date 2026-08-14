//! Resolve the process behind a port: what it is, where it runs, and which
//! project it belongs to.
//!
//! The project name is the column that makes the listing useful — "3000" tells
//! you nothing, "3000 acme-web" tells you which repo to go and stop.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, Users};

use crate::types::{ProcessInfo, ProjectType};

/// Manifest files that name a project, in the order we trust them.
const MANIFESTS: &[(&str, ProjectType)] = &[
    ("package.json", ProjectType::Node),
    ("pyproject.toml", ProjectType::Python),
    ("Cargo.toml", ProjectType::Rust),
    ("go.mod", ProjectType::Go),
    ("composer.json", ProjectType::Php),
    ("Gemfile", ProjectType::Ruby),
];

/// How far up from cwd to look. A dev server is often started from a
/// subdirectory of the repo, so checking only cwd would miss the name.
const MAX_WALK_DEPTH: usize = 5;

fn parse_json_name(raw: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let name = value.get("name")?.as_str()?.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// Good enough for `name = "x"` under [project], [package] or top level.
fn parse_toml_name(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("name") else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let value = rest.trim().trim_matches(['"', '\''].as_ref()).trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

fn parse_go_module(raw: &str) -> Option<String> {
    let line = raw.lines().find_map(|l| l.trim().strip_prefix("module "))?;
    let module = line.trim();
    // Module paths are URLs; the last segment is the useful label.
    Some(module.rsplit('/').next().unwrap_or(module).to_string())
}

fn parse_manifest(file: &str, raw: &str) -> Option<String> {
    match file {
        "package.json" | "composer.json" => parse_json_name(raw),
        "pyproject.toml" | "Cargo.toml" => parse_toml_name(raw),
        "go.mod" => parse_go_module(raw),
        // A Gemfile names dependencies, not the project.
        _ => None,
    }
}

pub struct Project {
    pub name: Option<String>,
    pub project_type: ProjectType,
    pub root: PathBuf,
}

/// Walk up from a directory looking for a project manifest.
pub fn detect_project(cwd: &Path) -> Option<Project> {
    let mut dir = cwd;

    for _ in 0..MAX_WALK_DEPTH {
        for (file, project_type) in MANIFESTS {
            let path = dir.join(file);
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            let name = parse_manifest(file, &raw).or_else(|| {
                // A manifest with no name still tells us where the project is.
                dir.file_name().and_then(|n| n.to_str()).map(str::to_string)
            });
            return Some(Project {
                name,
                project_type: *project_type,
                root: dir.to_path_buf(),
            });
        }

        dir = dir.parent()?;
    }

    None
}

/// Resolve pids to command, cwd and owning project.
///
/// Batched deliberately: this runs for every listener on every scan, and
/// resolving them one at a time would dominate scan time.
pub fn enrich_processes(pids: &[u32]) -> HashMap<u32, ProcessInfo> {
    let mut result = HashMap::new();

    let mut unique: Vec<u32> = pids.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.is_empty() {
        return result;
    }

    let sysinfo_pids: Vec<Pid> = unique.iter().map(|p| Pid::from_u32(*p)).collect();
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&sysinfo_pids),
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(sysinfo::UpdateKind::Always)
            .with_cwd(sysinfo::UpdateKind::Always)
            .with_user(sysinfo::UpdateKind::Always)
            .with_exe(sysinfo::UpdateKind::Always),
    );

    let users = Users::new_with_refreshed_list();

    for pid in unique {
        let Some(process) = system.process(Pid::from_u32(pid)) else {
            continue;
        };

        let mut info = ProcessInfo {
            pid,
            ..Default::default()
        };

        let command: Vec<String> = process
            .cmd()
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        if !command.is_empty() {
            info.command = Some(command.join(" "));
        }

        // Prefer the executable's basename: `name()` comes from the kernel's
        // comm field, which several platforms truncate.
        info.name = process
            .exe()
            .and_then(|exe| exe.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .or_else(|| Some(process.name().to_string_lossy().into_owned()));

        info.user = process
            .user_id()
            .and_then(|uid| users.get_user_by_id(uid))
            .map(|user| user.name().to_string());

        // `/` is every GUI app's cwd and tells us nothing about a project.
        if let Some(cwd) = process.cwd().filter(|c| c.as_os_str() != "/") {
            info.cwd = Some(cwd.to_string_lossy().into_owned());

            if let Some(project) = detect_project(cwd) {
                info.project_name = project.name;
                info.project_type = Some(project.project_type);
                info.project_root = Some(project.root.to_string_lossy().into_owned());
            }
        }

        result.insert(pid, info);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_name_out_of_each_manifest_format() {
        assert_eq!(
            parse_manifest("package.json", r#"{"name": "acme-web"}"#),
            Some("acme-web".into())
        );
        assert_eq!(
            parse_manifest("Cargo.toml", "[package]\nname = \"ports\"\nversion = \"1\""),
            Some("ports".into())
        );
        assert_eq!(
            parse_manifest("pyproject.toml", "[project]\nname = 'svc'"),
            Some("svc".into())
        );
        assert_eq!(
            parse_manifest("go.mod", "module github.com/acme/gateway\n\ngo 1.22"),
            Some("gateway".into())
        );
    }

    #[test]
    fn a_malformed_manifest_is_not_worth_failing_over() {
        assert_eq!(parse_manifest("package.json", "{not json"), None);
        assert_eq!(parse_manifest("Cargo.toml", "nothing here"), None);
    }

    #[test]
    fn walks_up_from_a_subdirectory_to_find_the_manifest() {
        // A dev server started from src/routes still belongs to the repo above.
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("package.json"), r#"{"name":"acme-web"}"#).unwrap();
        let deep = repo.path().join("src/routes");
        std::fs::create_dir_all(&deep).unwrap();

        let project = detect_project(&deep).expect("should walk up to the manifest");
        assert_eq!(project.name.as_deref(), Some("acme-web"));
        assert_eq!(project.project_type, ProjectType::Node);
        assert_eq!(project.root, repo.path());
    }

    #[test]
    fn prefers_the_nearest_manifest_over_one_further_up() {
        // In a monorepo the workspace owns the server, not the repo root.
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("package.json"), r#"{"name":"acme"}"#).unwrap();
        let app = repo.path().join("apps/web");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("package.json"), r#"{"name":"@acme/web"}"#).unwrap();

        let project = detect_project(&app).unwrap();
        assert_eq!(project.name.as_deref(), Some("@acme/web"));
        assert_eq!(project.root, app);
    }

    #[test]
    fn gives_up_rather_than_walking_to_the_filesystem_root() {
        let empty = tempfile::tempdir().unwrap();
        let deep = empty.path().join("a/b/c/d/e/f/g");
        std::fs::create_dir_all(&deep).unwrap();
        assert!(detect_project(&deep).is_none());
    }

    #[test]
    fn enriches_the_current_process() {
        let pid = std::process::id();
        let enriched = enrich_processes(&[pid]);
        let info = enriched.get(&pid).expect("our own process is visible");
        assert_eq!(info.pid, pid);
        assert!(info.name.is_some(), "should resolve an executable name");
    }
}
