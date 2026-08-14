//! Work out which port a workspace *would* serve on, without running it.
//!
//! Only ever a fallback. A running server tells us its real port; this is for
//! the cold case, where guessing wrong is worse than saying nothing, so
//! anything not actually declared somewhere is left unresolved rather than
//! filled in with a hopeful default.

use std::path::Path;

/// Where a port came from, so the preview can show how much to trust it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSource {
    /// Observed on a process whose cwd is in this workspace.
    Running,
    /// `PORT=` in a .env file.
    DotEnv,
    /// A `--port` flag in the dev script.
    DevScript,
    /// `server.port` in a framework config.
    FrameworkConfig,
    /// The framework's documented default, from its dependency entry.
    FrameworkDefault,
}

impl PortSource {
    pub fn label(self) -> &'static str {
        match self {
            PortSource::Running => "running",
            PortSource::DotEnv => ".env",
            PortSource::DevScript => "dev script",
            PortSource::FrameworkConfig => "config",
            PortSource::FrameworkDefault => "default",
        }
    }
}

/// Frameworks whose default dev port is well-known and stable.
const FRAMEWORK_DEFAULTS: &[(&str, u16)] = &[
    ("next", 3000),
    ("nuxt", 3000),
    ("@remix-run/dev", 3000),
    ("@nestjs/core", 3000),
    ("@sveltejs/kit", 5173),
    ("vite", 5173),
    ("astro", 4321),
    ("@angular/cli", 4200),
    ("gatsby", 8000),
    ("@storybook/react", 6006),
];

fn valid(port: u32) -> Option<u16> {
    (port >= 1 && port <= 65535).then_some(port as u16)
}

/// Read `PORT=` out of the .env files a dev server would load.
fn from_dotenv(dir: &Path) -> Option<u16> {
    // Ordered the way most loaders resolve precedence, most specific first.
    for file in [".env.development.local", ".env.local", ".env.development", ".env"] {
        let Ok(raw) = std::fs::read_to_string(dir.join(file)) else {
            continue;
        };
        for line in raw.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() != "PORT" {
                continue;
            }
            let value = value.trim().trim_matches(['"', '\''].as_ref()).trim();
            if let Some(port) = value.parse().ok().and_then(valid) {
                return Some(port);
            }
        }
    }
    None
}

/// Pull a port out of a command line: `--port 3001`, `--port=3001`, `-p 3001`,
/// or a `PORT=3001` prefix.
pub fn port_from_command(command: &str) -> Option<u16> {
    let tokens: Vec<&str> = command.split_whitespace().collect();

    for (index, token) in tokens.iter().enumerate() {
        let candidate = if let Some(value) = token.strip_prefix("--port=") {
            Some(value)
        } else if let Some(value) = token.strip_prefix("PORT=") {
            Some(value)
        } else if *token == "--port" || *token == "-p" {
            tokens.get(index + 1).copied()
        } else {
            None
        };

        if let Some(port) = candidate.and_then(|c| c.parse().ok()).and_then(valid) {
            return Some(port);
        }
    }

    None
}

/// `server: { port: 3001 }` in a vite/astro config.
fn port_from_config_source(raw: &str) -> Option<u16> {
    // Look for `port:` inside the source. Narrow enough in practice: these
    // config files are small and rarely mention a port for anything else.
    let mut search = raw;
    while let Some(index) = search.find("port:") {
        let after = &search[index + 5..];
        let digits: String = after
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Some(port) = digits.parse().ok().and_then(valid) {
            return Some(port);
        }
        search = after;
    }
    None
}

fn from_framework_config(dir: &Path) -> Option<u16> {
    for stem in ["vite.config", "astro.config", "nuxt.config", "svelte.config"] {
        for ext in ["ts", "js", "mjs", "mts", "cjs"] {
            let Ok(raw) = std::fs::read_to_string(dir.join(format!("{stem}.{ext}"))) else {
                continue;
            };
            if let Some(port) = port_from_config_source(&raw) {
                return Some(port);
            }
        }
    }
    None
}

struct PackageJson {
    dev_script: Option<String>,
    dependencies: Vec<String>,
}

fn read_package_json(dir: &Path) -> Option<PackageJson> {
    let raw = std::fs::read_to_string(dir.join("package.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;

    let dev_script = ["dev", "start", "serve"]
        .iter()
        .find_map(|name| value.get("scripts")?.get(name)?.as_str().map(str::to_string));

    let mut dependencies = Vec::new();
    for section in ["dependencies", "devDependencies"] {
        if let Some(map) = value.get(section).and_then(|d| d.as_object()) {
            dependencies.extend(map.keys().cloned());
        }
    }

    Some(PackageJson {
        dev_script,
        dependencies,
    })
}

/// Best guess at the port this workspace serves on, and where the guess came from.
pub fn infer_port(dir: &Path) -> Option<(u16, PortSource)> {
    // An explicit PORT beats everything: it is what the dev server will read.
    if let Some(port) = from_dotenv(dir) {
        return Some((port, PortSource::DotEnv));
    }

    let package = read_package_json(dir);

    if let Some(port) = package
        .as_ref()
        .and_then(|p| p.dev_script.as_deref())
        .and_then(port_from_command)
    {
        return Some((port, PortSource::DevScript));
    }

    if let Some(port) = from_framework_config(dir) {
        return Some((port, PortSource::FrameworkConfig));
    }

    // Last resort, and only for frameworks whose default is actually stable.
    if let Some(package) = package {
        for (name, port) in FRAMEWORK_DEFAULTS {
            if package.dependencies.iter().any(|d| d == name) {
                return Some((*port, PortSource::FrameworkDefault));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, contents) in files {
            let path = dir.path().join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, contents).unwrap();
        }
        dir
    }

    #[test]
    fn reads_port_from_a_dev_script() {
        assert_eq!(port_from_command("next dev --port 3001"), Some(3001));
        assert_eq!(port_from_command("next dev --port=3002"), Some(3002));
        assert_eq!(port_from_command("vite --host -p 5180"), Some(5180));
        assert_eq!(port_from_command("PORT=4500 node server.js"), Some(4500));
        assert_eq!(port_from_command("next dev"), None);
    }

    #[test]
    fn does_not_mistake_other_numbers_for_a_port() {
        assert_eq!(port_from_command("node --max-old-space-size=4096 x.js"), None);
        assert_eq!(port_from_command("tsc -p tsconfig.json"), None);
    }

    #[test]
    fn dotenv_beats_the_dev_script() {
        // The dev server reads PORT at runtime, so it wins over the flag.
        let dir = dir_with(&[
            (".env", "PORT=4500\n"),
            ("package.json", r#"{"scripts":{"dev":"next dev --port 3001"}}"#),
        ]);
        assert_eq!(infer_port(dir.path()), Some((4500, PortSource::DotEnv)));
    }

    #[test]
    fn a_more_specific_dotenv_wins() {
        let dir = dir_with(&[(".env", "PORT=3000\n"), (".env.local", "PORT=3999\n")]);
        assert_eq!(infer_port(dir.path()), Some((3999, PortSource::DotEnv)));
    }

    #[test]
    fn ignores_commented_out_and_unrelated_env_lines() {
        let dir = dir_with(&[(
            ".env",
            "# PORT=1111\nDATABASE_PORT=5432\nOTHER=x\nexport PORT=\"7777\"\n",
        )]);
        assert_eq!(infer_port(dir.path()), Some((7777, PortSource::DotEnv)));
    }

    #[test]
    fn reads_a_vite_config_port() {
        let dir = dir_with(&[
            ("package.json", r#"{"scripts":{"dev":"vite"}}"#),
            ("vite.config.ts", "export default { server: { port: 5180 } }"),
        ]);
        assert_eq!(
            infer_port(dir.path()),
            Some((5180, PortSource::FrameworkConfig))
        );
    }

    #[test]
    fn falls_back_to_a_framework_default() {
        let dir = dir_with(&[(
            "package.json",
            r#"{"scripts":{"dev":"next dev"},"dependencies":{"next":"15.0.0"}}"#,
        )]);
        assert_eq!(
            infer_port(dir.path()),
            Some((3000, PortSource::FrameworkDefault))
        );
    }

    #[test]
    fn a_library_workspace_yields_nothing_rather_than_a_guess() {
        // packages/ui has no dev server; inventing a port for it would put a
        // dead binding in the table.
        let dir = dir_with(&[(
            "package.json",
            r#"{"name":"@acme/ui","main":"index.ts","devDependencies":{"typescript":"5"}}"#,
        )]);
        assert_eq!(infer_port(dir.path()), None);
    }

    #[test]
    fn an_empty_directory_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(infer_port(dir.path()), None);
    }
}
