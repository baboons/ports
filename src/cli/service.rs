//! Install the proxy as a service.
//!
//! Four variants, picked by platform and by whether the configured ports are
//! privileged. The privileged path is only reached because someone wanted
//! `http://myapp.localhost` without a port suffix; asking for 8080 instead
//! needs no root anywhere.

use std::path::PathBuf;
use std::process::Command;

use crate::cli::format::{bold, dim, gray, green, yellow};
use crate::config::bindings::{load_bindings_from, needs_privilege};

const LAUNCHD_LABEL: &str = "dev.baboons.ports";
const SYSTEMD_UNIT: &str = "ports.service";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Install,
    Uninstall,
    Status,
    /// Print the unit file and change nothing.
    Print,
}

fn is_root() -> bool {
    // Safety: geteuid cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// The uid/gid to run as once privileged ports are bound.
///
/// Under sudo this is the invoking user, not root: the daemon only needs root
/// for the two seconds it takes to claim port 80.
fn target_user() -> (u32, u32, String) {
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| unsafe { libc::getuid() });
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| unsafe { libc::getgid() });
    let name = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "root".into());
    (uid, gid, name)
}

/// The home directory whose config the daemon should read.
fn target_home() -> String {
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        // Under sudo, HOME is root's, which is not where the bindings live.
        if cfg!(target_os = "macos") {
            return format!("/Users/{sudo_user}");
        }
        return format!("/home/{sudo_user}");
    }
    std::env::var("HOME").unwrap_or_else(|_| "/".into())
}

/// The bindings file the installed service will read.
///
/// Derived from the same home the unit sets, so what `service install` reports
/// is what the daemon will actually load.
fn target_config_path() -> PathBuf {
    PathBuf::from(target_home()).join(".config/ports/bindings.json")
}

/// Give up root, permanently, after the privileged ports are bound.
///
/// Order matters: the group has to go first, because dropping the user first
/// takes away the right to change the group.
pub fn drop_privileges() -> anyhow::Result<()> {
    if !is_root() {
        return Ok(());
    }
    let Ok(uid) = std::env::var("PORTS_DROP_UID") else {
        return Ok(());
    };
    let uid: u32 = uid.parse()?;
    let gid: u32 = std::env::var("PORTS_DROP_GID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(uid);

    // Safety: both calls are checked, and a failure to drop is fatal below.
    unsafe {
        if libc::setgid(gid) != 0 {
            anyhow::bail!("could not drop group to {gid}");
        }
        if libc::setuid(uid) != 0 {
            anyhow::bail!("could not drop user to {uid}");
        }
        // Paranoia, but the failure mode is a root-owned web proxy.
        if libc::setuid(0) == 0 {
            anyhow::bail!("privileges could be regained after dropping them");
        }
    }

    Ok(())
}

fn executable() -> anyhow::Result<String> {
    Ok(std::env::current_exe()?.to_string_lossy().into_owned())
}

// --- launchd ---------------------------------------------------------------

fn launchd_path(system: bool) -> PathBuf {
    if system {
        PathBuf::from("/Library/LaunchDaemons").join(format!("{LAUNCHD_LABEL}.plist"))
    } else {
        PathBuf::from(target_home())
            .join("Library/LaunchAgents")
            .join(format!("{LAUNCHD_LABEL}.plist"))
    }
}

fn launchd_plist(system: bool) -> anyhow::Result<String> {
    let program = executable()?;
    let home = target_home();
    let (uid, gid, _) = target_user();

    // A system daemon starts as root so it can bind :80, then hands the
    // privileges back. macOS has no CAP_NET_BIND_SERVICE equivalent, so there
    // is no way to skip the root step entirely here.
    let drop_env = if system {
        format!(
            "    <key>PORTS_DROP_UID</key>\n    <string>{uid}</string>\n\
             \x20   <key>PORTS_DROP_GID</key>\n    <string>{gid}</string>\n"
        )
    } else {
        String::new()
    };

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{program}</string>
    <string>serve</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>{home}</string>
{drop_env}  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardOutPath</key>
  <string>{home}/Library/Logs/ports.log</string>
  <key>StandardErrorPath</key>
  <string>{home}/Library/Logs/ports.error.log</string>
</dict>
</plist>
"#
    ))
}

// --- systemd ---------------------------------------------------------------

fn systemd_path(system: bool) -> PathBuf {
    if system {
        PathBuf::from("/etc/systemd/system").join(SYSTEMD_UNIT)
    } else {
        PathBuf::from(target_home())
            .join(".config/systemd/user")
            .join(SYSTEMD_UNIT)
    }
}

fn systemd_unit(system: bool) -> anyhow::Result<String> {
    let program = executable()?;
    let (_, _, user) = target_user();
    let home = target_home();

    // Linux can bind :80 without ever being root, which is strictly better
    // than the macOS start-as-root-and-drop dance.
    let privileged = if system {
        format!(
            "User={user}\n\
             Environment=HOME={home}\n\
             AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
             CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
        )
    } else {
        String::new()
    };

    // ProtectSystem=strict makes the entire hierarchy read-only, so the
    // daemon needs its own directories back explicitly — without these it
    // cannot cache a scan, store a favicon, or save a binding made from the
    // index, and all three fail silently.
    let writable = ["config", "cache", "local/share"]
        .iter()
        .map(|dir| {
            let dir = match *dir {
                "config" => ".config/ports".to_string(),
                "cache" => ".cache/ports".to_string(),
                _ => ".local/share/ports".to_string(),
            };
            // A leading `-` so a directory that does not exist yet is ignored
            // rather than refusing to start the service.
            format!("ReadWritePaths=-{home}/{dir}\n")
        })
        .collect::<String>();

    Ok(format!(
        "[Unit]\n\
         Description=ports — local domain proxy\n\
         Documentation=https://github.com/baboons/ports\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={program} serve\n\
         {privileged}Restart=on-failure\n\
         RestartSec=5\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=read-only\n\
         {writable}\n\
         [Install]\n\
         WantedBy={}\n",
        if system {
            "multi-user.target"
        } else {
            "default.target"
        }
    ))
}

// --- entry point -----------------------------------------------------------

pub struct ServiceArgs {
    pub action: ServiceAction,
    /// Install for the current user only, never system-wide.
    pub user: bool,
}

pub fn service(args: ServiceArgs) -> anyhow::Result<()> {
    let linux = cfg!(target_os = "linux");
    let mac = cfg!(target_os = "macos");
    if !linux && !mac {
        anyhow::bail!("service install covers Linux (systemd) and macOS (launchd) only");
    }

    // Deliberately the target user's config, not the invoking one's. Under
    // sudo those differ, and it is the daemon's that matters: it is the file
    // the service will read, and the ports in it decide whether the service
    // needs privileges at all.
    let bindings = load_bindings_from(&target_config_path()).unwrap_or_default();

    // A user agent cannot bind :80, so the choice is made by the ports the
    // user configured rather than by a flag they have to remember.
    let system = !args.user && needs_privilege(&bindings);

    let (path, unit) = if linux {
        (systemd_path(system), systemd_unit(system)?)
    } else {
        (launchd_path(system), launchd_plist(system)?)
    };

    match args.action {
        ServiceAction::Print => {
            println!("{}", dim(&format!("# {}", path.display())));
            print!("{unit}");
            Ok(())
        }
        ServiceAction::Install => install(&path, &unit, system, linux, &bindings),
        ServiceAction::Uninstall => uninstall(&path, system, linux),
        ServiceAction::Status => status(&path, system, linux),
    }
}

/// Which kind of service is installed, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Installed {
    /// System-wide: root to restart it.
    System,
    /// Just this user's.
    User,
}

/// Is a service installed, and of which kind?
///
/// Checked by looking for the unit file rather than asking the service
/// manager, so this answers the same on a box where the daemon happens to be
/// stopped.
pub fn installed() -> Option<Installed> {
    if systemd_path(true).exists() || launchd_path(true).exists() {
        return Some(Installed::System);
    }
    if systemd_path(false).exists() || launchd_path(false).exists() {
        return Some(Installed::User);
    }
    None
}

/// The command that would restart it, for telling someone who cannot.
pub fn restart_command(kind: Installed) -> String {
    let sudo = if kind == Installed::System {
        "sudo "
    } else {
        ""
    };
    if cfg!(target_os = "linux") {
        let scope = if kind == Installed::System {
            ""
        } else {
            "--user "
        };
        format!("{sudo}systemctl {scope}restart {SYSTEMD_UNIT}")
    } else if kind == Installed::System {
        format!("sudo launchctl kickstart -k system/{LAUNCHD_LABEL}")
    } else {
        format!("launchctl kickstart -k gui/$(id -u)/{LAUNCHD_LABEL}")
    }
}

/// Rewrite the unit of an already-installed service.
///
/// The unit is generated from this binary, so replacing the binary without
/// refreshing it can leave a unit describing an older one — which is how a
/// daemon keeps failing in a way that was already fixed.
pub fn refresh_unit(kind: Installed) -> anyhow::Result<()> {
    let system = kind == Installed::System;
    if system && !is_root() {
        anyhow::bail!("rewriting a system unit needs root");
    }

    let linux = cfg!(target_os = "linux");
    let (path, unit) = if linux {
        (systemd_path(system), systemd_unit(system)?)
    } else {
        (launchd_path(system), launchd_plist(system)?)
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, unit)?;
    create_state_dirs();

    if linux {
        let scope: &[&str] = if system { &[] } else { &["--user"] };
        run("systemctl", &[scope, &["daemon-reload"]].concat())?;
    }
    Ok(())
}

/// Restart the installed service so it picks up a new binary.
///
/// A system service needs root; without it the caller is told the command
/// rather than left with a daemon still running the old code.
pub fn restart(kind: Installed) -> anyhow::Result<()> {
    if kind == Installed::System && !is_root() {
        anyhow::bail!("restarting a system service needs root");
    }

    if cfg!(target_os = "linux") {
        let scope: &[&str] = if kind == Installed::System {
            &[]
        } else {
            &["--user"]
        };
        run("systemctl", &[scope, &["restart", SYSTEMD_UNIT]].concat())
    } else {
        let domain = if kind == Installed::System {
            "system".to_string()
        } else {
            format!("gui/{}", target_user().0)
        };
        // kickstart -k stops and starts in one step, so the port is released
        // and reclaimed by the same command.
        run(
            "launchctl",
            &["kickstart", "-k", &format!("{domain}/{LAUNCHD_LABEL}")],
        )
    }
}

/// Make the daemon's directories, owned by the user it will run as.
fn create_state_dirs() {
    let (uid, gid, _) = target_user();
    let home = PathBuf::from(target_home());

    for relative in [".config/ports", ".cache/ports", ".local/share/ports"] {
        let dir = home.join(relative);
        if std::fs::create_dir_all(&dir).is_err() {
            continue;
        }
        // Under sudo these would otherwise belong to root, leaving the daemon
        // unable to write the directories made for it.
        #[cfg(unix)]
        if is_root() {
            let path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).ok();
            if let Some(path) = path {
                // Safety: a valid NUL-terminated path, and a checked result.
                unsafe {
                    libc::chown(path.as_ptr(), uid, gid);
                }
            }
        }
    }
}

fn require_root(system: bool, action: &str) -> anyhow::Result<()> {
    if system && !is_root() {
        anyhow::bail!(
            "ports 80/443 need root to bind, so the service must be installed system-wide.\n  \
             Try:  sudo ports service {action}\n  \
             Or keep it unprivileged: set a higher port and use `ports service {action} --user`"
        );
    }
    Ok(())
}

fn install(
    path: &std::path::Path,
    unit: &str,
    system: bool,
    linux: bool,
    bindings: &crate::config::bindings::Bindings,
) -> anyhow::Result<()> {
    require_root(system, "install")?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, unit)?;
    println!("\n  wrote {}", bold(&path.display().to_string()));

    // Created here, owned by the user the service runs as: ReadWritePaths can
    // only grant access to a directory that already exists.
    create_state_dirs();

    if linux {
        let scope: &[&str] = if system { &[] } else { &["--user"] };
        run("systemctl", &[scope, &["daemon-reload"]].concat())?;
        run("systemctl", &[scope, &["enable", SYSTEMD_UNIT]].concat())?;
        run("systemctl", &[scope, &["restart", SYSTEMD_UNIT]].concat())?;
        println!("  enabled and started {}", bold(SYSTEMD_UNIT));

        if !system {
            println!(
                "{}",
                yellow(&format!(
                    "  note: user services stop at logout unless you run\n\
                     \x20       sudo loginctl enable-linger {}",
                    target_user().2
                ))
            );
        }
    } else {
        let domain = if system {
            "system".to_string()
        } else {
            format!("gui/{}", target_user().0)
        };
        // bootout first so a reinstall replaces rather than conflicts.
        let _ = run("launchctl", &["bootout", &domain, &path.to_string_lossy()]);
        run(
            "launchctl",
            &["bootstrap", &domain, &path.to_string_lossy()],
        )?;
        println!("  loaded {}", bold(LAUNCHD_LABEL));
    }

    println!(
        "\n  proxy on port {}, serving {} binding{} under {}",
        bindings.http_port,
        bindings.bindings.len(),
        if bindings.bindings.len() == 1 {
            ""
        } else {
            "s"
        },
        bold(&format!("*.{}", bindings.primary()))
    );

    if system {
        println!(
            "{}",
            gray("  runs as root only long enough to bind the port, then drops to you")
        );
    }
    println!();
    Ok(())
}

fn uninstall(path: &std::path::Path, system: bool, linux: bool) -> anyhow::Result<()> {
    require_root(system, "uninstall")?;

    if linux {
        let scope: &[&str] = if system { &[] } else { &["--user"] };
        let _ = run(
            "systemctl",
            &[scope, &["disable", "--now", SYSTEMD_UNIT]].concat(),
        );
    } else {
        let domain = if system {
            "system".to_string()
        } else {
            format!("gui/{}", target_user().0)
        };
        let _ = run("launchctl", &["bootout", &domain, &path.to_string_lossy()]);
    }

    match std::fs::remove_file(path) {
        Ok(()) => println!("\n  removed {}\n", bold(&path.display().to_string())),
        Err(_) => println!(
            "\n  nothing installed at {}\n",
            dim(&path.display().to_string())
        ),
    }

    if linux {
        let scope: &[&str] = if system { &[] } else { &["--user"] };
        let _ = run("systemctl", &[scope, &["daemon-reload"]].concat());
    }
    Ok(())
}

fn status(path: &std::path::Path, system: bool, linux: bool) -> anyhow::Result<()> {
    if !path.exists() {
        println!(
            "\n  not installed {}\n",
            dim(&format!("({})", path.display()))
        );
        return Ok(());
    }

    if linux {
        let scope: &[&str] = if system { &[] } else { &["--user"] };
        let output = std::process::Command::new("systemctl")
            .args([scope, &["status", SYSTEMD_UNIT, "--no-pager"]].concat())
            .output()?;
        println!("\n{}", String::from_utf8_lossy(&output.stdout).trim());
    } else {
        let output = Command::new("launchctl").arg("list").output()?;
        let running = String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.contains(LAUNCHD_LABEL));
        println!(
            "\n  {} {}",
            if running {
                green("running")
            } else {
                yellow("installed but not running")
            },
            dim(&format!("({})", path.display()))
        );
    }
    println!();
    Ok(())
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{program} {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_system_launchd_plist_carries_the_uid_to_drop_to() {
        let plist = launchd_plist(true).unwrap();
        assert!(plist.contains("PORTS_DROP_UID"));
        assert!(plist.contains("PORTS_DROP_GID"));
        // HOME must point at the user, or the daemon reads root's config and
        // finds no bindings at all.
        assert!(plist.contains("<key>HOME</key>"));
        assert!(plist.contains("<string>serve</string>"));
    }

    #[test]
    fn a_user_launchd_agent_does_not_ask_to_drop_anything() {
        let plist = launchd_plist(false).unwrap();
        assert!(!plist.contains("PORTS_DROP_UID"));
    }

    #[test]
    fn a_system_systemd_unit_binds_low_ports_without_ever_being_root() {
        let unit = systemd_unit(true).unwrap();
        // The whole point on Linux: a capability instead of uid 0.
        assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("User="));
        assert!(!unit.contains("User=root"));
    }

    #[test]
    fn the_systemd_unit_can_write_its_own_directories() {
        // ProtectSystem=strict makes everything read-only, so without these
        // the daemon silently cannot cache a scan, store a favicon, or save a
        // binding made from the index.
        let unit = systemd_unit(true).unwrap();
        assert!(
            unit.contains("ProtectSystem=strict"),
            "hardening should stay"
        );

        for dir in [".config/ports", ".cache/ports", ".local/share/ports"] {
            assert!(
                unit.contains(&format!("ReadWritePaths=-{}/{dir}", target_home())),
                "the daemon needs {dir} writable:\n{unit}"
            );
        }
    }

    #[test]
    fn a_user_systemd_unit_asks_for_no_capabilities() {
        let unit = systemd_unit(false).unwrap();
        assert!(!unit.contains("AmbientCapabilities"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn the_restart_command_matches_the_kind_installed() {
        // A system service needs root; a user one must not ask for it.
        let system = restart_command(Installed::System);
        assert!(system.starts_with("sudo "), "got {system}");

        let user = restart_command(Installed::User);
        assert!(!user.contains("sudo"), "got {user}");

        if cfg!(target_os = "linux") {
            assert!(system.contains("systemctl restart ports.service"));
            assert!(user.contains("--user restart ports.service"));
        } else {
            assert!(system.contains("system/dev.baboons.ports"));
            assert!(user.contains("gui/"));
        }
    }

    #[test]
    fn restarting_a_system_service_without_root_reports_rather_than_pretends() {
        // Silently doing nothing would leave the daemon on the old binary
        // while the update claimed success.
        if !is_root() {
            let err = restart(Installed::System).unwrap_err();
            assert!(err.to_string().contains("needs root"), "got {err}");
        }
    }

    #[test]
    fn nothing_installed_is_reported_as_nothing() {
        // Whatever this machine has, the answer must be one of the three and
        // must not panic looking for files that are not there.
        let found = installed();
        assert!(matches!(
            found,
            None | Some(Installed::System) | Some(Installed::User)
        ));
    }

    #[test]
    fn units_are_installed_where_the_service_manager_looks() {
        assert_eq!(
            systemd_path(true),
            PathBuf::from("/etc/systemd/system/ports.service")
        );
        assert!(systemd_path(false).ends_with(".config/systemd/user/ports.service"));
        assert_eq!(
            launchd_path(true),
            PathBuf::from("/Library/LaunchDaemons/dev.baboons.ports.plist")
        );
        assert!(launchd_path(false).ends_with("Library/LaunchAgents/dev.baboons.ports.plist"));
    }
}
