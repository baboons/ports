//! `ports kill` — stop whatever is listening on a port.
//!
//! The whole value is not having to run `lsof` and then `kill` by hand, so it
//! has to be at least as careful as doing it by hand would be: say what will
//! die before killing it, ask politely first, and check afterwards that the
//! port actually came free.

use std::io::Write;
use std::time::Duration;

use crate::cli::format::{bold, dim, gray, green, red, yellow};
use crate::scan::listeners::enumerate_listeners;
use crate::types::Listener;

/// How long a process gets to exit after SIGTERM before SIGKILL.
const GRACE: Duration = Duration::from_millis(3000);
const POLL: Duration = Duration::from_millis(100);

pub struct Target {
    pub port: u16,
    pub pid: u32,
    pub command: Option<String>,
    pub user: Option<String>,
    /// The repo it belongs to, when we could work it out.
    pub project: Option<String>,
}

/// What is listening on these ports, deduplicated by pid.
///
/// A process holding several of the named ports is one thing to kill, not
/// several, and killing it twice would report a spurious failure the second
/// time.
pub fn targets_for(ports: &[u16], listeners: &[Listener]) -> Vec<Target> {
    let mut found: Vec<Target> = Vec::new();

    for port in ports {
        for listener in listeners.iter().filter(|l| l.port == *port) {
            let Some(pid) = listener.pid else { continue };
            if found.iter().any(|t| t.pid == pid) {
                continue;
            }
            found.push(Target {
                port: *port,
                pid,
                command: listener.command.clone(),
                user: listener.user.clone(),
                project: None,
            });
        }
    }

    found
}

/// Fill in what the process actually is.
///
/// Socket enumeration gives a pid and nothing else, and "pid 76521 unknown" is
/// not enough to decide whether to kill something.
pub fn describe(targets: &mut [Target]) {
    let pids: Vec<u32> = targets.iter().map(|t| t.pid).collect();
    let described = crate::scan::process::enrich_processes(&pids);

    for target in targets.iter_mut() {
        let Some(info) = described.get(&target.pid) else {
            continue;
        };
        if target.command.is_none() {
            target.command = info.name.clone().or_else(|| info.command.clone());
        }
        if target.user.is_none() {
            target.user = info.user.clone();
        }
        target.project = info.project_name.clone();
    }
}

/// Is this process one we must not kill?
pub fn refuse_reason(pid: u32) -> Option<&'static str> {
    if pid <= 1 {
        return Some("that is init, and killing it takes the machine with it");
    }
    if pid == std::process::id() {
        return Some("that is this command");
    }
    None
}

/// Signal a process, translating the errno into something actionable.
fn signal(pid: u32, sig: i32) -> Result<(), String> {
    // Safety: kill is always safe to call; the result is checked below.
    let sent = unsafe { libc::kill(pid as i32, sig) };
    if sent == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    Err(match err.raw_os_error() {
        Some(libc::ESRCH) => "already gone".to_string(),
        Some(libc::EPERM) => "not yours to kill — try again with sudo".to_string(),
        _ => err.to_string(),
    })
}

fn is_alive(pid: u32) -> bool {
    // Signal 0 checks for existence without delivering anything. Cheap, and
    // enough to rule out a pid that is genuinely gone.
    if unsafe { libc::kill(pid as i32, 0) } != 0 {
        return false;
    }

    // But a process that has exited and not yet been reaped by its parent is
    // still a pid, and still answers signal 0. Waiting out the grace period
    // and then SIGKILLing a corpse would be pointless, so ask what state it
    // is actually in.
    use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System};
    let mut system = System::new();
    let pids = [Pid::from_u32(pid)];
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&pids),
        true,
        ProcessRefreshKind::nothing(),
    );

    match system.process(Pid::from_u32(pid)) {
        Some(process) => process.status() != ProcessStatus::Zombie,
        // Vanished between the two checks.
        None => false,
    }
}

pub struct Outcome {
    pub pid: u32,
    pub port: u16,
    pub result: Result<&'static str, String>,
}

/// Ask a process to stop, then insist.
///
/// SIGTERM first so a dev server can flush and exit tidily; SIGKILL only for
/// one that ignores it, because a killed process leaves no chance to clean up
/// its socket, temp files or child processes.
pub async fn stop(target: &Target, force: bool) -> Outcome {
    let result = if force {
        signal(target.pid, libc::SIGKILL).map(|_| "killed")
    } else {
        match signal(target.pid, libc::SIGTERM) {
            Err(err) => Err(err),
            Ok(()) => {
                let deadline = std::time::Instant::now() + GRACE;
                while std::time::Instant::now() < deadline {
                    if !is_alive(target.pid) {
                        break;
                    }
                    tokio::time::sleep(POLL).await;
                }

                if is_alive(target.pid) {
                    // It had its chance.
                    signal(target.pid, libc::SIGKILL).map(|_| "killed after ignoring SIGTERM")
                } else {
                    Ok("stopped")
                }
            }
        }
    };

    Outcome {
        pid: target.pid,
        port: target.port,
        result,
    }
}

pub async fn kill(ports: Vec<u16>, yes: bool, force: bool) -> anyhow::Result<()> {
    let listeners = enumerate_listeners();
    let mut targets = targets_for(&ports, &listeners);
    describe(&mut targets);

    if targets.is_empty() {
        let list = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        println!("\n  {}", dim(&format!("nothing listening on {list}")));

        // The likeliest reason on a shared machine.
        if !crate::scan::listeners::is_privileged() {
            println!(
                "{}\n",
                gray("  another user's processes are invisible without sudo")
            );
        } else {
            println!();
        }
        return Ok(());
    }

    // Refuse the ones that would be a mistake, before showing anything as
    // though it were going to happen.
    let bindings = crate::config::bindings::load_bindings();
    println!();
    let mut killable = Vec::new();
    for target in targets {
        let label = target
            .command
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        if let Some(reason) = refuse_reason(target.pid) {
            println!(
                "  {} {} {}",
                red("✗"),
                bold(&format!("{}", target.port)),
                dim(reason)
            );
            continue;
        }

        // Killing the proxy from a command the proxy is not involved in would
        // be a surprising way to take your own domains down.
        if bindings.own_ports().contains(&target.port) && label.contains("ports") {
            println!(
                "  {} {} {}",
                red("✗"),
                bold(&format!("{}", target.port)),
                dim("that is the ports proxy — `ports service uninstall` instead")
            );
            continue;
        }

        // Name the project too: "node" is every dev server on the machine,
        // and which repo it belongs to is what decides whether to kill it.
        let belongs = target
            .project
            .as_deref()
            .map(|project| gray(&format!("  {project}")))
            .unwrap_or_default();

        println!(
            "  {}  {}  {}{}{}",
            bold(&format!("{:>5}", target.port)),
            dim(&format!("pid {}", target.pid)),
            label,
            belongs,
            target
                .user
                .as_deref()
                .map(|user| gray(&format!("  ({user})")))
                .unwrap_or_default(),
        );
        killable.push(target);
    }

    if killable.is_empty() {
        println!();
        return Ok(());
    }

    println!();
    if !yes && !confirm(killable.len(), force)? {
        println!("{}\n", dim("  nothing killed"));
        return Ok(());
    }

    for target in &killable {
        let outcome = stop(target, force).await;
        match outcome.result {
            Ok(what) => println!("  {} {} {}", green("✓"), outcome.port, dim(what)),
            Err(err) => println!("  {} {} {}", red("✗"), outcome.port, yellow(&err)),
        }
    }

    // The honest check: a killed worker whose master respawns it leaves the
    // port exactly as busy as before.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let still = enumerate_listeners();
    for target in &killable {
        if still.iter().any(|l| l.port == target.port) {
            println!(
                "{}",
                yellow(&format!(
                    "  port {} is still in use — something respawned it",
                    target.port
                ))
            );
        }
    }

    println!();
    Ok(())
}

fn confirm(count: usize, force: bool) -> anyhow::Result<bool> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("not a terminal — pass --yes to kill without confirming");
    }

    let verb = if force { "kill" } else { "stop" };
    print!("  {verb} {count}? [y/N] ");
    std::io::stdout().flush()?;

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_lowercase();

    // Deliberately not defaulting to yes, unlike `adopt`: this one ends
    // processes.
    Ok(answer == "y" || answer == "yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Family;

    fn listener(port: u16, pid: Option<u32>, command: &str) -> Listener {
        Listener {
            port,
            address: "127.0.0.1".into(),
            family: Family::Ipv4,
            pid,
            command: Some(command.to_string()),
            user: Some("johan".into()),
        }
    }

    #[test]
    fn finds_what_is_listening_on_the_named_ports() {
        let listeners = vec![
            listener(3000, Some(101), "node"),
            listener(5173, Some(202), "vite"),
            listener(8080, Some(303), "python"),
        ];

        let targets = targets_for(&[3000, 8080], &listeners);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].pid, 101);
        assert_eq!(targets[1].pid, 303);
    }

    #[test]
    fn a_process_holding_several_named_ports_is_killed_once() {
        // Otherwise the second signal reports "already gone" as a failure.
        let listeners = vec![
            listener(8080, Some(101), "nginx"),
            listener(8443, Some(101), "nginx"),
        ];
        let targets = targets_for(&[8080, 8443], &listeners);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].pid, 101);
    }

    #[test]
    fn workers_sharing_one_port_are_each_listed() {
        // nginx forks; they are separate processes and each needs signalling.
        let listeners = vec![
            listener(80, Some(553), "nginx"),
            listener(80, Some(554), "nginx"),
        ];
        let targets = targets_for(&[80], &listeners);
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn a_listener_with_no_pid_cannot_be_killed() {
        // Found by the sweep rather than the process table, so there is
        // nothing to signal.
        let listeners = vec![listener(8080, None, "unknown")];
        assert!(targets_for(&[8080], &listeners).is_empty());
    }

    #[test]
    fn nothing_matches_a_port_that_is_not_listening() {
        let listeners = vec![listener(3000, Some(101), "node")];
        assert!(targets_for(&[9999], &listeners).is_empty());
    }

    #[test]
    fn a_target_is_described_beyond_its_pid() {
        // "pid 76521 unknown" is not enough to decide whether to kill it.
        let mut targets = vec![Target {
            port: 0,
            pid: std::process::id(),
            command: None,
            user: None,
            project: None,
        }];
        describe(&mut targets);

        assert!(
            targets[0].command.is_some(),
            "should have resolved a command name"
        );
    }

    #[test]
    fn refuses_to_kill_init_or_itself() {
        assert!(refuse_reason(1).is_some());
        assert!(refuse_reason(0).is_some());
        assert!(refuse_reason(std::process::id()).is_some());
        // An ordinary process is fine.
        assert!(refuse_reason(std::process::id() + 1).is_none());
    }

    #[tokio::test]
    async fn stops_a_real_process_and_reports_it() {
        // A child that sleeps until signalled.
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        assert!(is_alive(pid));

        let target = Target {
            port: 0,
            pid,
            command: Some("sleep".into()),
            user: None,
            project: None,
        };
        let outcome = stop(&target, false).await;

        assert!(outcome.result.is_ok(), "got {:?}", outcome.result);
        assert!(!is_alive(pid), "the process should be gone");
        let _ = child.wait();
    }

    #[tokio::test]
    async fn force_kills_something_that_ignores_sigterm() {
        // A shell that traps TERM and keeps going is exactly the case SIGKILL
        // exists for.
        let mut child = std::process::Command::new("sh")
            .args(["-c", "trap '' TERM; sleep 60"])
            .spawn()
            .expect("spawn sh");
        let pid = child.id();

        let target = Target {
            port: 0,
            pid,
            command: Some("sh".into()),
            user: None,
            project: None,
        };
        let outcome = stop(&target, true).await;

        assert!(outcome.result.is_ok(), "got {:?}", outcome.result);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!is_alive(pid));
        let _ = child.wait();
    }

    #[tokio::test]
    async fn signalling_something_that_is_gone_says_so() {
        let mut child = std::process::Command::new("sleep")
            .arg("0")
            .spawn()
            .unwrap();
        let pid = child.id();
        let _ = child.wait();
        // Reaped, so the pid no longer exists.
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(signal(pid, libc::SIGTERM), Err("already gone".to_string()));
    }
}
